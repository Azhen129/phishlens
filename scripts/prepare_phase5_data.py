"""Pre-score joint leakage audit and reserved new-source evaluation preparation.

Phase4 test/external rows are now explicitly development evidence. Fresh final
rows are inspected only for parsing and joint overlap controls before freezing.
"""
import csv,hashlib,json,mailbox,re,sys,zipfile
from collections import Counter,defaultdict
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from threadpoolctl import threadpool_limits
from langid.langid import LanguageIdentifier,model
from backend.ml_features import canonical_text
from backend.ml_training import UnionFind,sha256_file
from scripts.acquire_english_dataset import body_text
from scripts.prepare_english_dataset import deduplicate,full_inert_text,global_groups,has_subject_annotation,separate_external,write_csv

OUT=ROOT/'work/phase5/raw'

def base_row(text,label,source,identifier,external):
    return dict(text=text,label=label,source=source,row_id=identifier,group='',date='',language='unadjudicated',external=external)

def prepare():
    csv.field_size_limit(10_000_000)
    specs=json.loads((ROOT/'docs/ml/phase5/raw-snapshots.json').read_text())['files']
    for spec in specs:
        assert sha256_file(OUT/spec['filename'])==spec['sha256']
    rows=[];audit=Counter();baseline_ids=set()
    for name in ('english-train','english-external'):
        p=ROOT/f'work/phase4/raw/{name}.csv'
        prov=json.loads((ROOT/f'docs/ml/phase4/{name}-provenance.json').read_text())
        assert sha256_file(p)==prov['prepared']['sha256']
        for r in csv.DictReader(p.open(encoding='utf-8',newline='')):
            r.update(label=int(r['label']),external=False)
            baseline_ids.add(hashlib.sha256(canonical_text(r['text'],'email').encode()).hexdigest())
            rows.append(r)
    for year in (2018,2020,2021,2022,2023):
        path=OUT/f'nazario-phishing-{year}.mbox'
        box=mailbox.mbox(path,create=False,factory=lambda f:BytesParser(policy=policy.default).parse(f))
        try:
            audit[f'raw_nazario_{year}']=len(box)
            for i,message in enumerate(box):
                rows.append(base_row('Subject: '+str(message.get('Subject',''))+'\n\n'+body_text(message),1,f'Nazario-{year}',f'nazario-{year}-{i}',year==2023))
        finally:box.close()
    with zipfile.ZipFile(OUT/'university-scams.zip') as z:
        names=sorted(n for n in z.namelist() if '/with_bodies/' in n and n.endswith('.txt'))
        assert len(names)==5155
        for name in names:
            info=z.getinfo(name)
            assert info.file_size<1_000_000 and info.file_size/max(info.compress_size,1)<500
            value=z.read(name).decode('utf-8-sig',errors='replace')
            if not value.strip():
                audit['empty_university_files_excluded']+=1
                continue
            subject=re.search(r'(?im)^Subject:\s*([^\n]*)',value)
            body=re.search(r'(?im)^Body:[ \t]*',value)
            if not body:raise ValueError('University body field missing; review format')
            subject=subject.group(1).strip() if subject else ''
            if subject=='[NA]':subject=''
            source='University-'+name.split('/with_bodies/')[1].split('/')[0].removesuffix('_bodies_only')
            rows.append(base_row('Subject: '+subject+'\n\n'+value[body.end():].strip(),1,source,name,True))
        audit['raw_university_with_bodies']=len(names)
    ceas=Counter()
    for i,r in enumerate(csv.DictReader((OUT/'figshare-CEAS-08.csv').open(encoding='utf-8-sig',newline=''))):
        ceas[r['label']]+=1
        if r['label']=='0':rows.append(base_row('Subject: '+(r['subject'] or '')+'\n\n'+(r['body'] or ''),0,'CEAS-08-ham',f'ceas-{i}',True))
    assert ceas=={'0':17312,'1':21842}
    audit.update({'raw_CEAS_0':ceas['0'],'excluded_CEAS_1':ceas['1']})
    identifier=LanguageIdentifier.from_modelstring(model,norm_probs=True)
    accepted=[]
    for i,r in enumerate(rows):
        if has_subject_annotation(r['text']):audit['subject_annotation_quarantine']+=1;continue
        text=full_inert_text(r['text'])
        if not text.strip() or len(text)<5:audit['empty_quarantine']+=1;continue
        if not r['external']:
            language,score=identifier.classify(text)
            if language!='en' or score<.90:audit['development_nonEnglish_or_uncertain_excluded']+=1;continue
            r['language']='en'
        # Final sources are NOT filtered using the language router under test.
        # Source-described English is not independently adjudicated per row.
        r['provided_groups']=[r['group']] if r['group'].startswith('global:') else []
        accepted.append(r)
        if (i+1)%4000==0:print(f'Prepared {i+1}/{len(rows)} source rows',flush=True)
    prior=defaultdict(set)
    for r in accepted:prior[hashlib.sha256(canonical_text(r['text'],'email').encode()).hexdigest()].update(r['provided_groups'])
    unique,dup=deduplicate(accepted)
    print('Joint global template audit:',len(unique),'rows',flush=True)
    groups,ga=global_groups(unique,20_000_000)
    uf=UnionFind(len(unique));seen={}
    for i,(r,g) in enumerate(zip(unique,groups)):
        for key in [g,*prior[r['identifier']]]:
            if key in seen:uf.union(i,seen[key])
            else:seen[key]=i
    # Low-frequency registered domains can tie otherwise different campaign
    # wording. High-frequency provider domains are not campaign identifiers.
    import tldextract
    extract=tldextract.TLDExtract(suffix_list_urls=(),cache_dir=None,include_psl_private_domains=True)
    domain_rows=defaultdict(set)
    for i,r in enumerate(unique):
        for address in re.findall(r'https?://[^\s<>\"\x27]+',r['text'][:16000],flags=re.I):
            try:
                host=urlsplit(address).hostname or ''
                domain=extract(host).top_domain_under_public_suffix or host
                if domain:domain_rows[domain.casefold()].add(i)
            except ValueError:pass
    related=0
    for indexes in domain_rows.values():
        if 2<=len(indexes)<=25:
            indexes=sorted(indexes)
            for i in indexes[1:]:uf.union(indexes[0],i);related+=1
    ga['rare_registered_domain_policy']='Label-blind offline-PSL registered-domain components for domains occurring in2..25 unique emails; higher-frequency provider domains are not assumed campaigns. No DNS/network access.'
    ga['rare_domain_relations']=related
    ga['high_frequency_domains_not_assumed_campaigns']=sum(len(v)>25 for v in domain_rows.values())
    components=defaultdict(list)
    for i in range(len(unique)):components[uf.find(i)].append(i)
    for indexes in components.values():
        g='global:'+min(unique[i]['identifier'] for i in indexes)
        for i in indexes:groups[i]=g
    main,final,excluded,candidates=separate_external(unique,groups,24000)
    baseline_groups={r['group'] for r in unique if r['identifier'] in baseline_ids}
    baseline_related_final=[r for r in final if r['group'] in baseline_groups]
    final=[r for r in final if r['group'] not in baseline_groups]
    # Fixed label-blind hash cap within the single legitimate final source.
    ham=sorted((r for r in final if r['label']==0),key=lambda r:r['identifier'])[:5000]
    final=ham+[r for r in final if r['label']==1]
    info={'development':write_csv(OUT/'development.csv',main),'final':write_csv(OUT/'final.csv',final)}
    report={'protocol':'phase5-preparation-v1','raw_counts':dict(audit),'deduplication':dup,'group_audit':ga,'main_before_cap':len(candidates),'main_cap':24000,'purged_main_for_final_component':len(excluded),'purged_by_source':dict(Counter(r['source'] for r in excluded)),'final_ham_hash_cap':5000,'main_final_group_intersection':len({r['group'] for r in main}&{r['group'] for r in final}),'prepared':info,'final_language_policy':'Final source-described English rows retained without filtering on the new router; per-row language truth is unadjudicated. Report coverage and suspected assignment disagreements explicitly.'}
    report['baseline_related_final_rows_excluded']=len(baseline_related_final)
    report['baseline_related_final_excluded_by_source']=dict(Counter(r['source'] for r in baseline_related_final))
    report['baseline_original_and_final_group_intersection']=len({r['group'] for r in final}&baseline_groups)
    assert report['baseline_original_and_final_group_intersection']==0
    assert report['main_final_group_intersection']==0
    (OUT/'preparation-audit.json').write_text(json.dumps(report,indent=2)+'\n')
    provenance={'task':'email','supported_languages':['en'],'approved_for_training':True,'source_url':'https://www.monkey.org/~jose/phishing/','license':'CC BY 4.0 development; University evaluation CC BY-NC-SA 2.0 local noncommercial research only','permission_basis':'Pinned author CC BY4 Nazario and Figshare ham-only; held-out University author CC BY-NC-SA2 permits this local noncommercial research evaluation. Preserve attribution and limitations.','collection_notes':'Phase4 observed sets now development, plus unused2018/2020/2021/2022 Nazario. Fresh University broadscam, CEAS ham0 and unusedNazario2023 reserved. No synthetic primary data.','validation_scope':'Source-held-out curated archive stress; not representative deployment calibration. University labels broader scam, strict-phish subgroup reported separately.','prepared':info['development'],'final':info['final'],'raw_snapshots_sha256':sha256_file(ROOT/'docs/ml/phase5/raw-snapshots.json'),'preparation_audit_sha256':sha256_file(OUT/'preparation-audit.json')}
    (OUT/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    for name in ('preparation-audit.json','provenance.json'):
        (ROOT/'docs/ml/phase5'/name).write_bytes((OUT/name).read_bytes())
    print(json.dumps(info,indent=2),flush=True)

if __name__=='__main__':
    with threadpool_limits(limits=1):prepare()
