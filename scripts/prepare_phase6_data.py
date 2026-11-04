"""Model-blind source/era roles and joint campaign controls for Phase 6."""
from __future__ import annotations
import csv
import hashlib
import json
import mailbox
import re
import sys
from collections import Counter, defaultdict
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from threadpoolctl import threadpool_limits
from langid.langid import LanguageIdentifier, model
from backend.ml_training import UnionFind, sha256_file
from backend.text_normalization_v6 import normalize_english_text
from scripts.acquire_english_dataset import body_text
from scripts.prepare_english_dataset import global_groups, has_subject_annotation

OUT=ROOT/'work/phase6/raw'
FIELDS=['text','label','source','group','row_id','date','language','role']

def key(text):
    return hashlib.sha256(normalize_english_text(text).encode()).hexdigest()

def source_validation(source):
    return bool(re.search(r'(?:2022|2024|2025)$',source,re.I))

def group_text(text):
    subject,sep,body=text.partition('\n\n')
    return normalize_english_text(subject)+'\n\n'+normalize_english_text(body if sep else '')

def base(text,label,source,row_id,role,prior=False,group=''):
    return {'text':text,'label':int(label),'source':source,'row_id':row_id,'role':role,'prior':prior,'provided_groups':[group] if group.startswith('global:') else [],'group':'','date':'','language':'unadjudicated'}

def write(path, rows):
    with path.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=FIELDS,lineterminator='\n');w.writeheader()
        for r in sorted(rows,key=lambda x:x['identifier']):w.writerow({k:(r['identifier'] if k=='row_id' else r['text'][:16000] if k=='text' else r[k]) for k in FIELDS})
    return {'path':path.relative_to(ROOT).as_posix(),'sha256':sha256_file(path),'rows':len(rows),'class_balance':dict(Counter(str(r['label']) for r in rows)),'sources':dict(Counter(r['source'] for r in rows)),'roles':dict(Counter(r['role'] for r in rows)),'groups':len({r['group'] for r in rows})}

def prepare():
    csv.field_size_limit(10_000_000)
    if (OUT/'development.csv').exists() or (OUT/'final.csv').exists():
        raise ValueError('Prepared Phase6 snapshots already exist; never overwrite a frozen corpus.')
    acquisition=json.loads((OUT/'acquisition-v2.json').read_text())
    assert sha256_file(OUT/'meajor_cleaned_preprocessed.csv')==acquisition['meajor']['sha256']
    rows=[];audit=Counter()
    # Every earlier fitted/observed row participates in overlap controls.
    for stage,name in [('phase4','english-train'),('phase4','english-external'),('phase5','development'),('phase5','final')]:
        path=ROOT/f'work/{stage}/raw/{name}.csv'
        if stage=='phase4':
            provenance=json.loads((ROOT/f'docs/ml/phase4/{name}-provenance.json').read_text());expected=provenance['prepared']['sha256']
        else:
            provenance=json.loads((ROOT/'docs/ml/phase5/provenance.json').read_text());expected=provenance['prepared' if name=='development' else 'final']['sha256']
        assert sha256_file(path)==expected,'Historical prepared corpus identity changed'
        for r in csv.DictReader(path.open(encoding='utf-8',newline='')):
            source=r['source'];role='prior_only' if source.startswith('University-') else 'validation' if source_validation(source) else 'train_pool'
            rows.append(base(r['text'],r['label'],source,r['row_id'],role,True,r['group']))
    ceas=[]
    for i,r in enumerate(csv.DictReader((ROOT/'work/phase5/raw/figshare-CEAS-08.csv').open(encoding='utf-8-sig',newline=''))):
        if r['label']=='0':ceas.append(base('Subject: '+(r['subject'] or '')+'\n\n'+(r['body'] or ''),0,'CEAS-08-ham',f'ceas-{i}','train_pool'))
    rows.extend(sorted(ceas,key=lambda r:key(r['text']))[:6000]);audit['CEAS_ham_added_cap']=6000
    new=defaultdict(list);original=Counter()
    for i,r in enumerate(csv.DictReader((OUT/'meajor_cleaned_preprocessed.csv').open(encoding='utf-8-sig',newline=''))):
        source=r.get('source','');label=r.get('label','')
        original[source+':'+label]+=1
        if source not in {'trec5','trec6','trec7'} or label not in {'0.0','1.0'}:
            audit['MeAJOR_malformed_rows_excluded']+=1;continue
        if label!='0.0':audit['MeAJOR_all_merged_positives_excluded']+=1;continue
        text='Subject: '+(r.get('subject') or '')+'\n\n'+(r.get('body') or '')
        role={'trec5':'train_pool','trec6':'validation','trec7':'final'}[source]
        new[source].append(base(text,0,'MeAJOR-'+source,f'meajor-{i}',role))
    for source,cap in [('trec5',4000),('trec6',3000),('trec7',6000)]:
        chosen=sorted(new[source],key=lambda r:key(r['text']))[:cap]
        rows.extend(chosen);audit[source+'_hash_cap_retained']=len(chosen)
    annotations_path=ROOT/'work/phase6/pot-annotations-adjudicated-private.json'
    annotations=json.loads(annotations_path.read_text(encoding='utf-8'))
    parsed=json.loads((ROOT/'work/phase6/pot-parsed-private.json').read_text(encoding='utf-8'))
    assert len(annotations)==len(parsed)==400
    by_index={r['index']:r for r in annotations}
    annotation_counts=Counter()
    for r in parsed:
        a=by_index[r['index']];assert a['raw_sha256']==r['raw_sha256']
        annotation_counts[a['language']+':'+a['category']]+=1
        if a['language']!='en' or a['category'] not in {'strict_phishing','financial_scam'}:continue
        if not a['fully_reviewed']:
            if a['category']=='strict_phishing':raise ValueError('Included final phishing lacks bounded full-content review.')
            audit['Pot_incomplete_financial_scams_excluded']+=1;continue
        source='PhishingPot-'+a['category']
        rows.append(base(r['text'],1,source,r['row_id'],'final'))
    naz=OUT/'nazario-phishing-2019.mbox'
    assert sha256_file(naz)=='cab39d6fcb38cf80cdaabb3e6ffd1222777e2fcaac7e8480321b7f729c2e3c0e'
    box=mailbox.mbox(naz,create=False,factory=lambda f:BytesParser(policy=policy.default).parse(f))
    try:
        audit['Nazario_2019_raw_messages']=len(box)
        for i,m in enumerate(box):rows.append(base('Subject: '+str(m.get('Subject',''))+'\n\n'+body_text(m),1,'Nazario-2019',f'nazario2019-{i}','final'))
    finally:box.close()
    identifier=LanguageIdentifier.from_modelstring(model,norm_probs=True)
    buckets=defaultdict(list)
    for i,r in enumerate(rows):
        if has_subject_annotation(r['text']):audit['subject_annotation_quarantine']+=1;continue
        normalized=normalize_english_text(r['text'])
        if len(normalized)<5:audit['empty_text_quarantine']+=1;continue
        if r['role'] in {'train_pool','validation'} and not r['prior']:
            language,score=identifier.classify(normalized)
            if language!='en' or score<.90:audit['development_nonEnglish_uncertain_excluded']+=1;continue
        r['identifier']=hashlib.sha256(normalized.encode()).hexdigest()
        buckets[r['identifier']].append(r)
        if (i+1)%10000==0:print('Prepared source rows',i+1,'/',len(rows),flush=True)
    unique=[]
    for identifier,entries in sorted(buckets.items()):
        if len({r['label'] for r in entries})>1:
            audit['conflicting_canonical_rows_quarantined']+=len(entries);continue
        priority={'final':0,'validation':1,'train_pool':2,'prior_only':3}
        r=dict(min(entries,key=lambda x:(priority[x['role']],x['source'],x['row_id'])))
        r['prior']=any(x['prior'] for x in entries)
        r['provided_groups']=sorted({g for x in entries for g in x['provided_groups']})
        r['text_original']=r['text'];r['text']=group_text(r['text'])
        unique.append(r);audit['canonical_duplicate_copies_removed']+=len(entries)-1
    print('Joint harmonized campaign grouping:',len(unique),flush=True)
    groups,group_audit=global_groups(unique,30_000_000)
    uf=UnionFind(len(unique));seen={}
    for i,r in enumerate(unique):
        for g in [groups[i],*r['provided_groups']]:
            if g in seen:uf.union(i,seen[g])
            else:seen[g]=i
    import tldextract
    extract=tldextract.TLDExtract(suffix_list_urls=(),cache_dir=None,include_psl_private_domains=True)
    domains=defaultdict(set)
    for i,r in enumerate(unique):
        for address in re.findall(r'https?://[^\s<>\"\x27]+',r['text_original'][:16000],re.I):
            try:
                host=urlsplit(address).hostname or '';d=extract(host).top_domain_under_public_suffix or host
                if d:domains[d.casefold()].add(i)
            except ValueError:pass
    relations=0
    for indexes in domains.values():
        if 2<=len(indexes)<=25:
            ix=sorted(indexes)
            for i in ix[1:]:uf.union(ix[0],i);relations+=1
    components=defaultdict(list)
    for i in range(len(unique)):components[uf.find(i)].append(i)
    for ix in components.values():
        g='phase6:'+min(unique[i]['identifier'] for i in ix)
        for i in ix:unique[i]['group']=g;unique[i]['text']=unique[i].pop('text_original')
    final_groups={r['group'] for r in unique if r['role']=='final'}
    observed_groups={r['group'] for r in unique if r['prior']}
    final=[r for r in unique if r['role']=='final' and r['group'] not in observed_groups]
    excluded_final=[r for r in unique if r['role']=='final' and r['group'] in observed_groups]
    candidates=[r for r in unique if r['role'] in {'train_pool','validation'} and r['group'] not in final_groups]
    val_groups={r['group'] for r in candidates if r['role']=='validation'}
    val_groups.update(r['group'] for r in candidates if int(hashlib.sha256(r['group'].encode()).hexdigest(),16)%5==0)
    for r in candidates:r['role']='validation' if r['group'] in val_groups else 'train_pool';r['language']='en'
    assert not ({r['group'] for r in candidates}&{r['group'] for r in final})
    assert not ({r['group'] for r in final}&observed_groups)
    assert {r['label'] for r in candidates if r['role']=='validation'}=={0,1}
    info={'development':write(OUT/'development.csv',candidates),'final':write(OUT/'final.csv',final)}
    report={'protocol':'phase6-source-preparation-v1','raw_and_exclusions':dict(audit),'MeAJOR_original_source_labels':dict(original),'pot_annotation_counts':dict(annotation_counts),'pot_annotations_sha256':sha256_file(annotations_path),'canonical_unique_rows':len(unique),'group_audit':group_audit,'rare_domain_relations':relations,'global_components':len(components),'final_preexisting_component_rows_excluded':len(excluded_final),'excluded_final_by_source':dict(Counter(r['source'] for r in excluded_final)),'development_final_group_intersection':0,'final_previously_observed_group_intersection':0,'prepared':info,'normalization_sha256':sha256_file(ROOT/'backend/text_normalization_v6.py'),'final_language_policy':'Final sources not filtered by classifier/router. Pot language is model-blind content annotation; other final source language inherited and imperfect.'}
    (OUT/'preparation-audit.json').write_text(json.dumps(report,indent=2)+'\n')
    provenance={'task':'email','name':'Phase6 source/era-held-out English archive experiment','approved_for_training':True,'supported_languages':['en'],'source_url':'https://zenodo.org/records/18471483','license':'Development curator CC BY 4.0 / MASC CC BY 3.0 US; original source rights inherited. PhishingPot final only CC BY-NC 4.0. University never fits.','validation_scope':'Historical source/era-held-out archive diagnostics; limited independent-curator manually reviewed final subset, not deployment probability calibration.','prepared':info['development'],'final':info['final'],'source_roles':'TREC05 fit pool; TREC06 validation; TREC07 final; Nazario2022/24/25 validation; unused2019 final secondary; Pot final only','acquisition_sha256':sha256_file(OUT/'acquisition-v2.json'),'preparation_audit_sha256':sha256_file(OUT/'preparation-audit.json')}
    provenance['permission_basis']='MeAJOR v2 official Zenodo metadata explicitly licenses its anonymized curator release CC BY 4.0; original TREC/source/sender rights are inherited, not independently re-cleared. Existing Nazario and Figshare development are author/curator CC BY 4.0, MASC CC BY 3.0 US. No University or PhishingPot row fits this model. Pinned PhishingPot explicit CC BY-NC 4.0 is used solely for held-out local noncommercial evaluation.'
    provenance['collection_notes']='Real historical email subject/body only; MeAJOR original benign0 rows only, all merged spam/phishing1 rows excluded. TREC05 supports development and TREC06 source-held-out validation; TREC07 is final. Existing Phase4/5 tests are observed development evidence. Source, era, anonymization and imperfect ham labels remain limitations. Final Pot apparent-phishing labels were content-reviewed before any prediction; small repeated-campaign subset is not expert consensus or verified malicious infrastructure. No synthetic primary data.'
    (OUT/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    for name in ['preparation-audit.json','provenance.json','acquisition-v2.json']:(ROOT/'docs/ml/phase6'/name).write_bytes((OUT/name).read_bytes())
    print(json.dumps(info,indent=2),flush=True)

if __name__=='__main__':
    with threadpool_limits(limits=1):prepare()
