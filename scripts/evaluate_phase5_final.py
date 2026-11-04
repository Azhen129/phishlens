"""One frozen-candidate independent evaluation; never fits or tunes a model."""
import argparse,json,sys
from collections import Counter
from pathlib import Path
import joblib,numpy as np
from scipy.stats import binomtest
from threadpoolctl import threadpool_limits
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from backend.analysis import inspect_email
from backend.ml_features import hybrid_features
from backend.ml_runtime import _load,_classify_language,_phase4_email_language_route
from backend.language_routing_v2 import route_email_language,ROUTING_VERSION
from backend.ml_training import load_rows,sha256_file
from scripts.evaluate_english_model import classification_metrics,probability_metrics

def predict(model,texts):
    return np.concatenate([model.predict_proba(texts[i:i+128])[:,1] for i in range(0,len(texts),128)])

def selected_score(bundle,texts,points):
    p=predict(bundle['model'],texts)
    if bundle['metadata'].get('assessment_mode')=='hybrid':
        return p,bundle['hybrid_model'].predict_proba(hybrid_features(p,points))[:,1],bundle['hybrid_threshold']
    return p,p,bundle['threshold']

def full_predictions(routes,en_scores,en_threshold,es_scores,es_threshold,points):
    return np.asarray([bool(en_scores[i]>=en_threshold) if r['language_routing_status']=='supported' and r['detected_language']=='en' else bool(es_scores[i]>=es_threshold) if r['language_routing_status']=='supported' and r['detected_language']=='es' else bool(points[i]>=60) for i,r in enumerate(routes)])

def route_summary(routes,y):
    result={'n':len(routes),'statuses':dict(Counter(r['language_routing_status'] for r in routes)),'assigned_languages':dict(Counter(r['detected_language'] for r in routes))}
    for label in (0,1):
        ix=np.flatnonzero(y==label)
        result[str(label)]={'n':len(ix),'english_applied':sum(routes[i]['language_routing_status']=='supported' and routes[i]['detected_language']=='en' for i in ix),'either_language_applied':sum(routes[i]['language_routing_status']=='supported' for i in ix),'fallback':sum(routes[i]['language_routing_status']!='supported' for i in ix)}
    result['language_truth_limitation']='Source-described English, not independently adjudicated per-row language. Disagreements are suspected assignment issues; short/mixed/unsupported rows remain in final denominators.'
    return result

def paired(y,a,b):
    result={}
    for label in (0,1):
        mask=y==label
        improved=int((mask&(a!=y)&(b==y)).sum());regressed=int((mask&(a==y)&(b!=y)).sum());n=improved+regressed
        result[str(label)]={'improved':improved,'regressed':regressed,'two_sided_exact_discordance_p':float(binomtest(improved,n,.5).pvalue) if n else 1.,'limitation':'Row-level paired diagnostic; campaign correlation is not accounted for.'}
    return result

def evaluate(output=None):
    output=Path(output) if output else ROOT/'docs/ml/phase5/independent-evaluation.json'
    if output.exists():raise ValueError('Final report already exists. Refusing to overwrite or rescore a supposedly untouched benchmark.')
    selection=json.loads((ROOT/'docs/ml/phase5/selection.json').read_text())
    directory=ROOT/selection['directory'];manifest=json.loads((directory/'manifest.json').read_text())
    assert manifest['version']==selection['version']
    assert sha256_file(directory/'model.joblib')==selection['model_sha256']==manifest['sha256']
    # This is project-owned, newly trained research serialization. A pending
    # manifest is evaluated offline rather than exposed via live inference.
    candidate=joblib.load(directory/'model.joblib')
    assert candidate['version']==selection['version']
    baseline,reason=_load('email_en',use_active=False);assert baseline is not None,reason
    spanish,reason=_load('email');assert spanish is not None,reason
    prov=json.loads((ROOT/'docs/ml/phase5/provenance.json').read_text())
    final_csv=ROOT/'work/phase5/raw/final.csv';dev_csv=ROOT/'work/phase5/raw/development.csv'
    assert sha256_file(final_csv)==prov['final']['sha256'] and sha256_file(dev_csv)==prov['prepared']['sha256']
    rows,clean=load_rows(final_csv,'email',50000);dev,_=load_rows(dev_csv,'email',24000)
    assert not {r.identifier for r in rows}&{r.identifier for r in dev}
    assert not {r.supplied_group for r in rows}&{r.supplied_group for r in dev}
    prep=json.loads((ROOT/'docs/ml/phase5/preparation-audit.json').read_text())
    assert prep['baseline_original_and_final_group_intersection']==0
    watched=[directory/n for n in ('model.joblib','manifest.json','metrics.json','splits.json')]
    watched += [ROOT/'backend/ml_runtime.py',ROOT/'backend/language_routing_v2.py',ROOT/'backend/ml_features.py',ROOT/'backend/ml_features_v3.py',final_csv,dev_csv]
    watched += [p for key in ('email','email_en','url') for p in (ROOT/'backend/models'/key).rglob('*') if p.is_file()]
    hashes={p.relative_to(ROOT).as_posix():sha256_file(p) for p in watched}
    y=np.asarray([r.label for r in rows]);raw=[r.text for r in rows]
    parsed=[];points=[];old_routes=[];new_routes=[]
    for i,row in enumerate(rows):
        scan=inspect_email(row.text,use_ml=False)
        text='Subject: '+scan['subject']+'\n\n'+scan['email']['body']
        parsed.append(text);points.append(scan['score'])
        old_routes.append(_phase4_email_language_route(text))
        new_routes.append(route_email_language(text,_classify_language))
        if (i+1)%500==0:print('Final parsed/routed',i+1,'/',len(rows),flush=True)
    points=np.asarray(points)
    _,br,bt=selected_score(baseline,raw,points)
    _,cr,ct=selected_score(candidate,raw,points)
    _,bp,bt=selected_score(baseline,parsed,points)
    cpbase,cp,ct=selected_score(candidate,parsed,points)
    ep=predict(spanish['model'],parsed);et=spanish['threshold']
    before=full_predictions(old_routes,bp,bt,ep,et,points)
    route_only=full_predictions(new_routes,bp,bt,ep,et,points)
    after=full_predictions(new_routes,cp,ct,ep,et,points)
    metrics={}
    groups={'all':np.arange(len(rows)),'primary_new_source_scam_ham':np.asarray([i for i,r in enumerate(rows) if r.source!='Nazario-2023']),'strict_phishing_ham':np.asarray([i for i,r in enumerate(rows) if r.source in {'Nazario-2023','CEAS-08-ham'}])}
    groups.update({'source:'+s:np.asarray([i for i,r in enumerate(rows) if r.source==s]) for s in sorted({r.source for r in rows})})
    for name,ix in groups.items():
        metrics[name]={'n':len(ix),'source_counts':dict(Counter(rows[i].source for i in ix)),
          'baseline_raw_model':probability_metrics(y[ix],br[ix],bt),'candidate_raw_model':probability_metrics(y[ix],cr[ix],ct),
          'baseline_parsed_model':probability_metrics(y[ix],bp[ix],bt),'candidate_parsed_model':probability_metrics(y[ix],cp[ix],ct),
          'candidate_base_ml_parsed':probability_metrics(y[ix],cpbase[ix],candidate['threshold']),
          'baseline_end_to_end':classification_metrics(y[ix],before[ix]),'baseline_model_new_router':classification_metrics(y[ix],route_only[ix]),'candidate_end_to_end':classification_metrics(y[ix],after[ix]),
          'heuristic_high_only':classification_metrics(y[ix],points[ix]>=60),'heuristic_review25_only':classification_metrics(y[ix],points[ix]>=25),
          'old_routing':route_summary([old_routes[i] for i in ix],y[ix]),'new_routing':route_summary([new_routes[i] for i in ix],y[ix]),'paired_changes':paired(y[ix],before[ix],after[ix])}
    primary=metrics['primary_new_source_scam_ham'];strict=metrics['strict_phishing_ham']
    b=primary['baseline_end_to_end'];c=primary['candidate_end_to_end'];fpr=c['false_positive_rate'];bfpr=b['false_positive_rate']
    conditions={'internal_candidate_gate':selection['internal_pass'],'primary_recall_gain_at_least_5pp':c['recall']>=b['recall']+.05,'final_empirical_fpr_at_most_1pct':fpr['rate']<=.01,'final_wilson_fpr_upper_at_most_2pct':fpr['wilson_95'][1]<=.02,'fpr_increase_at_most_half_percentage_point':fpr['rate']<=bfpr['rate']+.005,'strict_phishing_recall_no_regression':strict['candidate_end_to_end']['recall']>=strict['baseline_end_to_end']['recall']}
    records=[{'sha256':r.identifier,'group_sha256':r.supplied_group,'source':r.source,'label':r.label,'rule_points':int(points[i]),'baseline_raw_score':float(br[i]),'candidate_raw_score':float(cr[i]),'baseline_parsed_score':float(bp[i]),'candidate_parsed_score':float(cp[i]),'baseline_high':bool(before[i]),'router_only_high':bool(route_only[i]),'candidate_high':bool(after[i]),'old_route':old_routes[i],'new_route':new_routes[i]} for i,r in enumerate(rows)]
    assert all(sha256_file(ROOT/p)==h for p,h in hashes.items()),'Watched data/model/code changed during final evaluation'
    result={'candidate_version':candidate['version'],'baseline_version':baseline['version'],'router_version':ROUTING_VERSION,'identity':hashes,'final_csv_sha256':sha256_file(final_csv),'development_csv_sha256':sha256_file(dev_csv),'preparation_audit_sha256':sha256_file(ROOT/'docs/ml/phase5/preparation-audit.json'),'canonical_development_final_intersection':0,'global_component_development_final_intersection':0,'baseline_original_final_component_intersection':0,'frozen_thresholds':{'baseline':bt,'candidate':ct,'candidate_base':candidate['threshold'],'spanish':et},'metrics':metrics,'admission_conditions':conditions,'candidate_admitted':all(conditions.values()),'records':records,'limitations':['University archive labels broader scam, not adjudicated narrowly credential phishing for eachrow.','CEAS ham inherits spam-oriented annotation, not modern independent security adjudication.','Nazario2023 is fresh strict-phish mail but same curator and older than some observed development years.','No representative deployment probabilities/confidence validated by this curated source mixture.','Source/campaign/time/language truth limitations and rare-domain grouping assumptions remain.'],'all_watched_hashes_unchanged':True,'no_fitting_or_threshold_selection':True}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'output':str(output),'candidate_admitted':result['candidate_admitted'],'conditions':conditions,'primary_before':b,'primary_after':c,'strict_before':strict['baseline_end_to_end'],'strict_after':strict['candidate_end_to_end']},indent=2),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=ROOT/'docs/ml/phase5/independent-evaluation.json')
    args=parser.parse_args()
    with threadpool_limits(limits=1):evaluate(args.out)
