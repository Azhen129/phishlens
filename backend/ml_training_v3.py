"""Frozen Phase5 word/character experiments with validation FPR constraints.

No final evaluation data or application database is opened. New model versions
are written separately; none of the original model artifacts are overwritten.
"""
import argparse,hashlib,json,shutil,sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
import joblib,numpy as np,sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline,FeatureUnion
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from threadpoolctl import threadpool_limits
from .ml_features import FEATURE_VERSION,TrainedClassifier,CalibratedHybrid,normalize_email_text,hybrid_features
from .ml_features_v3 import PIPELINE_VERSION,TextStructureTransformer
from .ml_training import (SEED,PARTITIONS,load_rows,build_groups,grouped_partitions,evaluate,heuristic_points,sha256_file,verify_dataset_identity,json_write,hybrid_selection_exclusions)

CANDIDATES=[('word_lr_balanced','word','lr','balanced'),('word_svm_balanced','word','svm','balanced'),('char_lr_balanced','char','lr','balanced'),('char_svm_balanced','char','svm','balanced'),('union_svm_balanced','union','svm','balanced'),('union_svm_unweighted','union','svm',None),('structure_lr_balanced','structure','lr','balanced')]

def estimator(kind,algorithm,weight):
    word=TfidfVectorizer(preprocessor=normalize_email_text,ngram_range=(1,2),min_df=2,max_features=40000,sublinear_tf=True,dtype=np.float64)
    char=TfidfVectorizer(preprocessor=normalize_email_text,analyzer='char_wb',ngram_range=(3,5),min_df=2,max_features=60000,sublinear_tf=True,dtype=np.float64)
    features=word if kind=='word' else char if kind=='char' else FeatureUnion([('word',word),('char',char)]+([('structure',Pipeline([('text',TextStructureTransformer()),('scale',StandardScaler(with_mean=False))]))] if kind=='structure' else []))
    classifier=LogisticRegression(C=1,solver='liblinear',class_weight=weight,max_iter=2000,random_state=SEED) if algorithm=='lr' else LinearSVC(C=1,class_weight=weight,max_iter=15000,tol=.001,random_state=SEED)
    return Pipeline([('features',features),('classifier',classifier)])

def sigmoid(scores,y):
    m=LogisticRegression(C=1,solver='lbfgs',max_iter=2000,random_state=SEED)
    return m.fit(np.asarray(scores).reshape(-1,1),y)

def wilson_upper(fp,n):
    if not n:return 1.
    z=1.959963984540054;p=fp/n
    return float((p+z*z/(2*n)+z*np.sqrt(p*(1-p)/n+z*z/(4*n*n)))/(1+z*z/n))

def constrained_threshold(y,p):
    y=np.asarray(y);p=np.asarray(p);ham=int((y==0).sum());phish=int((y==1).sum())
    choices=[]
    for threshold in np.unique(np.r_[np.clip(p,1e-12,1-1e-12),np.nextafter(1.,0.)]):
        pred=p>=threshold;fp=int(((y==0)&pred).sum());tp=int(((y==1)&pred).sum())
        if fp/max(ham,1)<=.01 and wilson_upper(fp,ham)<=.02:
            choices.append((tp/max(phish,1),-fp,tp/max(tp+fp,1),-abs(threshold-.5),float(threshold)))
    if not choices:raise ValueError('No threshold satisfies declared validation FPR constraints; report insufficient ham/control.')
    return max(choices)[-1]

def train(args):
    root=Path(__file__).resolve().parents[1]
    prov=json.loads(args.provenance.read_text());verify_dataset_identity(args.csv,prov,'email')
    rows,clean=load_rows(args.csv,'email',24000)
    groups,ga=build_groups(rows,'email',max_comparisons=20_000_000)
    y=np.asarray([r.label for r in rows]);texts=np.asarray([r.text for r in rows],dtype=object)
    parts=grouped_partitions(y,groups);points=heuristic_points(rows,'email')
    run_digest=hashlib.sha256((sha256_file(args.csv)+sha256_file(args.provenance)+sha256_file(Path(__file__))).encode()).hexdigest()[:12]
    scratch=root/'work/phase5/experiments'/('run-'+run_digest)
    if scratch.exists():raise ValueError('Experiment checkpoint directory already exists; originals are retained and will not be overwritten.')
    scratch.mkdir(parents=True)
    results={};paths={}
    for name,kind,algorithm,weight in CANDIDATES:
        print('Fitting',name,'n=',len(parts['train']),flush=True)
        base=estimator(kind,algorithm,weight).fit(texts[parts['train']],y[parts['train']])
        cal=parts['calibration'];v=parts['validation'];test=parts['test']
        classifier=TrainedClassifier(base,sigmoid(base.decision_function(texts[cal]),y[cal]))
        p=classifier.predict_proba(texts)[:,1]
        hf,hc=parts['hybrid_fit'],parts['hybrid_calibration']
        combiner=LogisticRegression(C=1,solver='lbfgs',max_iter=2000,random_state=SEED).fit(hybrid_features(p[hf],points[hf]),y[hf])
        hybrid=CalibratedHybrid(combiner,sigmoid(combiner.decision_function(hybrid_features(p[hc],points[hc])),y[hc]))
        hp=hybrid.predict_proba(hybrid_features(p,points))[:,1]
        raw=1/(1+np.exp(-np.clip(base.decision_function(texts),-40,40)))
        mt=constrained_threshold(y[v],p[v]);ht=constrained_threshold(y[v],hp[v])
        path=scratch/(name+'.joblib')
        joblib.dump({'model':classifier,'hybrid_model':hybrid,'threshold':mt,'hybrid_threshold':ht},path,compress=3)
        for mode,pred,threshold in [('ml',p,mt),('hybrid',hp,ht)]:
            key=name+'_'+mode
            exclusions=hybrid_selection_exclusions('email',hybrid) if mode=='hybrid' else []
            if classifier.calibrator.coef_[0,0]<=0:exclusions.append('Nonpositive base sigmoid slope')
            val=evaluate(y[v],pred[v],threshold)
            results[key]={'name':name,'mode':mode,'threshold':threshold,'eligible':not exclusions,'exclusions':exclusions,'validation':val,'validation_fpr_wilson_upper':wilson_upper(val['false_positives'],val['class_balance']['0']),'internal_test':evaluate(y[test],pred[test],threshold),'calibration_before':evaluate(y[test],raw[test]),'calibration_slope':float(classifier.calibrator.coef_[0,0]),'hybrid_coefficients':hybrid.estimator.coef_.tolist(),'hybrid_calibration_slope':float(hybrid.calibrator.coef_[0,0])}
            paths[key]=path
        del base,classifier,hybrid
    eligible=[n for n,r in results.items() if r['eligible']]
    selected=max(eligible,key=lambda n:(results[n]['validation']['recall'],-results[n]['validation']['false_positive_rate'],-results[n]['validation']['log_loss'],n))
    chosen=results[selected];bundle=joblib.load(paths[selected])
    identities={name:sha256_file(root/name) for name in ['backend/ml_features.py','backend/ml_features_v3.py','backend/ml_training_v3.py','docs/ml/phase5/PROTOCOL.md']}
    identity={'dataset':sha256_file(args.csv),'provenance':sha256_file(args.provenance),'code':identities,'candidates':CANDIDATES,'seed':SEED,'partitions':PARTITIONS,'sklearn':sklearn.__version__}
    version=PIPELINE_VERSION+'-'+hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:12]
    output=root/'backend/models/email_en_v5'/version
    if output.exists():raise ValueError('Version already exists; refusing to overwrite a retained experiment.')
    output.mkdir(parents=True)
    test=chosen['internal_test'];internal_pass=test['roc_auc']>=.70 and test['false_positive_rate']<=.02 and test['recall']>=.5
    metadata={'kind':'email','version':version,'calibrated':True,'validation_passed':internal_pass,'feature_version':FEATURE_VERSION,'feature_code_sha256':identities['backend/ml_features.py'],'additional_code_sha256':{'ml_features_v3.py':identities['backend/ml_features_v3.py']},'assessment_mode':chosen['mode'],'selected_candidate':selected,'supported_languages':['en'],'calibration':'C=1 sigmoid fitted on a separate archive partition; not verified representative deployment probability','probability_validated_for_deployment':False,'probability_scope':'Archive decision score; representative deployment calibration not established','prediction_warning':'Research decision score, not confidence or a verified probability for this inbox. New-source evaluation pending; legitimate never means safe.','validation_scope':prov['validation_scope'],'dataset_source':prov['source_url'],'dataset_license':prov['license'],'limitations':['Source, campaign, era and class prevalence shifts remain.','No live authentication/reputation, destination fetching or attachment execution.','Related semantic campaigns may survive bounded lexical grouping.'],'pipeline_version':PIPELINE_VERSION}
    bundle.update(format_version=1,kind='email',version=version,metadata=metadata)
    metrics={'format_version':1,'kind':'email','version':version,'created_at':datetime.now(timezone.utc).isoformat(),'dataset':prov,'dataset_sha256':sha256_file(args.csv),'cleaning':clean,'group_audit':ga,'group_intersection_count':0,'partitions':{n:{'n':len(ix),'class_balance':dict(Counter(str(y[i]) for i in ix)),'sources':dict(Counter(rows[i].source for i in ix))} for n,ix in parts.items()},'selected_candidate':selected,'selection_rule':'Maximum validation recall under empirical FPR<=1% and Wilson95 upper<=2%; ties lowerFPR, lowerlogloss, deterministicname. Final data never read.','candidates':results,'selected_test':test,'heuristic_only_internal_test':evaluate(y[parts['test']],points[parts['test']]/100,.60,calibrated=False),'deployment_gate':{'passed':internal_pass,'scope':'Internal candidate eligibility only. Manifest remains unvalidated until separate independent admission checks.'},'code_sha256':identities,'independent_evaluation_pending':True}
    joblib.dump(bundle,output/'model.joblib',compress=3)
    json_write(output/'metrics.json',metrics)
    json_write(output/'experiment.json',identity)
    json_write(output/'splits.json',{n:[{'sha256':rows[i].identifier,'group_sha256':str(groups[i]),'label':int(y[i]),'source':rows[i].source} for i in ix] for n,ix in parts.items()})
    json_write(output/'manifest.json',{'format_version':1,'kind':'email','version':version,'artifact':'model.joblib','metrics_file':'metrics.json','sha256':sha256_file(output/'model.joblib'),'sklearn_version':sklearn.__version__,'validated':False,'metadata':metadata})
    json_write(root/'docs/ml/phase5/selection.json',{'version':version,'directory':output.relative_to(root).as_posix(),'selected_candidate':selected,'threshold':chosen['threshold'],'validation':{k:v for k,v in chosen['validation'].items() if k not in ['curves','calibration_bins']},'internal_pass':internal_pass,'no_final_data_read':True,'model_sha256':sha256_file(output/'model.joblib')})
    print(json.dumps({'version':version,'selected':selected,'threshold':chosen['threshold'],'internal_pass':internal_pass,'internal_test':{k:v for k,v in test.items() if k not in ['curves','calibration_bins']}},indent=2),flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--csv',type=Path,default=Path('work/phase5/raw/development.csv'));p.add_argument('--provenance',type=Path,default=Path('work/phase5/raw/provenance.json'));args=p.parse_args()
    with threadpool_limits(limits=1):train(args)

if __name__=='__main__':main()
