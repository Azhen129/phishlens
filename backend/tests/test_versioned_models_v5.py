"""Version selection/security/score semantics; fixtures are not ML evaluation."""
import hashlib
import json
import shutil
from pathlib import Path

import joblib
import pytest
from fastapi.testclient import TestClient

from backend import ml_runtime, storage
from backend.main import app
from backend.tests.test_ml_integration import artifact_factory

VERSION = "email-multiscale-v3-0123456789ab"
ENGLISH = "Please review the attached agenda for our project meeting tomorrow. We will discuss progress and plan the next stage together."


def candidate(artifact_factory):
    baseline, manifest = artifact_factory('email_en')
    root=baseline.parent
    target=root/'email_en_v5'/VERSION
    shutil.copytree(baseline,target)
    bundle=joblib.load(target/'model.joblib')
    bundle['version']=VERSION
    feature=Path(ml_runtime.__file__).with_name('ml_features_v3.py')
    bundle['metadata']['additional_code_sha256']={'ml_features_v3.py':hashlib.sha256(feature.read_bytes()).hexdigest()}
    joblib.dump(bundle,target/'model.joblib')
    manifest.update(version=VERSION,sha256=hashlib.sha256((target/'model.joblib').read_bytes()).hexdigest(),metadata=bundle['metadata'])
    (target/'manifest.json').write_text(json.dumps(manifest))
    metrics=json.loads((target/'metrics.json').read_text())
    metrics['version']=VERSION
    (target/'metrics.json').write_text(json.dumps(metrics))
    return root,target,manifest


def activate(root):
    (root/'active-models.json').write_text(json.dumps({'email_en':'email_en_v5/'+VERSION}))


def test_absent_selection_uses_retained_baseline_and_valid_selection_loads_version(artifact_factory):
    root,target,manifest=candidate(artifact_factory)
    baseline,_=ml_runtime._load('email_en')
    assert baseline['version']=='unit-fixture-v1'
    activate(root)
    selected,reason=ml_runtime._load('email_en')
    assert selected is not None,reason
    assert selected['version']==VERSION
    assert (root/'email_en/model.joblib').exists()


@pytest.mark.parametrize('selected',['../email_en','email_en/model.joblib','email_en_v5/../../email','email_en_v5\\email-multiscale-v3-0123456789ab','email_en_v5/email-multiscale-v3-abc','C:/external/model'])
def test_unreviewed_selection_falls_back_instead_of_using_old_model(artifact_factory,selected):
    baseline,_=artifact_factory('email_en')
    assert ml_runtime._load('email_en')[0] is not None
    (baseline.parent/'active-models.json').write_text(json.dumps({'email_en':selected}))
    assert ml_runtime._load('email_en')[0] is None


@pytest.mark.parametrize('payload',['not JSON','[]','{"email_en":"email_en_v5/email-multiscale-v3-0123456789ab","url":"url"}'])
def test_invalid_config_or_missing_selected_version_never_silently_uses_baseline(artifact_factory,payload):
    baseline,_=artifact_factory('email_en')
    (baseline.parent/'active-models.json').write_text(payload)
    assert ml_runtime._load('email_en')[0] is None


def test_missing_selected_version_and_english_config_do_not_disable_spanish(artifact_factory):
    baseline,_=artifact_factory('email_en')
    artifact_factory('email')
    activate(baseline.parent)
    assert ml_runtime._load('email_en')[0] is None
    assert ml_runtime._load('email')[0] is not None


@pytest.mark.parametrize('checksums',[{'ml_features_v3.py':'0'*64},{'../ml_features_v3.py':'0'*64},{}])
def test_additional_feature_identity_rejected_before_deserialization(artifact_factory,monkeypatch,checksums):
    root,target,manifest=candidate(artifact_factory)
    activate(root)
    manifest['metadata']['additional_code_sha256']=checksums
    (target/'manifest.json').write_text(json.dumps(manifest))
    calls=[]
    def forbidden(*args,**kwargs):
        calls.append(True)
        raise AssertionError('Must not deserialize incompatible code')
    monkeypatch.setattr(joblib,'load',forbidden)
    assert ml_runtime._load('email_en')[0] is None
    assert calls==[]


def test_new_scores_are_explicitly_not_deployment_probability(artifact_factory):
    artifact_factory('email_en')
    ml,assessment=ml_runtime.assess('email',ENGLISH,28,'Medium')
    assert ml['available']
    assert ml['decision_score']==ml['phishing_probability']
    assert ml['probability_validated_for_deployment'] is False
    assert ml['score_type']=='archive_calibrated_decision_score'
    assert assessment['score_is_probability_percent'] is False
    assert assessment['score_is_decision_percent'] is True


@pytest.mark.parametrize('score,label',[(.4999999,'Legitimate'),(.5,'Phishing'),(.5000001,'Phishing')])
def test_threshold_uses_unrounded_score_not_display_percent(monkeypatch,score,label):
    class Estimator:
        classes_=[0,1]
        def predict_proba(self,values):return [[1-score,score]]
    bundle={'version':'threshold-fixture','artifact_sha256':'0'*64,'model':Estimator(),'threshold':.5,'metadata':{'supported_languages':['en'],'assessment_mode':'ml'}}
    monkeypatch.setattr(ml_runtime,'_load',lambda kind:(bundle,'Unit fixture'))
    ml,assessment=ml_runtime.assess('email',ENGLISH,28,'Medium')
    assert ml['classification']==assessment['label']==label
    assert assessment['score']==50


def test_saved_old_version_and_report_snapshot_survive_active_version_change(artifact_factory,tmp_path,monkeypatch):
    root,target,manifest=candidate(artifact_factory)
    monkeypatch.setenv('PHISHLENS_DB',str(tmp_path/'versioned-workflow.sqlite3'))
    with TestClient(app) as client:
        old=client.post('/api/analyze/email',json={'raw':'Subject: Fixture\n\n'+ENGLISH}).json()
        case=client.post('/api/investigations',json={'analysis_id':old['id'],'notes':'Retain original reviewed version.'}).json()
        activate(root)
        new=client.post('/api/analyze/email',json={'raw':'Subject: Fixture\n\n'+ENGLISH}).json()
        assert old['ml']['model_version']=='unit-fixture-v1'
        assert new['ml']['model_version']==VERSION
        reopened=client.get('/api/investigations/'+case['id']).json()
        assert reopened['analysis']['ml']==old['ml']
        assert reopened['notes']=='Retain original reviewed version.'
        report=client.post('/api/reports',json={'case_id':case['id']}).json()
        assert storage.get('report',report['id'])['snapshot']['ml']==old['ml']
        assert client.get(report['url']).content.startswith(b'%PDF-')
