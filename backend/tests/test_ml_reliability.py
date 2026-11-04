"""Reliability protocol invariants; fixtures are not classifier evaluation data."""
import socket
import json
import numpy as np
from backend.ml_features_v3 import TextStructureTransformer
from backend.ml_training_v3 import constrained_threshold,wilson_upper
from backend import ml_runtime

def test_recall_threshold_cannot_pass_by_flagging_everything():
    y=np.asarray([0]*1000+[1]*100)
    p=np.r_[np.linspace(.001,.5,1000),np.linspace(.1,.9,100)]
    threshold=constrained_threshold(y,p)
    predicted=p>=threshold
    fp=int(predicted[:1000].sum())
    assert fp/1000<=.01
    assert wilson_upper(fp,1000)<=.02
    assert not predicted.all()
    assert predicted[1000:].any()
    for lower in np.unique(p[p<threshold]):
        q=p>=lower
        if q[1000:].sum()>predicted[1000:].sum():
            assert q[:1000].mean()>.01 or wilson_upper(int(q[:1000].sum()),1000)>.02

def test_structure_features_are_inert_finite_and_bounded(monkeypatch):
    def deny(*args,**kwargs):raise AssertionError('No network for features')
    monkeypatch.setattr(socket,'getaddrinfo',deny)
    monkeypatch.setattr(socket.socket,'connect',deny)
    t=TextStructureTransformer()
    result=t.fit_transform(['<script>evil()</script><p>Account update https://example.test/</p>','x'*1000000]).toarray()
    assert result.shape==(2,12)
    assert np.isfinite(result).all()
    assert result[1,0]<=np.log1p(16000)
    assert len(t.get_feature_names_out())==12
    assert not any('sender' in s or 'authentication' in s for s in t.get_feature_names_out())

def test_release_disclosure_is_version_and_hash_bound_without_mutating_saved_metadata(tmp_path,monkeypatch):
    monkeypatch.setattr(ml_runtime,'MODEL_ROOT',tmp_path)
    metadata={'prediction_warning':'Original historical scope','limitations':[]}
    bundle={'metadata':metadata,'version':'baseline-v1','artifact_sha256':'a'*64}
    path=tmp_path/'release-notes.json'
    notes={'format_version':1,'models':{'baseline-v1':{'artifact_sha256':'b'*64,'prediction_warning':'New evidence'}}}
    path.write_text(json.dumps(notes))
    assert ml_runtime._public_metadata(bundle)['prediction_warning']=='Original historical scope'
    notes['models']['baseline-v1']['artifact_sha256']='a'*64
    path.write_text(json.dumps(notes))
    assert ml_runtime._public_metadata(bundle)['prediction_warning']=='New evidence'
    assert metadata['prediction_warning']=='Original historical scope'

def test_malformed_optional_release_notes_do_not_break_original_model_metadata(tmp_path,monkeypatch):
    monkeypatch.setattr(ml_runtime,'MODEL_ROOT',tmp_path)
    (tmp_path/'release-notes.json').write_text('{broken')
    bundle={'metadata':{'prediction_warning':'Archive scope'},'version':'baseline-v1','artifact_sha256':'a'*64}
    assert ml_runtime._public_metadata(bundle)['prediction_warning']=='Archive scope'
