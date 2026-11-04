"""Optional omissions and corrupt present artifacts have different CI outcomes."""
import json

from backend import ml_runtime
from scripts.check_model_registry import check_registry


def prepare(tmp_path,monkeypatch,present):
    monkeypatch.setattr(ml_runtime,'MODEL_ROOT',tmp_path)
    for kind in ml_runtime.MODEL_SPECS:
        path=tmp_path/kind
        path.mkdir()
        expected_kind=ml_runtime.MODEL_SPECS[kind][0]
        (path/'manifest.json').write_text(json.dumps({'format_version':1,'kind':expected_kind,'version':'test-v1','artifact':'model.joblib','metrics_file':'metrics.json','sha256':'a'*64}))
        (path/'metrics.json').write_text(json.dumps({'kind':expected_kind,'version':'test-v1'}))
        if kind in present:
            (path/'model.joblib').write_bytes(b'test-controlled-placeholder')
    monkeypatch.setattr(ml_runtime,'_load',lambda kind:({'version':'test-v1','artifact_sha256':'a'*64},'test-controlled successful integrity path'))


def test_complete_trusted_registry_selects_full_checks(tmp_path,monkeypatch):
    prepare(tmp_path,monkeypatch,{'email','email_en','url'})
    result=check_registry()
    assert result['passed'] and result['full_registry']
    assert result['mode']=='full_trusted_models'


def test_explicit_missing_optional_weights_selects_disclosed_rules_mode(tmp_path,monkeypatch):
    prepare(tmp_path,monkeypatch,{'email','url'})
    result=check_registry()
    assert result['passed'] and not result['full_registry']
    assert result['models']['email_en']['state']=='optional_weights_absent'
    assert 'NOT RUN' in result['coverage_notice']


def test_corrupt_present_bundle_fails_even_if_another_model_is_omitted(tmp_path,monkeypatch):
    prepare(tmp_path,monkeypatch,{'email','url'})
    monkeypatch.setattr(ml_runtime,'_load',lambda kind:(None,'rejected before loading'))
    result=check_registry()
    assert not result['passed'] and not result['full_registry']
    assert result['mode']=='invalid_registry'
    assert result['failed_model_keys']==['email','url']


def test_malformed_present_metadata_does_not_pass_as_optional_absence(tmp_path,monkeypatch):
    prepare(tmp_path,monkeypatch,{'email','url'})
    (tmp_path/'email_en/manifest.json').write_text('{broken')
    result=check_registry()
    assert not result['passed']
    assert result['models']['email_en']['state']=='invalid_present_metadata'


def test_mismatched_metadata_without_weights_is_still_a_failure(tmp_path,monkeypatch):
    prepare(tmp_path,monkeypatch,{'email','url'})
    (tmp_path/'email_en/metrics.json').write_text(json.dumps({'kind':'url','version':'wrong-v2'}))
    result=check_registry()
    assert not result['passed'] and result['mode']=='invalid_registry'
