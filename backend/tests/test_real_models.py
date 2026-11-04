"""Read-only smoke tests of the actual licensed-data model artifacts.

These fixtures are not training data and assert no invented accuracy/verdict.
"""
import hashlib
import json
import math
import socket
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import ml_runtime, storage
from backend.analysis import inspect_email, inspect_url_submission
from backend.main import app

pytestmark = pytest.mark.real_models
PROJECT = Path(__file__).resolve().parents[2]
SPANISH = (PROJECT / "fixtures/spanish-account-review.eml").read_text(encoding="utf-8")


def test_shipped_models_are_real_evaluated_and_integrity_checked():
    ml_runtime.clear_cache()
    statuses = ml_runtime.model_status()
    for kind in ("email", "email_en", "url"):
        directory = ml_runtime._model_directory(kind)
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        metrics = json.loads((directory / "metrics.json").read_text(encoding="utf-8"))
        assert statuses[kind]["available"], statuses[kind]["reason"]
        assert manifest["validated"] and metrics["deployment_gate"]["passed"]
        assert hashlib.sha256((directory / "model.joblib").read_bytes()).hexdigest() == manifest["sha256"]
        assert metrics["group_intersection_count"] == 0
        assert metrics["selected_test"]["n"] >= 100
        assert "CC BY 4.0" in metrics["dataset"]["license"]
        assert manifest["version"] == metrics["version"]


def test_rejected_real_experiment_cannot_replace_the_active_classifier(tmp_path, monkeypatch):
    import joblib
    selection=json.loads((PROJECT/'docs/ml/phase5/selection.json').read_text())
    original=PROJECT/selection['directory']
    manifest=json.loads((original/'manifest.json').read_text())
    assert manifest['validated'] is False
    assert manifest['metadata']['independent_admission_passed'] is False
    assert ml_runtime._model_directory('email_en') != original
    target=tmp_path/'models'/'email_en_v5'/selection['version']
    shutil.copytree(original,target)
    (tmp_path/'models/active-models.json').write_text(json.dumps({'email_en':'email_en_v5/'+selection['version']}))
    monkeypatch.setattr(ml_runtime,'MODEL_ROOT',tmp_path/'models')
    def forbidden(*args,**kwargs):
        raise AssertionError('Rejected model must not be deserialized')
    monkeypatch.setattr(joblib,'load',forbidden)
    ml_runtime.clear_cache()
    assert ml_runtime._load('email_en')[0] is None
    result=inspect_email('Subject: Example\n\nPlease review the project notes for our upcoming team meeting tomorrow morning and send any proposed changes to the organizer.')
    assert not result['ml']['available']
    assert result['assessment']['method']=='heuristic_fallback'


@pytest.mark.parametrize("filename,language,key", [("spanish-account-review.eml", "es", "email"), ("suspicious-invoice.eml", "en", "email_en"), ("ordinary-update.eml", "en", "email_en")])
def test_real_language_models_preserve_rule_evidence(filename, language, key):
    raw = (PROJECT / "fixtures" / filename).read_text(encoding="utf-8")
    actual = inspect_email(raw)
    rules = inspect_email(raw, use_ml=False)
    assert actual["ml"]["available"]
    assert actual["ml"]["supported_languages"] == [language]
    assert actual["ml"]["detected_language"] == language
    assert actual["ml"]["model_key"] == key
    if language == "en":
        if actual['ml']['model_version'].startswith('email-source-text-v6-'):
            assert actual['ml']['classifier_decision'] == 'Approved for limited use'
            assert 'Limited local research' in actual['ml']['prediction_warning']
        else:
            assert actual['ml']['classifier_decision'] == 'Experimental'
        assert "representative deployment" in actual["ml"]["probability_scope"]
    assert math.isfinite(actual["ml"]["phishing_probability"])
    assert 0 <= actual["ml"]["phishing_probability"] <= 1
    assert actual["score"] == rules["score"]
    assert actual["evidence"] == rules["evidence"]


def test_phase6_selection_preserves_baseline_and_fails_closed_without_admission(tmp_path, monkeypatch):
    import joblib
    active = ml_runtime._model_directory('email_en')
    if active.parent.name != 'email_en_v6':
        pytest.skip('Phase 6 English artifact is not selected in this registry')
    original, reason = ml_runtime._load('email_en', use_active=False)
    assert original is not None, reason
    assert original['version'] == 'email-passive-text-v2-3c3796081ca9'
    assert active.name != original['version']
    root = tmp_path / 'models'
    target = root / 'email_en_v6' / active.name
    shutil.copytree(active, target, ignore=shutil.ignore_patterns('admission.json'))
    (root / 'active-models.json').write_text(json.dumps({'email_en': 'email_en_v6/' + active.name}))
    monkeypatch.setattr(ml_runtime, 'MODEL_ROOT', root)
    def forbidden(*args, **kwargs):
        pytest.fail('Missing admission must fail before artifact deserialization')
    monkeypatch.setattr(joblib, 'load', forbidden)
    assert ml_runtime._load('email_en')[0] is None


@pytest.mark.parametrize("body,status", [("Bonjour, voici les documents de notre réunion de travail. Merci de préparer les questions pour la discussion de demain avec les collègues.", "unsupported"), ("Please review the project schedule for our team meeting tomorrow morning and send any updates to the organizer.\n\nPor favor revise el calendario del proyecto para nuestra reunión de equipo mañana por la mañana y envíe cualquier actualización al organizador.", "mixed"), ("OK", "too_short")])
def test_real_gate_abstains_without_probability(body, status):
    result = inspect_email("Subject: Message\n\n" + body)
    assert not result["ml"]["available"]
    assert result["ml"]["language_routing_status"] == status
    assert "phishing_probability" not in result["ml"]
    assert result["assessment"]["method"] == "heuristic_fallback"


def test_real_url_inference_is_passive_and_hostname_policy_is_invariant(monkeypatch):
    ml_runtime.model_status()  # Load trusted local artifacts before forbidding IO.
    def forbidden(*args, **kwargs):
        raise AssertionError("A submitted URL must never trigger a connection or DNS lookup")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    original = inspect_url_submission("http://example.test/")
    modified = inspect_url_submission("https://example.test/documentation/project/" + "a" * 300 + "?view=detail")
    assert original["ml"]["available"] and modified["ml"]["available"]
    assert original["ml"]["phishing_probability"] == modified["ml"]["phishing_probability"]
    assert original["score"] != modified["score"]  # Full-URL rules remain independent.


@pytest.mark.parametrize("filename,language", [("spanish-account-review.eml", "es"), ("suspicious-invoice.eml", "en")])
def test_real_model_metadata_survives_case_reopen_and_pdf(tmp_path, monkeypatch, filename, language):
    monkeypatch.setenv("PHISHLENS_DB", str(tmp_path / "real-model-workflow.sqlite3"))
    with TestClient(app) as client:
        raw = (PROJECT / "fixtures" / filename).read_text(encoding="utf-8")
        response = client.post("/api/analyze/email", json={"raw": raw})
        assert response.status_code == 201
        scan = response.json()
        assert scan["ml"]["available"]
        assert scan["ml"]["supported_languages"] == [language]
        case = client.post("/api/investigations", json={"analysis_id": scan["id"]}).json()
        update = client.patch("/api/investigations/" + case["id"], json={"status": "In Review", "notes": "Actual classifier metadata retained."})
        assert update.status_code == 200
        reopened = client.get("/api/investigations/" + case["id"]).json()
        assert reopened["analysis"]["ml"] == scan["ml"]
        assert reopened["analysis"]["assessment"] == scan["assessment"]
        assert reopened["notes"] == "Actual classifier metadata retained."
        report = client.post("/api/reports", json={"case_id": case["id"]}).json()
        assert storage.get("report", report["id"])["snapshot"]["ml"] == scan["ml"]
        pdf = client.get(report["url"])
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")
