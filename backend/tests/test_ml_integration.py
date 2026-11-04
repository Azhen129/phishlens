"""Transport/security tests use tiny trained fixtures, never reported metrics."""
import hashlib
import json
import socket
from pathlib import Path

import joblib
import pytest
import sklearn
from fastapi.testclient import TestClient
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from backend import ml_runtime, storage
from backend.analysis import inspect_email, inspect_url_submission
from backend.main import app
from backend.ml_features import FEATURE_VERSION


@pytest.fixture
def artifact_factory(tmp_path, monkeypatch):
    root = tmp_path / "models"
    monkeypatch.setattr(ml_runtime, "MODEL_ROOT", root)
    ml_runtime.clear_cache()

    def write(kind="email", hybrid=False):
        task_kind = "email" if kind == "email_en" else kind
        # These are algorithm/serialization fixtures, not an evaluation corpus.
        texts = ["project meeting agenda tomorrow", "the library opening hours", "weekly team project notes", "documentation release notes", "urgent verify your password", "account suspended login immediately", "confirm payment bank credentials", "verify account secret password"]
        labels = [0, 0, 0, 0, 1, 1, 1, 1]
        model = make_pipeline(TfidfVectorizer(), LogisticRegression(random_state=42)).fit(texts, labels)
        hybrid_model = LogisticRegression(random_state=42).fit([[-2, 0], [-1, .1], [-.5, .1], [-1.5, .4], [.5, .8], [1, .8], [2, 1], [.1, 1]], labels) if hybrid else None
        metadata = {"calibrated": True, "validation_passed": True, "supported_languages": ["en"] if kind == "email_en" else ["es"] if kind == "email" else [], "assessment_mode": "hybrid" if hybrid else "ml", "feature_version": FEATURE_VERSION, "limitations": ["Synthetic unit fixture; no deployable performance claim."], "validation_scope": "Unit-test serialization contract only."}
        bundle = {"format_version": 1, "kind": task_kind, "version": "unit-fixture-v1", "model": model, "hybrid_model": hybrid_model, "threshold": .5, "hybrid_threshold": .5, "metadata": metadata}
        directory = root / kind
        directory.mkdir(parents=True)
        artifact = directory / "model.joblib"
        joblib.dump(bundle, artifact)
        manifest = {"format_version": 1, "kind": task_kind, "version": bundle["version"], "artifact": "model.joblib", "metrics_file": "metrics.json", "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "sklearn_version": sklearn.__version__, "validated": True, "metadata": metadata}
        (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (directory / "metrics.json").write_text(json.dumps({"kind":task_kind,"version":bundle['version'],"deployment_gate":{"passed":True},"scope": "Unit fixture, not actual model evaluation"}), encoding="utf-8")
        return directory, manifest

    return write


def test_missing_model_retains_exact_heuristic_evidence_and_scores():
    raw = "Subject: Urgent verify your account\n\nAction required: confirm payment"
    direct = inspect_email(raw, use_ml=False)
    inferred = inspect_email(raw)
    assert inferred["score"] == direct["score"] == inferred["heuristic_score"]
    assert inferred["evidence"] == direct["evidence"]
    assert inferred["ml"]["available"] is False
    assert "phishing_probability" not in inferred["ml"]
    assert inferred["assessment"]["method"] == "heuristic_fallback"


def test_valid_model_serializes_loads_and_returns_separate_probability(artifact_factory, monkeypatch):
    artifact_factory()
    monkeypatch.setattr(ml_runtime, "_email_language_route", lambda text: {"detected_language": "es", "language_routing_status": "supported"})
    scan = inspect_email("Subject: verify account\n\nurgent verify your password")
    assert scan["ml"]["available"] is True
    assert scan["ml"]["model_version"] == "unit-fixture-v1"
    assert 0 <= scan["ml"]["phishing_probability"] <= 1
    assert scan["score"] == scan["heuristic_score"]
    assert scan["assessment"]["method"] == "ml"
    assert scan["ml"]["calibrated"] is True


def test_hybrid_uses_held_out_estimator_contract(artifact_factory, monkeypatch):
    artifact_factory(hybrid=True)
    monkeypatch.setattr(ml_runtime, "_email_language_route", lambda text: {"detected_language": "es", "language_routing_status": "supported"})
    scan = inspect_email("Subject: urgent verify account\n\nAction required: confirm payment")
    assert scan["assessment"]["method"] == "validated_hybrid"
    assert 0 <= scan["assessment"]["phishing_probability"] <= 1
    assert scan["assessment"]["score"] == round(100 * scan["assessment"]["phishing_probability"])


def test_hash_is_checked_before_deserialization(artifact_factory, monkeypatch):
    directory, manifest = artifact_factory("url")
    (directory / "model.joblib").write_bytes(b"corrupted bytes must not be unpickled")
    def forbidden(*args, **kwargs):
        raise AssertionError("Deserialization must not happen after checksum failure")
    monkeypatch.setattr(joblib, "load", forbidden)
    result = inspect_url_submission("http://192.0.2.1/login")
    assert result["ml"]["available"] is False
    assert result["score"] == 26
    assert "phishing_probability" not in result["ml"]


@pytest.mark.parametrize("field,value", [("validated", False), ("sklearn_version", "0.0.invalid"), ("artifact", "../../other.joblib"), ("kind", "email")])
def test_unvalidated_incompatible_or_path_changed_manifest_falls_back(artifact_factory, field, value):
    directory, manifest = artifact_factory("url")
    manifest[field] = value
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert ml_runtime.model_status()["url"]["available"] is False
    assert inspect_url_submission("https://example.test")["assessment"]["method"] == "heuristic_fallback"


def test_inference_failure_does_not_remove_rules(artifact_factory, monkeypatch):
    artifact_factory("url")
    bundle, _ = ml_runtime._load("url")
    def fail(*args, **kwargs):
        raise RuntimeError("Do not leak internal model details")
    monkeypatch.setattr(bundle["model"], "predict_proba", fail)
    result = inspect_url_submission("http://192.0.2.1/login")
    assert result["score"] == 26
    assert result["ml"]["available"] is False
    assert "internal model details" not in result["ml"]["reason"]


def test_mismatched_evaluation_cannot_enable_a_model(artifact_factory):
    directory, _ = artifact_factory('url')
    (directory / 'metrics.json').write_text(json.dumps({'kind':'email','version':'wrong','deployment_gate':{'passed':True}}),encoding='utf-8')
    assert not ml_runtime.model_status()['url']['available']
    assert inspect_url_submission('http://192.0.2.1/login')['score']==26


def test_missing_english_model_does_not_route_to_available_spanish_classifier(artifact_factory, monkeypatch):
    artifact_factory()
    class EnglishIdentifier:
        def classify(self, text):
            return "en", .999
    monkeypatch.setattr(ml_runtime, "_language_identifier", EnglishIdentifier())
    result = inspect_email("Subject: Project notes\n\nPlease review the attached project notes for our team meeting tomorrow morning.")
    assert ml_runtime.model_status()["email"]["available"] is True
    assert result["ml"]["available"] is False
    assert result["ml"]["model_key"] == "email_en"
    assert result["ml"]["detected_language"] == "en"
    assert "phishing_probability" not in result["ml"]
    assert result["assessment"]["method"] == "heuristic_fallback"
    assert not ml_runtime._language_supported("hola", {"supported_languages": ["es"]})


def test_english_artifact_uses_email_task_kind_in_its_own_directory(artifact_factory):
    artifact_factory("email_en")
    bundle, reason = ml_runtime._load("email_en")
    assert bundle is not None, reason
    assert bundle["kind"] == "email"
    assert bundle["model_key"] == "email_en"
    assert bundle["metadata"]["supported_languages"] == ["en"]


@pytest.mark.parametrize("key,wrong_language", [("email", "en"), ("email_en", "es")])
def test_artifact_cannot_be_loaded_under_the_wrong_language_route(artifact_factory, key, wrong_language):
    directory, manifest = artifact_factory(key)
    manifest["metadata"]["supported_languages"] = [wrong_language]
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert ml_runtime._load(key)[0] is None


def test_bounded_inference_never_connects_to_submitted_url(artifact_factory, monkeypatch):
    artifact_factory("url")
    def fail(*args, **kwargs):
        raise AssertionError("No connection or DNS lookup is allowed")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    result = inspect_url_submission("https://127.0.0.1/private")
    assert result["ml"]["available"] is True
    assert result["links"][0]["host"] == "127.0.0.1"


def test_training_can_request_rules_without_loading_any_model(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Training heuristic extraction must not invoke inference")
    monkeypatch.setattr(ml_runtime, "assess", forbidden)
    assert inspect_email("Subject: sample\n\nsample", use_ml=False)["score"] == 0
    assert inspect_url_submission("https://example.test", use_ml=False)["score"] == 0


def test_api_preserves_model_metadata_through_case_notes_and_report(artifact_factory, tmp_path, monkeypatch):
    artifact_factory()
    monkeypatch.setattr(ml_runtime, "_email_language_route", lambda text: {"detected_language": "es", "language_routing_status": "supported"})
    monkeypatch.setenv("PHISHLENS_DB", str(tmp_path / "only-this-test.sqlite3"))
    with TestClient(app) as client:
        scan = client.post("/api/analyze/email", json={"raw": "Subject: verify account\n\nurgent verify your password"}).json()
        assert scan["ml"]["available"] is True
        case = client.post("/api/investigations", json={"analysis_id": scan["id"]}).json()
        assert scan["score"] < 25 and scan["risk"] == "Low"
        assert scan["assessment"]["risk"] == case["risk"] == "High"
        assert case["score"] == case["heuristic_score"] == scan["score"]
        assert case["heuristic_risk"] == "Low"
        assert case["final_assessment"] == scan["assessment"]
        client.patch("/api/investigations/" + case["id"], json={"status": "In Progress", "notes": "Preserve the stored model metadata."})
        reopened = client.get("/api/investigations/" + case["id"]).json()
        assert reopened["analysis"]["ml"] == scan["ml"]
        assert reopened["analysis"]["assessment"] == scan["assessment"]
        report = client.post("/api/reports", json={"case_id": case["id"]}).json()
        assert storage.get("report", report["id"])["snapshot"]["ml"] == scan["ml"]
        assert client.get(report["url"]).content.startswith(b"%PDF-")
        assert client.get(report["url"]).content == client.get(report["url"]).content


def test_legacy_analysis_is_not_reclassified_when_read(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHLENS_DB", str(tmp_path / "legacy-test.sqlite3"))
    original = {"id": "historical-scan", "kind": "email", "score": 10, "risk": "Low", "ml": {"available": False, "reason": "Original stored reason"}, "subject": "Original subject"}
    storage.save("analysis", original)
    with TestClient(app) as client:
        assert client.get("/api/analyses/historical-scan").json() == original
    assert storage.get("analysis", original["id"]) == original
