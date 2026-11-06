from pathlib import Path
import base64
from html import unescape
import socket
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from backend import analysis, storage
from backend.demo import app, MAX_DEMO_EMAIL_BYTES, MAX_DEMO_REQUEST_BYTES, _work_slots


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    database = tmp_path / "must-not-exist.sqlite3"
    monkeypatch.setenv("PHISHLENS_DB", str(database))

    def forbidden_storage(*args, **kwargs):
        pytest.fail("The public demo attempted to access persistent application storage")

    monkeypatch.setattr(storage, "connection", forbidden_storage)
    monkeypatch.setattr(storage, "save", forbidden_storage)
    with TestClient(app) as test:
        yield test
    assert not database.exists()


def test_public_entrypoint_imports_no_local_database_or_model_runtime():
    code = "import api.index,sys; assert 'backend.main' not in sys.modules; assert 'backend.storage' not in sys.modules; assert 'backend.ml_runtime' not in sys.modules"
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)


def test_health_declares_temporary_rules_only_operation(client):
    response = client.get("/api/health")
    result = response.json()
    assert result["mode"] == "public-demo"
    assert not result["ml"]["available"]
    assert all(not model["available"] for model in result["models"].values())
    assert result["demo"]["storage"] == "temporary-browser-memory"
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_analysis_uses_real_heuristics_without_network_or_models(client, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Passive demo attempted network or model inference")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(analysis, "_apply_ml", forbidden)
    raw = (ROOT / "fixtures/suspicious-invoice.eml").read_bytes().decode()
    response = client.post("/api/analyze/email", json={"raw": raw})
    assert response.status_code == 201
    scan = response.json()
    assert scan["score"] > 0 and scan["evidence"]
    assert scan["ml"]["available"] is False
    assert scan["assessment"]["method"] == "heuristic_fallback"
    assert scan["demo"]["storage"] == "temporary-browser-memory"
    assert "<script" not in scan["email"]["body"]
    url = client.post("/api/analyze/url", json={"url": "http://user:pass@192.0.2.25/login"})
    assert url.status_code == 201 and url.json()["evidence"]
    assert url.json()["ml"]["available"] is False


def test_requests_never_expose_another_guests_records(client):
    first = client.post("/api/analyze/email", json={"raw": "Subject: private-marker-9382\n\nhello"}).json()
    with TestClient(app) as other:
        for path in ("/api/analyses", "/api/investigations", "/api/reports", "/api/data", "/api/metrics", "/api/analyses/" + first["id"]):
            response = other.get(path)
            assert response.status_code == 404
            assert "private-marker-9382" not in response.text
        assert other.post("/api/investigations", json={"analysis_id": first["id"]}).status_code == 404


def test_public_limits_and_safe_validation(client):
    assert client.post("/api/analyze/email", json={"raw": "a" * (MAX_DEMO_EMAIL_BYTES + 1)}).status_code == 422
    assert client.post("/api/analyze/email", json={"raw": "é" * MAX_DEMO_EMAIL_BYTES}).status_code == 413
    response = client.post("/api/analyze/url", json={"url": "javascript:private-secret-9382"})
    assert response.status_code == 422 and "private-secret-9382" not in response.text
    assert client.post("/api/analyze/url", json={"url": "https://example.test", "fetch": True}).status_code == 422
    assert client.post("/api/analyze/email", content=b"{}", headers={"content-length": str(MAX_DEMO_REQUEST_BYTES + 1)}).status_code == 413
    assert client.post("/api/analyze/email", content=b"x" * (MAX_DEMO_REQUEST_BYTES + 1)).status_code == 413


def test_upload_is_bounded_and_not_persisted(client):
    assert client.post("/api/analyze/email/file", files={"file": ("example.eml", b"Subject: demo\n\nhello")}).status_code == 201
    assert client.post("/api/analyze/email/file", files={"file": ("wrong.exe", b"hello")}).status_code == 422
    assert client.post("/api/analyze/email/file", files={"file": ("large.eml", b"a" * (MAX_DEMO_EMAIL_BYTES + 1))}).status_code == 413


def test_demo_rejects_cross_site_browser_requests(client):
    assert client.post("/api/analyze/url", json={"url": "https://example.test"}, headers={"Origin": "https://attacker.test"}).status_code == 403
    assert client.post("/api/analyze/url", json={"url": "https://example.test"}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/analyze/url", json={"url": "https://example.test"}, headers={"Host": "phishlens.vercel.app", "Origin": "https://phishlens.vercel.app"}).status_code == 201


def test_concurrent_work_is_bounded(client):
    _work_slots.acquire()
    _work_slots.acquire()
    try:
        assert client.post("/api/analyze/url", json={"url": "https://example.test"}).status_code == 429
        assert client.post("/api/demo/reports", json={"kind": "url", "input": "https://example.test"}).status_code == 429
    finally:
        _work_slots.release()
        _work_slots.release()


def test_pdf_recomputes_evidence_and_has_no_saved_report_route(client, monkeypatch):
    import backend.reports as reports

    paragraphs = []
    original_paragraph = reports.Paragraph

    def capture_paragraph(text, style):
        paragraphs.append(unescape(text))
        return original_paragraph(text, style)

    monkeypatch.setattr(reports, "Paragraph", capture_paragraph)
    payload = {
        "kind": "email", "input": "From: team@example.test\nSubject: Demo report\n\nPlease review http://192.0.2.25/notes",
        "analysis_id": "scan-fixture", "report_id": "report-fixture", "analyzed_at": "2026-11-05T10:00:00Z", "created_at": "2026-11-05T11:00:00Z",
        "case": {"id": "PL-FIXTURE", "status": "In Review", "notes": "Fixture analyst note", "timeline": [{"at": "2026-11-05T10:01:00Z", "title": "Demo review", "detail": "Browser-session note"}]},
    }
    result = client.post("/api/demo/reports", json=payload)
    assert result.status_code == 200 and result.content.startswith(b"%PDF-")
    assert result.headers["content-type"] == "application/pdf"
    assert result.headers["content-disposition"] == 'attachment; filename="phishlens-report-fixture.pdf"'
    rendered_text = "\n".join(paragraphs)
    assert "Fixture analyst note" in rendered_text and "In Review" in rendered_text
    assert "Numeric IP destination" in rendered_text
    assert "Copyright (c) 2003 by Bitstream, Inc." in rendered_text
    assert "Public demonstration" in rendered_text
    assert "saved local analysis" not in rendered_text
    assert client.post("/api/demo/reports", json={**payload, "analysis": {"evidence": []}}).status_code == 422
    assert client.post("/api/demo/reports", json={**payload, "report_id": "injected\r\nheader"}).status_code == 422
    assert client.post("/api/demo/reports", json={**payload, "case": {"id": "PL-FIXTURE", "notes": "a" * 4001}}).status_code == 422
    assert client.get("/api/reports/report-fixture/download").status_code == 404


def test_uploaded_report_retains_original_non_utf8_bytes(client, monkeypatch):
    import backend.demo as demo

    raw = (
        b"Subject: Binary source\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=demo\n\n"
        b"--demo\nContent-Type: text/plain; charset=iso-8859-1\n\ncaf\xe9 https://example.test\n"
        b"--demo\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=fixture.bin\n"
        b"Content-Transfer-Encoding: base64\n\nAP8BAgM=\n--demo--\n"
    )
    upload = client.post("/api/analyze/email/file", files={"file": ("latin.eml", raw)})
    assert upload.status_code == 201
    expected = upload.json()
    captured = {}

    def inspect_report(scan, report, case, include_raw):
        captured.update(scan)
        return b"%PDF-test"

    monkeypatch.setattr(demo, "generate_pdf", inspect_report)
    result = client.post("/api/demo/reports", json={"kind": "email", "input_base64": base64.b64encode(raw).decode("ascii")})
    assert result.status_code == 200
    assert captured["email"] == expected["email"]
    assert captured["evidence"] == expected["evidence"]
    assert captured["email"]["body"].startswith("café")
    assert captured["attachments"] == expected["attachments"]
    assert captured["attachments"][0]["size"] == 5
    assert client.post("/api/demo/reports", json={"kind": "url", "input_base64": "YWJj"}).status_code == 422
    assert client.post("/api/demo/reports", json={"kind": "email", "input_base64": "invalid%%"}).status_code == 422
    assert client.post("/api/demo/reports", json={"kind": "email", "input_base64": "YWJj", "input": "abc"}).status_code == 422
