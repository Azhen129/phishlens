import importlib

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend import storage


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHLENS_DB", str(tmp_path / "test.sqlite3"))
    with TestClient(app) as test:
        yield test


def test_empty_health_and_metrics(client):
    assert client.get("/api/health").json()["ml"]["available"] is False
    assert client.get("/api/investigations").json() == []
    assert client.get("/api/metrics").json()["total"] == 0


def test_complete_persistence_lifecycle_and_pdf(client):
    response = client.post("/api/analyze/email", json={"raw": "From: team@example.test\nSubject: Project status\n\nProject notes. https://example.test/status"})
    assert response.status_code == 201
    scan = response.json()
    assert scan["risk"] == "Low"
    case = client.post("/api/investigations", json={"analysis_id": scan["id"], "notes": "Reviewed locally"}).json()
    assert case["analysis"]["id"] == scan["id"]
    updated = client.patch("/api/investigations/" + case["id"], json={"status": "In Progress", "notes": "Need independent confirmation"}).json()
    assert updated["status"] == "In Progress"
    assert len(updated["timeline"]) == 4
    # Reopening a SQLite connection recovers exact user edits.
    assert storage.get("case", case["id"])["notes"] == "Need independent confirmation"
    report = client.post("/api/reports", json={"case_id": case["id"]}).json()
    pdf = client.get(report["url"])
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-")
    assert len(pdf.content) > 2000
    assert client.get(report["url"]).content == pdf.content  # Saved snapshot renders deterministically.
    metrics = client.get("/api/metrics").json()
    assert metrics["total"] == 1
    assert metrics["reports"] == 1
    assert sum(row["value"] for row in metrics["severity"]) == 1
    assert len(client.get("/api/reports").json()) == 1
    assert client.delete("/api/analyses/" + scan["id"]).status_code == 204
    assert client.get("/api/investigations").json() == []
    assert client.get("/api/reports").json() == []


def test_upload_and_errors(client):
    response = client.post("/api/analyze/email/file", files={"file": ("message.eml", b"Subject: Example\n\nhello", "message/rfc822")})
    assert response.status_code == 201
    assert client.post("/api/analyze/email/file", files={"file": ("program.exe", b"hello")}).status_code == 422
    assert client.post("/api/analyze/url", json={"url": "javascript:alert(1)"}).status_code == 422
    assert client.post("/api/analyze/url", json={"url": "https://example.com", "fetch": True}).status_code == 422
    assert client.post("/api/investigations", json={"analysis_id": "missing"}).status_code == 404
    assert client.patch("/api/investigations/missing", json={"status": "Made Up"}).status_code == 422
    assert client.get("/api/reports/../../../secret/download").status_code == 404


def test_origin_host_and_size_protection(client):
    assert client.post("/api/analyze/url", json={"url": "https://example.com"}, headers={"Origin": "https://attacker.test"}).status_code == 403
    assert client.get("/api/health", headers={"Host": "attacker.test"}).status_code == 400
    assert client.post("/api/analyze/url", content=b"{}", headers={"Content-Length": str(27 * 1024 * 1024)}).status_code == 413
    assert client.get("/api/health").headers["x-content-type-options"] == "nosniff"


def test_delete_requires_explicit_confirmation(client):
    client.post("/api/analyze/url", json={"url": "https://example.com"})
    assert client.request("DELETE", "/api/data", json={"confirm": "yes"}).status_code == 422
    assert len(client.get("/api/analyses").json()) == 1
    assert client.request("DELETE", "/api/data", json={"confirm": "DELETE ALL LOCAL DATA"}).status_code == 204
    assert client.get("/api/analyses").json() == []


def test_report_snapshot_preserves_original_notes(client):
    scan = client.post("/api/analyze/url", json={"url": "http://192.0.2.1/login"}).json()
    case = client.post("/api/investigations", json={"analysis_id": scan["id"], "notes": "Original notes"}).json()
    report = client.post("/api/reports", json={"case_id": case["id"]}).json()
    client.patch("/api/investigations/" + case["id"], json={"notes": "Changed notes"})
    assert storage.get("report", report["id"])["case_snapshot"]["notes"] == "Original notes"


def test_sql_injection_strings_are_only_data(client):
    scan = client.post("/api/analyze/email", json={"raw": "Subject: '; DROP TABLE records;--\n\n<script>alert(1)</script>"}).json()
    assert "DROP TABLE" in client.get("/api/analyses/" + scan["id"]).json()["subject"]
    assert client.get("/api/health").status_code == 200


def test_unusual_email_codec_is_not_server_error(client):
    result = client.post("/api/analyze/email", json={"raw": "Subject: Test\nContent-Type: text/plain; charset=idna\n\nurgent"})
    assert result.status_code == 201
    assert result.json()["score"] == 10


@pytest.mark.parametrize("kind", ["long-subject", "long-url", "very-long-subject"])
def test_report_long_input_spans_pages_without_layout_error(client, kind):
    if kind in {"long-subject", "very-long-subject"}:
        size = 12000 if kind == "long-subject" else 50000
        scan = client.post("/api/analyze/email", json={"raw": "Subject: " + "x" * size + "\n\nOrdinary message"}).json()
    else:
        value = "https://example.test/" + "x" * (8192 - len("https://example.test/"))
        scan = client.post("/api/analyze/url", json={"url": value}).json()
    report = client.post("/api/reports", json={"analysis_id": scan["id"]}).json()
    result = client.get(report["url"])
    assert result.status_code == 200
    assert result.content.startswith(b"%PDF-")
    assert len(result.content) < 200000  # Field caps keep output and rendering bounded.


def test_report_layout_error_is_actionable_without_input_leak(client, monkeypatch):
    from reportlab.platypus.doctemplate import LayoutError
    import backend.main as main
    scan = client.post("/api/analyze/url", json={"url": "https://example.test/private-token"}).json()
    report = client.post("/api/reports", json={"analysis_id": scan["id"]}).json()
    def fail(*args, **kwargs):
        raise LayoutError("private-token must never appear in an API error")
    monkeypatch.setattr(main, "generate_pdf", fail)
    result = client.get(report["url"])
    assert result.status_code == 422
    assert "without raw email" in result.json()["detail"]
    assert "private-token" not in result.text
