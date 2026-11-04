from __future__ import annotations

import json
import os
import uuid
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware
from reportlab.platypus.doctemplate import LayoutError

from .analysis import MAX_BYTES, inspect_email, inspect_url_submission, now, MODEL_REASON
from . import storage
from .reports import generate_pdf
from .ml_runtime import model_status

def _isolated_test_mode() -> bool:
    qa_database = Path(__file__).resolve().parents[1] / "work/phase6/e2e.sqlite3"
    return os.environ.get("PHISHLENS_TEST_MODE") == "1" and storage.database_path().resolve() == qa_database


TEST_MODE = _isolated_test_mode()
EXTRA_TEST_ORIGINS = {"http://127.0.0.1:5180", "http://localhost:5180", "http://127.0.0.1:8010", "http://localhost:8010"} if TEST_MODE else set()


class LimitedLocalRequests:
    """Bound request memory and prevent browser cross-origin writes to local data."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        origin = headers.get(b"origin", b"").decode("latin1")
        allowed = {"http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173", "http://127.0.0.1:4173", "http://localhost:8000", "http://127.0.0.1:8000"} | EXTRA_TEST_ORIGINS
        if origin and origin not in allowed:
            return await JSONResponse({"detail": "Origin is not allowed to access this local API."}, status_code=403)(scope, receive, send)
        if headers.get(b"sec-fetch-site") == b"cross-site":
            return await JSONResponse({"detail": "Cross-site requests are not allowed."}, status_code=403)(scope, receive, send)
        limit = MAX_BYTES + 1024 * 1024
        try:
            if int(headers.get(b"content-length", b"0")) > limit:
                return await JSONResponse({"detail": "Request exceeds 26 MiB."}, status_code=413)(scope, receive, send)
        except ValueError:
            return await JSONResponse({"detail": "Invalid content length."}, status_code=400)(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > limit:
                return await JSONResponse({"detail": "Request exceeds 26 MiB."}, status_code=413)(scope, receive, send)
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        sent = False
        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return {"type": "http.disconnect"}
        async def secure_send(message):
            if message["type"] == "http.response.start":
                message["headers"] += [(b"x-content-type-options", b"nosniff"), (b"cache-control", b"no-store"), (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")]
            await send(message)
        await self.app(scope, replay, secure_send)


@asynccontextmanager
async def lifespan(app):
    with storage.connection():
        pass
    yield


app = FastAPI(title="PhishLens local API", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173", "http://127.0.0.1:4173"] + sorted(EXTRA_TEST_ORIGINS), allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type"])
app.add_middleware(LimitedLocalRequests)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmailInput(StrictModel):
    raw: str = Field(min_length=1, max_length=MAX_BYTES)


class URLInput(StrictModel):
    url: str = Field(min_length=1, max_length=8192)


class CaseInput(StrictModel):
    analysis_id: str = Field(min_length=1, max_length=100)
    notes: str = Field(default="", max_length=10000)


Status = Literal["Open", "In Progress", "In Review", "Resolved", "False Positive", "Closed", "Archived"]


class CaseUpdate(StrictModel):
    status: Status | None = None
    notes: str | None = Field(default=None, max_length=10000)


class ReportInput(StrictModel):
    analysis_id: str | None = Field(default=None, max_length=100)
    case_id: str | None = Field(default=None, max_length=100)
    include_raw: bool = False


class DeleteInput(StrictModel):
    confirm: Literal["DELETE ALL LOCAL DATA"]


def require(kind, identifier):
    item = storage.get(kind, identifier)
    if not item:
        raise HTTPException(404, f"{kind.capitalize()} record not found.")
    return item


def analyze_and_save(function, value):
    try:
        result = function(value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return storage.save("analysis", result)


@app.get("/api/health")
def health():
    models = model_status()
    loaded = sum(bool(value["available"]) for value in models.values())
    return {"status": "ok", "mode": "local-passive", "ml": {"available": loaded > 0, "reason": f"{loaded}/{len(models)} local archive classifiers loaded." if loaded else "Heuristic analysis is available. No local classifier is loaded."}, "models": models, "schema_version": 1, "test_mode": TEST_MODE}


@app.post("/api/analyze/email", status_code=201)
def analyze_email(payload: EmailInput):
    return analyze_and_save(inspect_email, payload.raw)


@app.post("/api/analyze/email/file", status_code=201)
async def analyze_file(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith(".eml"):
        raise HTTPException(422, "Choose an .eml file. Attachments are never executed.")
    data = await file.read(MAX_BYTES + 1)
    await file.close()
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "Email exceeds 25 MiB.")
    return analyze_and_save(inspect_email, data)


@app.post("/api/analyze/url", status_code=201)
def analyze_url(payload: URLInput):
    return analyze_and_save(inspect_url_submission, payload.url)


@app.get("/api/analyses")
def analyses():
    return storage.all_records("analysis")


@app.get("/api/analyses/{identifier}")
def analysis(identifier: str):
    return require("analysis", identifier)


@app.delete("/api/analyses/{identifier}", status_code=204)
def delete_analysis(identifier: str):
    require("analysis", identifier)
    # Cascade delete to remove all copies of potentially sensitive submitted text.
    cases = [c for c in storage.all_records("case") if c["analysis_id"] == identifier]
    for case in cases:
        storage.delete("case", case["id"])
    for report in storage.all_records("report"):
        if report["analysis_id"] == identifier:
            storage.delete("report", report["id"])
    storage.delete("analysis", identifier)
    return Response(status_code=204)


@app.post("/api/investigations", status_code=201)
def create_case(payload: CaseInput):
    scan = require("analysis", payload.analysis_id)
    at = now()
    final = scan.get("assessment") or {"method": "heuristic_fallback", "score": scan["score"], "risk": scan["risk"], "label": scan["risk"] + " heuristic risk", "limitations": ["Historical scan did not store an ML assessment."]}
    final_risk = final["risk"] if final.get("method") in {"ml", "validated_hybrid"} else scan["risk"]
    model_note = f"Stored model {scan['ml'].get('model_version', 'unknown')}; final assessment {final.get('label', final_risk)} via {final.get('method')}." if scan.get("ml", {}).get("available") else "No ML probability was obtained; heuristic assessment retained."
    case = {"id": "PL-" + uuid.uuid4().hex[:8].upper(), "analysis_id": scan["id"], "subject": scan["subject"], "score": scan["score"], "risk": final_risk, "heuristic_score": scan["score"], "heuristic_risk": scan["risk"], "assessment_method": final.get("method", "heuristic_fallback"), "final_assessment": final, "source": "Email" if scan["kind"] == "email" else "URL", "status": "Open", "notes": payload.notes, "created_at": at, "updated_at": at, "analysis": scan, "timeline": [{"at": at, "title": "Investigation created", "detail": "Promoted from a completed passive analysis."}, {"at": at, "title": "Evidence attached", "detail": f"{len(scan['evidence'])} observations; heuristic score {scan['score']}/100. {model_note}"}]}
    return storage.save("case", case)


@app.get("/api/investigations")
def cases():
    return storage.all_records("case")


@app.get("/api/investigations/{identifier}")
def case(identifier: str):
    return require("case", identifier)


@app.patch("/api/investigations/{identifier}")
def update_case(identifier: str, payload: CaseUpdate):
    item = require("case", identifier)
    updates = payload.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(422, "Provide status or analyst notes.")
    at = now()
    for field, value in updates.items():
        if item[field] != value:
            detail = f"{item[field]} → {value}" if field == "status" else "Analyst notes updated."
            item["timeline"].append({"at": at, "title": "Status changed" if field == "status" else "Analyst review", "detail": detail})
            item[field] = value
    item["updated_at"] = at
    return storage.save("case", item)


@app.delete("/api/investigations/{identifier}", status_code=204)
def delete_case(identifier: str):
    require("case", identifier)
    for report in storage.all_records("report"):
        if report.get("case_id") == identifier:
            storage.delete("report", report["id"])
    storage.delete("case", identifier)
    return Response(status_code=204)


@app.get("/api/metrics")
def metrics():
    items = [c for c in storage.all_records("case") if c["status"] != "Archived"]
    severity = Counter(c["risk"] for c in items)
    trend = defaultdict(list)
    categories = Counter()
    for item in items:
        trend[item["created_at"][:10]].append(item["score"])
        findings = item["analysis"]["evidence"]
        ids = " ".join(f["id"] for f in findings)
        # Each case belongs to one transparent priority category.
        category = "Credential language" if "language-credentials" in ids else "Brand / identity indicators" if "brand" in ids or "lookalike" in ids else "Attachment indicators" if "attachment" in ids else "URL syntax indicators" if any(f["source"].startswith(("URL", "Extracted URL", "HTML anchor")) for f in findings) else "Other / no indicators"
        categories[category] += 1
    return {"total": len(items), "high": severity["High"], "false_positives": sum(c["status"] == "False Positive" for c in items), "reports": len(storage.all_records("report")), "trend": [{"date": date, "score": round(sum(values) / len(values), 1)} for date, values in sorted(trend.items())], "severity": [{"name": name, "value": severity[name]} for name in ("High", "Medium", "Low")], "categories": [{"name": name, "value": value} for name, value in categories.items()]}


@app.post("/api/reports", status_code=201)
def create_report(payload: ReportInput):
    if bool(payload.case_id) == bool(payload.analysis_id):
        raise HTTPException(422, "Provide exactly one case_id or analysis_id.")
    case = require("case", payload.case_id) if payload.case_id else None
    scan = case["analysis"] if case else require("analysis", payload.analysis_id)
    report = {"id": "report-" + uuid.uuid4().hex[:16], "created_at": now(), "analysis_id": scan["id"], "case_id": case["id"] if case else None, "subject": scan["subject"], "include_raw": payload.include_raw}
    report["filename"] = "phishlens-" + report["id"] + ".pdf"
    report["url"] = f"/api/reports/{report['id']}/download"
    # Persist the exact evidence snapshot so later analyst edits do not rewrite reports.
    storage.save("report", {**report, "snapshot": scan, "case_snapshot": case})
    if case:
        case["timeline"].append({"at": report["created_at"], "title": "Report generated", "detail": report["filename"]})
        case["updated_at"] = report["created_at"]
        storage.save("case", case)
    return report


@app.get("/api/reports")
def reports():
    return [{k: v for k, v in r.items() if k not in {"snapshot", "case_snapshot"}} for r in storage.all_records("report")]


@app.get("/api/reports/{identifier}/download")
def download_report(identifier: str):
    report = require("report", identifier)
    try:
        data = generate_pdf(report["snapshot"], report, report.get("case_snapshot"), report.get("include_raw", False))
    except (LayoutError, ValueError, UnicodeError, OverflowError) as exc:
        # Do not expose raw submitted content or ReportLab internals in errors.
        raise HTTPException(422, "The report could not be laid out within printable limits. Generate it without raw email content, or shorten the submitted fields.") from exc
    return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{report["filename"]}"'})


@app.delete("/api/data", status_code=204)
def delete_data(payload: DeleteInput):
    storage.purge()
    return Response(status_code=204)
