"""Stateless public demo API with bounded offline analysis and PDF responses."""
from __future__ import annotations

import base64
import threading
import uuid
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from reportlab.platypus.doctemplate import LayoutError
from starlette.concurrency import run_in_threadpool

from .analysis import inspect_email, inspect_url_submission, now
from .reports import generate_pdf


MAX_DEMO_EMAIL_BYTES = 256 * 1024
MAX_DEMO_REQUEST_BYTES = 512 * 1024
DEMO_REASON = "The public demonstration runs using passive heuristic rules. Private research classifiers are unavailable in this deployment."
DEMO_STORAGE = "Case history and report files stay in this browser tab's temporary memory and reset on reload. Submitted content is processed for this response and is not written to an application database."
_work_slots = threading.BoundedSemaphore(2)


class DemoRequests:
    """Cap bytes before parsing and keep browser requests on the same origin."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        origin = headers.get(b"origin", b"").decode("latin1")
        host = headers.get(b"host", b"").decode("latin1").lower()
        try:
            origin_parts = urlsplit(origin)
            host_name = urlsplit("https://" + host).hostname
        except ValueError:
            return await JSONResponse({"detail": "Invalid request origin."}, status_code=403)(scope, receive, send)
        local = host_name in {"localhost", "127.0.0.1", "testserver"} and origin_parts.hostname in {"localhost", "127.0.0.1", "testserver"}
        same_origin = origin_parts.scheme in {"http", "https"} and origin_parts.netloc.lower() == host
        if origin and not (same_origin or local):
            return await JSONResponse({"detail": "Cross-origin demo requests are not allowed."}, status_code=403)(scope, receive, send)
        if headers.get(b"sec-fetch-site") == b"cross-site":
            return await JSONResponse({"detail": "Cross-site demo requests are not allowed."}, status_code=403)(scope, receive, send)
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "Invalid content length."}, status_code=400)(scope, receive, send)
        if content_length < 0 or content_length > MAX_DEMO_REQUEST_BYTES:
            return await JSONResponse({"detail": "Public demo requests are limited to 512 KiB."}, status_code=413)(scope, receive, send)
        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > MAX_DEMO_REQUEST_BYTES:
                return await JSONResponse({"detail": "Public demo requests are limited to 512 KiB."}, status_code=413)(scope, receive, send)
            chunks.append(body)
            if not message.get("more_body", False):
                break
        consumed = False

        async def replay():
            nonlocal consumed
            if consumed:
                return {"type": "http.disconnect"}
            consumed = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message["headers"] += [
                    (b"cache-control", b"no-store, private"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
                ]
            await send(message)

        await self.app(scope, replay, secure_send)


app = FastAPI(title="PhishLens public demonstration API", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(DemoRequests)


@app.exception_handler(RequestValidationError)
async def invalid_input(request, exc):
    return JSONResponse({"detail": "Request fields are invalid or exceed the public demo limits."}, status_code=422)


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmailInput(StrictInput):
    raw: str = Field(min_length=1, max_length=MAX_DEMO_EMAIL_BYTES)


class URLInput(StrictInput):
    url: str = Field(min_length=1, max_length=8192)


class DemoEvent(StrictInput):
    at: datetime
    title: str = Field(max_length=120)
    detail: str = Field(max_length=1000)


class DemoCase(StrictInput):
    id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    status: Literal["Open", "In Progress", "In Review", "Resolved", "False Positive", "Closed", "Archived"] = "Open"
    notes: str = Field(default="", max_length=4000)
    created_at: datetime | None = None
    timeline: list[DemoEvent] = Field(default_factory=list, max_length=20)


class DemoReportInput(StrictInput):
    kind: Literal["email", "url"]
    input: str | None = Field(default=None, min_length=1, max_length=MAX_DEMO_EMAIL_BYTES)
    input_base64: str | None = Field(default=None, min_length=1, max_length=4 * ((MAX_DEMO_EMAIL_BYTES + 2) // 3))
    analysis_id: str | None = Field(default=None, min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    analyzed_at: datetime | None = None
    report_id: str | None = Field(default=None, min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    created_at: datetime | None = None
    case: DemoCase | None = None
    include_raw: bool = False

    @model_validator(mode="after")
    def validate_source(self):
        if (self.input is None) == (self.input_base64 is None):
            raise ValueError("Provide exactly one source representation.")
        if self.kind == "url" and self.input_base64 is not None:
            raise ValueError("URL input must be text.")
        return self


def _timestamp(value: datetime | None) -> str:
    if value is None:
        return now()
    return value.replace(tzinfo=timezone.utc).isoformat(timespec="seconds") if value.tzinfo is None else value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _inspect(kind: str, value: str | bytes) -> dict:
    if kind == "email":
        data = value.encode("utf-8") if isinstance(value, str) else value
        if len(data) > MAX_DEMO_EMAIL_BYTES:
            raise HTTPException(413, "The public demo accepts emails up to 256 KiB.")
        result = inspect_email(value, use_ml=False)
    else:
        result = inspect_url_submission(value, use_ml=False)
    if len(result["evidence"]) > 80 or len(result["links"]) > 40 or len(result["attachments"]) > 20:
        raise HTTPException(422, "The public demo accepts at most 80 findings, 40 links and 20 attachments per analysis.")
    result["ml"] = {"available": False, "reason": DEMO_REASON, "score_type": "heuristic_only", "deployment_mode": "public-demo"}
    result["demo"] = {"mode": "public-demo", "storage": "temporary-browser-memory", "limitations": [DEMO_REASON, DEMO_STORAGE]}
    return result


def _bounded_analysis(kind: str, value: str | bytes) -> dict:
    if not _work_slots.acquire(blocking=False):
        raise HTTPException(429, "The demo is busy. Try again shortly.")
    try:
        return _inspect(kind, value)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise HTTPException(422, "This input could not be inspected within the public demo limits.") from None
    finally:
        _work_slots.release()


@app.get("/api/health")
def health():
    return {
        "status": "ok", "mode": "public-demo", "test_mode": False,
        "ml": {"available": False, "reason": DEMO_REASON},
        "models": {key: {"available": False, "reason": DEMO_REASON} for key in ("email", "email_en", "url")},
        "demo": {"storage": "temporary-browser-memory", "email_limit_bytes": MAX_DEMO_EMAIL_BYTES, "request_limit_bytes": MAX_DEMO_REQUEST_BYTES, "limitations": [DEMO_REASON, DEMO_STORAGE]},
    }


@app.post("/api/analyze/email", status_code=201)
def analyze_email(payload: EmailInput):
    return _bounded_analysis("email", payload.raw)


@app.post("/api/analyze/email/file", status_code=201)
async def analyze_file(file: UploadFile = File(...)):
    try:
        if not (file.filename or "").lower().endswith(".eml"):
            raise HTTPException(422, "Choose an .eml file for passive inspection.")
        data = await file.read(MAX_DEMO_EMAIL_BYTES + 1)
    finally:
        await file.close()
    return await run_in_threadpool(_bounded_analysis, "email", data)


@app.post("/api/analyze/url", status_code=201)
def analyze_url(payload: URLInput):
    return _bounded_analysis("url", payload.url)


@app.post("/api/demo/reports")
def report_pdf(payload: DemoReportInput):
    if not _work_slots.acquire(blocking=False):
        raise HTTPException(429, "The demo is busy. Try again shortly.")
    try:
        if payload.kind == "url" and len(payload.input) > 8192:
            raise HTTPException(422, "URL inputs are limited to 8,192 characters.")
        source = base64.b64decode(payload.input_base64, validate=True) if payload.input_base64 is not None else payload.input
        scan = _inspect(payload.kind, source)
        scan["id"] = payload.analysis_id or scan["id"]
        scan["created_at"] = _timestamp(payload.analyzed_at)
        scan["summary"] = "Public demonstration. Findings were recomputed from the submitted source using passive heuristic rules. " + scan["summary"]
        report = {"id": payload.report_id or "report-" + uuid.uuid4().hex[:16], "created_at": _timestamp(payload.created_at)}
        case = None
        if payload.case:
            supplied = payload.case
            case = {
                "id": supplied.id, "status": supplied.status, "notes": supplied.notes,
                "timeline": [{"at": _timestamp(event.at), "title": event.title, "detail": event.detail} for event in supplied.timeline],
            }
            if not case["timeline"]:
                case["timeline"] = [{"at": _timestamp(supplied.created_at), "title": "Temporary demonstration case", "detail": "Browser-session analyst notes and status supplied for this report."}]
        data = generate_pdf(scan, report, case, payload.include_raw)
    except (LayoutError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise HTTPException(422, "The report could not be rendered within the public demo limits.") from None
    finally:
        _work_slots.release()
    return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="phishlens-{report["id"]}.pdf"'})
