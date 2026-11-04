"""Deterministic, entirely offline email and URL inspection.

This module deliberately has no HTTP client or DNS resolver. Scores are rule
weights, not calibrated probabilities. Submitted headers remain untrusted.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import PurePath
from urllib.parse import unquote, urlsplit, urlunsplit

MAX_BYTES = 25 * 1024 * 1024
MAX_URLS = 200
MAX_PARTS = 200
MODEL_REASON = "Not trained / unavailable: no licensed, provenance-documented training dataset has been supplied. Rules only; scores are not probabilities."
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
RISKY_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".com", ".hta", ".msi", ".lnk", ".iso"}
BRANDS = {"microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com"), "paypal": ("paypal.com",), "google": ("google.com", "gmail.com"), "apple": ("apple.com", "icloud.com"), "amazon": ("amazon.com", "amazon.co.uk")}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def risk(score: int) -> str:
    return "High" if score >= 60 else "Medium" if score >= 25 else "Low"


def evidence(code: str, title: str, detail: str, severity: str, source: str, weight: int) -> dict:
    return {"id": code, "title": title, "detail": detail, "severity": severity, "source": source, "weight": weight}


def owned_domain(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def edit_distance_one(a: str, b: str) -> bool:
    """Only exact single insertion/deletion/substitution, never broad similarity."""
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    shorter, longer = sorted((a, b), key=len)
    return any(longer[:i] + longer[i + 1:] == shorter for i in range(len(longer)))


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("Provide a URL of at most 8,192 characters without control characters.")
    if re.match(r"^[a-z][a-z0-9+.-]*:", value, re.I) and not re.match(r"^https?://", value, re.I):
        raise ValueError("Only http:// and https:// URLs are accepted for passive inspection.")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError("URL has an invalid host or port.") from exc
    if parts.scheme.lower() not in {"https", "http"} or not host or "\\" in parts.netloc or re.search(r"\s", parts.netloc):
        raise ValueError("Provide a valid HTTP(S) URL with a hostname.")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Hostname cannot be normalized.") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(ascii_host) > 253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in ascii_host.rstrip(".").split(".")):
            raise ValueError("Hostname contains invalid characters or labels.")
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, parts.fragment))


def inspect_url(value: str) -> tuple[dict, list[dict]]:
    normalized = normalize_url(value)
    parts = urlsplit(normalized)
    host = (parts.hostname or "").lower().rstrip(".")
    findings = []
    def add(code, title, detail, severity, weight):
        findings.append(evidence(code, title, detail, severity, "URL syntax", weight))
    if parts.username is not None:
        add("url-userinfo", "Credentials embedded in URL", "The URL contains a user-info segment before @. This can disguise the actual destination host: " + host, "High", 22)
    try:
        address = ipaddress.ip_address(host)
        add("url-ip", "Numeric IP destination", f"The destination is the literal IP address {address}. This is a syntax indicator, not proof of abuse; no connection was made.", "Medium", 18)
    except ValueError:
        pass
    if parts.scheme == "http":
        add("url-http", "Unencrypted URL scheme", "The supplied URL uses HTTP rather than HTTPS. This does not establish malicious intent.", "Low", 8)
    if "xn--" in host or any(ord(c) > 127 for c in host):
        add("url-idn", "Internationalized hostname", "The hostname contains Unicode or punycode. Visually similar characters may obscure identity; internationalized names can also be legitimate.", "Medium", 15)
    if len(host.split(".")) >= 5:
        add("url-depth", "Unusual subdomain depth", f"The hostname has {len(host.split('.'))} labels. Review its actual domain carefully.", "Medium", 10)
    if "%" in parts.netloc or re.search(r"%25|%2f|%5c|%40", normalized, re.I):
        add("url-encoding", "Obscuring URL encoding", "Encoded separators or nested percent encoding appear in the URL. Review the literal hostname and decoded structure.", "Medium", 12)
    if len(parts.path) + len(parts.query) > 250:
        add("url-length", "Long path or query", "The path and query exceed 250 characters; long URLs may conceal important details but are also common in legitimate services.", "Low", 5)
    if host.count("-") >= 3:
        add("url-hyphens", "Hyphen-heavy hostname", "The hostname contains at least three hyphens. Review the destination independently.", "Low", 6)
    for brand, official in BRANDS.items():
        if owned_domain(host, official):
            continue
        labels = host.split(".")
        if any(brand in label for label in labels):
            add("url-brand-" + brand, "Brand name in unrelated hostname", f"The hostname includes '{brand}' but is outside the configured {brand} domain list ({', '.join(official)}). Ownership is not independently verified.", "High", 22)
        elif any(edit_distance_one(label, brand) for label in labels[:-1]):
            add("url-lookalike-" + brand, "One-edit brand lookalike", f"A hostname label differs by exactly one character from '{brand}' and is outside its configured domains. This is a narrow comparison rule, not an ownership verdict.", "High", 20)
    score = min(100, sum(f["weight"] for f in findings))
    return {"url": normalized, "host": host, "score": score, "risk": risk(score), "reason": "; ".join(f["title"] for f in findings) if findings else "No known syntax indicators detected; not verified safe."}, findings


class InertHTML(HTMLParser):
    """Collect text and anchors; never execute markup, load images or follow links."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.current = None
        self.ignore = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.ignore += 1
        if tag in {"p", "br", "div", "li", "tr"}:
            self.text.append("\n")
        if tag == "a" and not self.ignore:
            href = dict(attrs).get("href", "")
            self.current = [href, []]

    def handle_data(self, data):
        if not self.ignore:
            self.text.append(data)
            if self.current:
                self.current[1].append(data)

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.ignore = max(0, self.ignore - 1)
        if tag == "a" and self.current:
            self.links.append((self.current[0], "".join(self.current[1]).strip()))
            self.current = None


def decode_part(part) -> str:
    content = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return content.decode(charset, errors="replace")
    except (LookupError, UnicodeError):
        return content.decode("utf-8", errors="replace")


def inspect_email(raw: str | bytes, *, use_ml: bool = True) -> dict:
    started = time.perf_counter()
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if not data.strip():
        raise ValueError("Paste an email or choose a non-empty .eml file.")
    if len(data) > MAX_BYTES:
        raise ValueError("Email exceeds the 25 MiB limit.")
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Unable to parse this MIME email safely.") from exc
    headers = {}
    for index, (key, val) in enumerate(msg.items()):
        if index >= 1000:
            raise ValueError("Email contains too many headers.")
        headers[key] = (headers.get(key, "") + ("\n" if key in headers else "") + str(val))[:50000]
    plain, html_text, anchors, attachments = [], [], [], []
    stack = [(msg, 0)]
    part_count = 0
    while stack:
        part, depth = stack.pop()
        part_count += 1
        if depth > 20 or part_count > MAX_PARTS:
            raise ValueError("Email MIME nesting/part count exceeds the safe parser limit (20 levels / 200 parts).")
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            # message/rfc822 payloads are lists even when they are attachments.
            # Inventory the attached message as opaque bytes, never traverse it.
            content = part.get_payload(decode=True)
            if content is None and isinstance(part.get_payload(), list):
                content = b"\n".join(p.as_bytes(policy=policy.default) for p in part.get_payload())
            content = content or b""
            # Filenames are display-only. No attachment bytes are written or expanded.
            filename = (filename or "unnamed-attachment").replace("\\", "/").rsplit("/", 1)[-1][:255]
            attachments.append({"filename": filename, "content_type": part.get_content_type(), "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        elif part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                stack.extend((p, depth + 1) for p in reversed(payload))
            continue
        elif part.get_content_type() == "text/plain":
            plain.append(decode_part(part)[:500000])
        elif part.get_content_type() == "text/html":
            parsed = InertHTML()
            parsed.feed(decode_part(part)[:500000])
            html_text.append("".join(parsed.text))
            anchors.extend(parsed.links)
    body = "\n".join(plain or html_text)[:500000]
    urls = []
    candidates = [href for href, _ in anchors] + URL_RE.findall(body)
    for value in candidates:
        value = value.rstrip(".,;!?)]")
        if re.match(r"^https?://", value, re.I) and value not in urls:
            urls.append(value)
        if len(urls) >= MAX_URLS:
            break
    links, findings = [], []
    for index, value in enumerate(urls):
        try:
            link, indicators = inspect_url(value)
        except ValueError:
            continue
        links.append(link)
        for indicator in indicators:
            indicator["id"] += f"-{index}"
            indicator["source"] = f"Extracted URL {index + 1}"
            indicator["detail"] += f" Submitted destination: {link['host']}."
            findings.append(indicator)
    # Display-text mismatch is asserted only when visible text is itself a URL/host.
    # 'Verify account' is a generic label and cannot establish a URL mismatch.
    for index, (href, label) in enumerate(anchors):
        if not label or not re.match(r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/|$)", label, re.I):
            continue
        try:
            visible_host = urlsplit(normalize_url(label)).hostname
            actual_host = urlsplit(normalize_url(href)).hostname
        except ValueError:
            continue
        if visible_host != actual_host:
            findings.append(evidence(f"display-mismatch-{index}", "Display text vs. destination mismatch", f"The visible link names {visible_host}, while its href points to {actual_host}.", "High", "HTML anchor", 28))
    from_value = str(msg.get("From", ""))
    reply_value = str(msg.get("Reply-To", ""))
    from_addr = parseaddr(from_value)[1]
    reply_addr = parseaddr(reply_value)[1]
    from_host = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""
    reply_host = reply_addr.rsplit("@", 1)[-1].lower() if "@" in reply_addr else ""
    if from_host and reply_host and from_host != reply_host:
        findings.append(evidence("reply-to-mismatch", "Reply-to and sender domains differ", f"From uses {from_host}; Reply-To uses {reply_host}. Delegated mail services can legitimately differ; validate the intended reply destination.", "Medium", "Email headers", 14))
    display = parseaddr(from_value)[0].lower()
    for brand, official in BRANDS.items():
        if brand in display and from_host and not owned_domain(from_host, official):
            findings.append(evidence("sender-brand-" + brand, "Sender display name claims a brand", f"Display name contains '{brand}', but the From domain {from_host} is outside the configured domain list. No domain ownership lookup was performed.", "High", "Email headers", 20))
    subject = str(msg.get("Subject", "Untitled email"))
    # Both MIME alternatives can carry distinct social-engineering language.
    # The UI body can prefer plain text while rules inspect all inert variants.
    text = subject + "\n" + "\n".join(plain + html_text)
    language_rules = [
        ("urgency", r"\burgent\b|\bimmediate(?:ly)?\b|\baction required\b|within\s+(?:24|48)\s+hours", "Urgent / coercive language", 10),
        ("credentials", r"\bverify\s+(?:your\s+)?account\b|\bpassword\b|\blog\s?in\b|\bsign[ -]?in\b", "Account or credential language", 8),
        ("threat", r"\bsuspend(?:ed)?\b|\bsuspension\b|\bwill be closed\b|\bservice interruption\b|\bpermanently disabled\b", "Threat of account or service loss", 10),
        ("payment", r"\bwire transfer\b|\bbank details\b|\bpayment\b|\binvoice\b", "Financial / payment request", 6),
    ]
    for code, pattern, title, weight in language_rules:
        matches = list(dict.fromkeys(m.group(0) for m in re.finditer(pattern, text, re.I)))[:5]
        if matches:
            findings.append(evidence("language-" + code, title, "Observed phrases: " + ", ".join(repr(m) for m in matches) + ". Language alone does not prove phishing.", "Medium" if weight >= 8 else "Low", "Message language", weight))
    auth_values = "\n".join(str(v) for v in msg.get_all("Authentication-Results", []))
    authentication = {}
    reported_failures = []
    for method in ("spf", "dkim", "dmarc"):
        statuses = re.findall(r"\b" + method + r"\s*=\s*([a-z_-]+)", auth_values, re.I)
        if statuses:
            unique = ", ".join(dict.fromkeys(s.lower() for s in statuses))
            authentication[method.upper()] = f"Reported {unique} in supplied headers; unverified by PhishLens"
            if any(s.lower() in {"fail", "softfail", "permerror"} for s in statuses):
                reported_failures.append(method.upper())
        else:
            authentication[method.upper()] = "Not verified — no supplied Authentication-Results observation"
    if reported_failures:
        findings.append(evidence("auth-reported-failure", "Reported authentication failures (unverified)", f"Supplied Authentication-Results reports failures for {', '.join(reported_failures)}. The header itself is untrusted; PhishLens did not verify SPF, DKIM or DMARC.", "Medium", "Supplied headers (unverified)", 8))
    for index, attachment in enumerate(attachments):
        suffix = PurePath(attachment["filename"]).suffix.lower()
        if suffix in RISKY_EXTENSIONS:
            findings.append(evidence(f"attachment-{index}", "Executable or active attachment type", f"{attachment['filename']} has the {suffix} extension. Only metadata and SHA-256 were inspected; bytes were never executed or scanned for malware.", "High", "Attachment metadata", 22))
        elif suffix in {".docm", ".xlsm", ".pptm"}:
            findings.append(evidence(f"attachment-{index}", "Macro-capable attachment extension", f"{attachment['filename']} uses a macro-capable extension. Metadata only; macro presence and malware status are unknown.", "Medium", "Attachment metadata", 12))
    addresses = sorted(set(a for _, a in getaddresses([str(msg.get(k, "")) for k in ("From", "To", "Cc", "Reply-To")]) if a))
    domains = sorted(set([a.rsplit("@", 1)[-1].lower() for a in addresses if "@" in a] + [l["host"] for l in links]))
    # Duplicating one URL cannot inflate a score: each rule family counts once.
    grouped = {}
    for finding in findings:
        family = re.sub(r"-\d+$", "", finding["id"])
        grouped[family] = max(grouped.get(family, 0), finding["weight"])
    score = min(100, sum(grouped.values()))
    result = base_result("email", subject, score, findings, links, started)
    result.update({"attachments": attachments, "email": {"from": from_value, "to": str(msg.get("To", "")), "reply_to": reply_value, "date": str(msg.get("Date", "")), "headers": headers, "body": body, "raw": data.decode("utf-8", errors="replace"), "addresses": addresses, "domains": domains, "authentication": authentication}})
    if use_ml:
        _apply_ml(result, "Subject: " + subject + "\n\n" + body)
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def base_result(kind: str, subject: str, score: int, findings: list, links: list, started: float) -> dict:
    label = risk(score)
    summary = (f"{len(findings)} evidence observation{'s' if len(findings) != 1 else ''} identified. " if findings else "No configured indicators detected. ")
    summary += {"High": "Multiple weighted indicators warrant heightened caution and independent verification.", "Medium": "Review the documented indicators before taking action.", "Low": "Low observed heuristic risk does not establish that this input is safe."}[label]
    return {"id": "scan-" + uuid.uuid4().hex[:16], "kind": kind, "created_at": now(), "subject": subject, "score": score, "heuristic_score": score, "risk": label, "summary": summary, "evidence": findings, "links": links, "attachments": [], "email": None, "ml": {"available": False, "reason": "ML inference was not requested for this heuristic-only calculation."}, "assessment": {"method": "heuristic_fallback", "score": score, "risk": label, "label": label + " heuristic risk", "limitations": ["Rule points are not calibrated probabilities."]}, "duration_ms": round((time.perf_counter() - started) * 1000, 2)}


def inspect_url_submission(value: str, *, use_ml: bool = True) -> dict:
    started = time.perf_counter()
    link, findings = inspect_url(value)
    result = base_result("url", link["url"], link["score"], findings, [link], started)
    if use_ml:
        _apply_ml(result, link["url"])
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def _apply_ml(result: dict, text: str) -> None:
    # The original rule score, summary, observations and stored records retain
    # their meaning. Model and validated hybrid assessments are separate fields.
    from .ml_runtime import assess
    result["ml"], result["assessment"] = assess(result["kind"], text, result["score"], result["risk"])
