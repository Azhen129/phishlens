"""Acquire licensed real email corpora as inert data for Phase 4 research.

Never follows a URL contained in an email, renders HTML, imports dataset code,
extracts ZIP paths, or executes an attachment. Fixed source URLs and hashes pin
the reviewed snapshot. CSV text contains subject and decoded body only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mailbox
import re
import ssl
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from langid.langid import LanguageIdentifier, model

HEADERS = {"User-Agent": "PhishLens-research/1.0 (licensed offline corpus acquisition)"}
HOSTS = {"www.monkey.org", "monkey.org", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
FIELDS = ["text", "label", "source", "group", "row_id", "date", "language"]
BODY_DIAGNOSTICS = Counter()
NAZARIO_ROOT = "https://www.monkey.org/~jose/phishing/"
SPECS = [
    {"filename": "nazario-phishing0.mbox", "url": NAZARIO_ROOT + "phishing0.mbox", "sha256": "6184b0a34ed8cbbb252676e21c1eab9eac5fa4be89c61e30cc9954ebbb25d848", "limit": 4_000_000, "count": 414},
    {"filename": "nazario-phishing1.mbox", "url": NAZARIO_ROOT + "phishing1.mbox", "sha256": "99f02474a11086408a5ce6d11ef38823f003c6611a4312c31fbee96773eeba28", "limit": 5_000_000, "count": 456},
    {"filename": "nazario-phishing2.mbox", "url": NAZARIO_ROOT + "phishing2.mbox", "sha256": "5113277984eae759a5ff958ccf408b542441ce033a49b923ab3b0f324075e6bd", "limit": 12_000_000, "count": 1423},
    {"filename": "nazario-phishing-2024.mbox", "url": NAZARIO_ROOT + "phishing-2024", "sha256": "60afa40a2757170093a2bde31ec9cda4e54d33992203ce04bfbbc86d2e5e5b99", "limit": 17_000_000, "count": 403},
    {"filename": "nazario-phishing-2025.mbox", "url": NAZARIO_ROOT + "phishing-2025", "sha256": "f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f", "limit": 20_000_000, "count": 481},
]
MASC = {
    "filename": "masc_500k_texts.zip",
    "url": "https://github.com/nancyide/anc-website/releases/download/datasets-2026-09-25/masc_500k_texts.zip",
    "sha256": "0c3f1fd3314ee5ec09830d6f6b217c19a6899d1cabd22c42264578c3348b2d01", "limit": 2_000_000,
}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_url(url: str) -> None:
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname not in HOSTS or p.username or p.password:
        raise ValueError("Download is outside the fixed reviewed corpus hosts.")


class ReviewedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(spec: dict, output: Path) -> Path:
    target = output / spec["filename"]
    if target.exists():
        if digest(target) != spec["sha256"]:
            raise ValueError(f"Existing {target.name} differs from the reviewed snapshot.")
        return target
    check_url(spec["url"])
    opener = urllib.request.build_opener(ReviewedRedirects(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    partial = target.with_suffix(target.suffix + ".partial")
    try:
        with opener.open(urllib.request.Request(spec["url"], headers=HEADERS), timeout=60) as response, partial.open("wb") as out:
            check_url(response.url)
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > spec["limit"]:
                    raise ValueError("Corpus exceeds its reviewed size limit.")
                out.write(chunk)
        if digest(partial) != spec["sha256"]:
            raise ValueError("Corpus checksum changed; review the new snapshot before use.")
        partial.replace(target)
    finally:
        if partial.exists():
            partial.unlink()
    return target


def body_text(message) -> str:
    """Prefer readable plain body, otherwise retain inert decoded HTML text.

    The shared training feature normalizer strips tags. Link destinations and
    message headers remain absent from the text-classifier input policy.
    """
    plain, html = [], []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment" or part.get_filename():
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            value = part.get_content()
        except LookupError:
            BODY_DIAGNOSTICS["unknown_charset_utf8_replacement"] += 1
            value = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        if isinstance(value, bytes):
            value = value.decode(part.get_content_charset() or "utf-8", errors="replace")
        (plain if part.get_content_type() == "text/plain" else html).append(str(value))
    return "\n".join(plain or html)[:200_000]


def thread_group(subject: str, source: str, row_id: str) -> str:
    value = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", subject.strip(), flags=re.I)
    value = re.sub(r"\s+", " ", value).strip().casefold()
    # Repeated subjects/threads are conservative group constraints; further
    # near-duplicate and campaign clustering belongs in the training pipeline.
    key = value or row_id
    return source + ":thread:" + hashlib.sha256(key.encode()).hexdigest()[:20]


def nazario_rows(paths: list[Path], counts: Counter):
    for path, spec in zip(paths, SPECS, strict=True):
        box = mailbox.mbox(path, create=False, factory=lambda stream: BytesParser(policy=policy.default).parse(stream))
        try:
            if len(box) != spec["count"]:
                raise ValueError(f"Unexpected mailbox count for {path.name}.")
            for number, message in enumerate(box):
                subject = str(message.get("Subject", ""))
                text = "Subject: " + subject + "\n\n" + body_text(message)
                row_id = hashlib.sha256(message.as_bytes()).hexdigest()
                counts["Nazario_all"] += 1
                yield {"text": text, "label": 1, "source": path.stem, "group": thread_group(subject, "Nazario", row_id), "row_id": row_id, "date": str(message.get("Date", "")), "language": "und"}
        finally:
            box.close()


def masc_rows(path: Path, counts: Counter):
    with zipfile.ZipFile(path) as archive:
        members = sorted(n for n in archive.namelist() if n.startswith("masc_500k_texts/written/email/") and n.endswith(".txt"))
        if len(members) != 80:
            raise ValueError("MASC snapshot should contain exactly 80 email documents, excluding its separate spam genre.")
        for name in members:
            item = archive.getinfo(name)
            if item.file_size > 100_000 or item.file_size / max(item.compress_size, 1) > 100:
                raise ValueError("Unexpected MASC archive member size.")
            raw = archive.read(name)
            value = raw.decode("utf-8-sig", errors="replace").lstrip()
            short = Path(name).stem
            source = "MASC-W3C" if short.startswith("lists-") else "MASC-Enron"
            if source == "MASC-W3C":
                metadata, body = re.split(r"\n[ \t]*\n", value, maxsplit=1)
                match = re.search(r'^subject="(.*)"$', metadata, re.M)
                subject = match.group(1) if match else ""
                date_match = re.search(r'^sent="(.*)"$', metadata, re.M)
                date = date_match.group(1) if date_match else ""
            elif value.startswith("Message-ID:"):
                message = BytesParser(policy=policy.default).parsebytes(value.encode("utf-8"))
                subject, body, date = str(message.get("Subject", "")), body_text(message), str(message.get("Date", ""))
            else:
                # Two additional plain-text Enron documents account for the
                # published 78 vs downloaded 80 discrepancy; each stays whole.
                subject, body, date = "", value, ""
            row_id = "masc:" + short
            counts[source + "_all"] += 1
            yield {"text": "Subject: " + subject + "\n\n" + body, "label": 0, "source": source, "group": thread_group(subject, source, row_id), "row_id": row_id, "date": date, "language": "en"}


def prepare(output: Path, min_english_probability: float = 0.90) -> dict:
    args = SimpleNamespace(output=output, min_english_probability=min_english_probability)
    if not 0.5 <= args.min_english_probability <= 1:
        raise ValueError("English language acceptance threshold must be between 0.5 and 1.")
    args.output.mkdir(parents=True, exist_ok=True)
    paths = [download(spec, args.output) for spec in SPECS]
    masc = download(MASC, args.output)
    identifier = LanguageIdentifier.from_modelstring(model, norm_probs=True)
    counts, rejected_languages = Counter(), Counter()
    all_rows = [*nazario_rows(paths, counts), *masc_rows(masc, counts)]
    target = args.output / "english-nazario-masc.csv"
    accepted = []
    for row in all_rows:
        # Import the application-owned offline normalizer, never dataset code.
        from backend.ml_features import normalize_email_text
        language, probability = identifier.classify(normalize_email_text(row["text"]))
        if language != "en" or probability < args.min_english_probability:
            rejected_languages[f"{language}:{row['label']}"] += 1
            continue
        row["language"] = "en"
        accepted.append(row)
    with target.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(accepted)
    classes = Counter(str(row["label"]) for row in accepted)
    provenance = {
        "name": "Nazario phishing + MASC email research subset", "version": "phase4-reviewed-2026-11-02",
        "task": "email", "supported_languages": ["en"], "approved_for_training": True,
        "source_url": NAZARIO_ROOT, "license": "CC BY 4.0 (Nazario) and CC BY 3.0 US (MASC)",
        "license_url": NAZARIO_ROOT + "LICENSE.txt",
        "permission_basis": "Author Nazario README explicitly licenses the files CC BY 4.0 including derivatives/commercial use. MASC official page permits any purpose under CC BY 3.0 US. Attribution and adaptation notice retained in docs/ml/phase4/DATASET_RESEARCH.md.",
        "attribution": "José Nazario, Phishing Corpus; American National Corpus Project, Manually Annotated Sub-Corpus (MASC).",
        "collection_notes": "Real hand-classified personal-inbox phishing, historical and 2024/2025; MASC routine Enron and W3C correspondence (linguistic email genre), separate MASC spam genre excluded. MASC genre is not publisher security annotation; manual contextual review and source bias limitations apply. No synthetic examples.",
        "validation_scope": "Small source-confounded English research benchmark. Personal-inbox phishing versus historical Enron/W3C routine email. Cannot establish broad English phishing detection, field prevalence calibration, or source-disjoint generalization. MASC legitimate sample is small and is not professionally adjudicated security ground truth.",
        "changes": "Decoded subject+body only; removed mail transport metadata and attachments; plain text preferred; unsupported/uncertain langid outputs filtered; subject-derived conservative thread groups retained. No email was split into artificial samples.",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "raw": [{"url": spec["url"], "path": path.as_posix(), "sha256": digest(path), "bytes": path.stat().st_size} for spec, path in zip([*SPECS, MASC], [*paths, masc], strict=True)],
        "prepared": {"path": target.as_posix(), "sha256": digest(target), "rows": len(accepted), "class_balance": dict(classes), "label_mapping": {"0": "legitimate", "1": "phishing"}},
        "language_filter": {"tool": "langid", "normalized_probability_threshold": args.min_english_probability, "rejected_language_label_counts": dict(rejected_languages)},
        "original_counts": dict(counts),
        "body_decoding_diagnostics": dict(BODY_DIAGNOSTICS),
        "limitations": [
            "Labels are perfectly confounded with source families; report source-only baseline and holdout source stress tests.",
            "MASC email genre contributes only 80 original files (publisher overview says78); legitimate label is contextual, not a security adjudication from the publisher.",
            "Phishing inbox curator acknowledges hand-label errors and nonexhaustive representativeness; earlier mailboxes anonymized, later ones not.",
            "Historical legitimate messages (1990s/2000s) versus newer phishing cause era and formatting bias. Source header removal cannot eliminate all content bias.",
            "Related threads, campaigns and copied bodies must remain grouped; source/thread groups here are only initial constraints.",
            "Corpus class balance and calibration cannot be treated as deployment prevalence or universally calibrated confidence.",
            "Language ID is an imperfect offline filter, not a guarantee of English or single-language content.",
        ],
    }
    destination = args.output / "english-nazario-masc-provenance.json"
    destination.write_text(json.dumps(provenance, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"prepared": provenance["prepared"], "original_counts": dict(counts), "rejected_language_label_counts": dict(rejected_languages), "provenance": destination.as_posix()}, indent=2))
    return provenance


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/phase4/raw"))
    parser.add_argument("--min-english-probability", type=float, default=0.90)
    args = parser.parse_args()
    prepare(args.output, args.min_english_probability)


if __name__ == "__main__":
    # Permit `python scripts/acquire_english_dataset.py` from the repository.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    main()
