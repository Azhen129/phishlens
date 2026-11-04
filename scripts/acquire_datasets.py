"""Acquire reviewed, explicitly licensed research data; never access contained URLs.

Only fixed repository download URLs are used. This script reads data as CSV/ZIP
bytes, does not import dataset code, render HTML, or extract archive paths.
Raw and prepared files default to ignored work/phase3/raw/.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import ssl
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


HEADERS = {"User-Agent": "PhishLens-research/1.0 (licensed offline dataset acquisition)"}
ALLOWED_HOSTS = {
    "data.mendeley.com", "archive.ics.uci.edu",
    "prod-dcd-datasets-public-files-eu-west-1.s3.eu-west-1.amazonaws.com",
}
SPAPHISH = {
    "url": "https://data.mendeley.com/public-files/datasets/hz2d6gz7pc/files/f796c8e2-3768-4c2d-8b73-48f0d7771de5/file_downloaded",
    "sha256": "656b2245d58da72d640680e5c2a168673a130b38607f2a427c773bbb167e995e",
    "filename": "spaphish-v5.csv", "limit": 8_000_000,
}
PHIUSIIL = {
    "url": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
    "sha256": "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a",
    "filename": "phiusiil.zip", "limit": 25_000_000,
}
FIELDS = ["text", "label", "source", "group", "row_id", "date", "language"]


class RepositoryRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_repository_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_repository_url(url: str) -> None:
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname not in ALLOWED_HOSTS or p.username or p.password:
        raise ValueError("Download redirect is outside the fixed reviewed repository hosts.")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(spec: dict, output: Path) -> Path:
    target = output / spec["filename"]
    if target.exists():
        if sha256(target) != spec["sha256"]:
            raise ValueError(f"Existing {target.name} does not match its recorded SHA-256.")
        return target
    check_repository_url(spec["url"])
    opener = urllib.request.build_opener(RepositoryRedirects(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    partial = target.with_suffix(target.suffix + ".partial")
    try:
        request = urllib.request.Request(spec["url"], headers=HEADERS)
        with opener.open(request, timeout=60) as response, partial.open("wb") as destination:
            check_repository_url(response.url)
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > spec["limit"]:
                    raise ValueError("Repository payload exceeds the acquisition size limit.")
                destination.write(chunk)
        if sha256(partial) != spec["sha256"]:
            raise ValueError("Repository payload checksum changed; review the new snapshot before use.")
        partial.replace(target)
    finally:
        if partial.exists():
            partial.unlink()
    return target


def write_common(path: Path, rows) -> dict:
    counts = Counter()
    total = 0
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            if row["label"] not in {0, 1}:
                raise ValueError("Unrecognized binary label in reviewed dataset.")
            if len(row["text"]) > 5_000_000:
                raise ValueError("Dataset row exceeds the acquisition text limit.")
            writer.writerow(row)
            counts[str(row["label"])] += 1
            total += 1
    return {"path": path.as_posix(), "sha256": sha256(path), "rows": total, "class_balance": dict(sorted(counts.items())), "label_mapping": {"0": "legitimate", "1": "phishing"}}


def prepare_email(output: Path) -> dict:
    raw = download(SPAPHISH, output)
    def rows():
        # Actual v5 bytes use commas, despite README saying semicolons. Validate
        # actual schema rather than trusting an incorrect delimiter description.
        with raw.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not {"hash", "subject", "body", "date", "Label"} <= set(reader.fieldnames or []):
                raise ValueError("SpaPhish v5 schema differs from the reviewed snapshot.")
            for row in reader:
                yield {"text": "Subject: " + row["subject"] + "\n\n" + row["body"], "label": int(row["Label"]), "source": "SpaPhish-v5", "group": "", "row_id": row["hash"], "date": row["date"], "language": "es"}
    prepared = write_common(output / "email.csv", rows())
    if prepared["rows"] != 1395 or prepared["class_balance"] != {"0": 664, "1": 731}:
        raise ValueError("SpaPhish counts differ from the reviewed release.")
    return {
        "name": "SpaPhish", "version": "5", "task": "email", "language": "es",
        "approved_for_training": True, "supported_languages": ["es"],
        "validation_scope": "Spanish-only anonymized author-inbox emails in SpaPhish v5. Does not validate English email predictions or deployment prevalence; source/campaign and collection-era limitations remain.",
        "source_url": "https://data.mendeley.com/datasets/hz2d6gz7pc/5",
        "doi": "10.17632/hz2d6gz7pc.5",
        "paper_url": "https://pmc.ncbi.nlm.nih.gov/articles/PMC13273897/",
        "license": "CC BY 4.0", "license_url": "https://creativecommons.org/licenses/by/4.0/",
        "attribution": "Bustio-Martinez, L., Fuentes-Fuentes, V., Agudelo-Fuentes, L. F., Herrera-Semenets, V., Llanes-Guilarte, D., Trujillo-Fernandez, F. A., Cardeña-Matamoros, C. A., Betancourt-Moreno, C. F., Haase-Hernandez, J. I., Molano-Jimenez, A. G., and van den Berg, J. (2026). SpaPhish: A Spanish Dataset for Phishing and Psychological Pattern Detection, version 5. Mendeley Data.",
        "permission_basis": "The dataset creators release their manually anonymized inbox collection under explicit CC BY 4.0; attribution and adaptation notice are retained.",
        "collection_notes": "Real Spanish personal/institutional inbox email from 2014–2025. Creator triple-annotator phishing/legitimate labeling; majority/adjudication; generic spam excluded. No original sender/campaign identifiers are public. SHA-256 row IDs and dates are retained for grouping/audits; technical and psychological annotations are excluded from model inputs.",
        "changes": "Selected subject/body only, joined as Subject: + subject + blank line + body; retained labels 0=legitimate/1=phishing; ignored derived/annotated features. Actual release delimiter is comma, contrary to README description.",
        "raw": {"path": raw.as_posix(), "url": SPAPHISH["url"], "sha256": sha256(raw), "bytes": raw.stat().st_size},
        "prepared": prepared,
        "limitations": ["Spanish only; this corpus does not validate English email inference.", "Small author-inbox collection with collection/time/source bias; anonymization may introduce artifacts.", "No sender or campaign grouping metadata; near-duplicate grouping must be computed from text before splitting.", "Anonymization changes named entities; corpus benchmark calibration is not deployment prevalence calibration."],
    }


def prepare_url(output: Path) -> dict:
    raw = download(PHIUSIIL, output)
    stats = {"legitimate_https": 0, "legitimate_max_url_length": 0, "legitimate_with_path": 0}
    def rows():
        with zipfile.ZipFile(raw) as archive:
            name = "PhiUSIIL_Phishing_URL_Dataset.csv"
            item = archive.getinfo(name)
            if item.file_size > 70_000_000 or item.file_size / max(1, item.compress_size) > 20:
                raise ValueError("Unexpected archive expansion ratio/size.")
            # Read only the exact expected member in memory; never extract paths.
            with archive.open(name) as binary, io.TextIOWrapper(binary, encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                if not {"URL", "label"} <= set(reader.fieldnames or []):
                    raise ValueError("PhiUSIIL schema differs from the reviewed snapshot.")
                for index, row in enumerate(reader):
                    original = int(row["label"])
                    if original not in {0, 1}:
                        raise ValueError("Unknown PhiUSIIL source label.")
                    text = row["URL"]
                    if original == 1:
                        parts = urlsplit(text)
                        stats["legitimate_https"] += parts.scheme.lower() == "https"
                        stats["legitimate_max_url_length"] = max(stats["legitimate_max_url_length"], len(text))
                        stats["legitimate_with_path"] += parts.path not in {"", "/"}
                    yield {"text": text, "label": 1 - original, "source": "PhiUSIIL-UCI967", "group": "", "row_id": f"uci967-{index}", "date": "", "language": "url"}
    prepared = write_common(output / "url.csv", rows())
    if prepared["rows"] != 235795 or prepared["class_balance"] != {"0": 134850, "1": 100945}:
        raise ValueError("PhiUSIIL counts differ from the reviewed release.")
    return {
        "name": "PhiUSIIL Phishing URL (Website)", "version": "UCI-967-2024-snapshot", "task": "url",
        "approved_for_training": True, "supported_languages": [],
        "validation_scope": "Offline raw-URL benchmark from UCI PhiUSIIL with registrable-domain-disjoint evaluation. Strong HTTPS/path/length collection artifacts prohibit interpreting benchmark calibration or accuracy as arbitrary-URL field performance.",
        "source_url": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
        "doi": "10.1016/j.cose.2023.103545",
        "license": "CC BY 4.0", "license_url": "https://creativecommons.org/licenses/by/4.0/",
        "attribution": "Prasad, A. and Chandra, S. (2024). PhiUSIIL Phishing URL (Website). UCI Machine Learning Repository. DOI:10.1016/j.cose.2023.103545.",
        "permission_basis": "UCI's original record explicitly licenses this dataset under CC BY 4.0; attribution and adaptation notice are retained.",
        "collection_notes": "235,795 publisher-labeled URL/website records. Original label1=legitimate,0=phishing. Only raw URL strings and labels are used. Website source, page content, title, and all supplied numeric/reputation features are excluded; no destination is contacted.",
        "changes": "Selected URL and label only; inverted original labels to common0=legitimate,1=phishing. Remaining feature extraction and grouping happen offline from string only.",
        "raw": {"path": raw.as_posix(), "url": PHIUSIIL["url"], "sha256": sha256(raw), "bytes": raw.stat().st_size},
        "prepared": prepared, "directly_measured_bias": stats,
        "limitations": ["Source collection bias: every legitimate URL is HTTPS and at most58characters, with no non-root path in this snapshot. Benchmark scores can exploit these artifacts.", "A historical corpus label does not establish current host safety or current maliciousness.", "No known collection/campaign timestamps in the released URL subset; enforce registrable-domain disjoint splits and report source bias.", "Exclude all webpage-derived features and corpus-label-derived probability columns to prevent unavailable-feature leakage."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("all", "email", "url"), default="all")
    parser.add_argument("--output", type=Path, default=Path("work/phase3/raw"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    csv.field_size_limit(10_000_000)
    datasets = []
    if args.kind in {"all", "email"}:
        datasets.append(prepare_email(args.output))
    if args.kind in {"all", "url"}:
        datasets.append(prepare_url(args.output))
    manifest = {"acquired_at_utc": datetime.now(timezone.utc).isoformat(), "network_policy": "Only fixed reviewed repository hosts; contained URLs never visited. No dataset code or HTML executed.", "datasets": datasets}
    (args.output / "provenance.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    for item in datasets:
        (args.output / f"{item['task']}-provenance.json").write_text(json.dumps(item, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({x["task"]: x["prepared"] for x in datasets}, indent=2))


if __name__ == "__main__":
    main()
