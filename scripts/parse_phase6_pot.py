"""Reconstruct private Phase 6 parser inputs from pinned EMLs and reviewed labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.acquire_english_dataset import body_text

WORK = ROOT / "work" / "phase6"
EVIDENCE = ROOT / "docs" / "ml" / "phase6"
LABEL_FIELDS = {"index", "raw_sha256", "language", "category", "fully_reviewed"}
LANGUAGES = {"en", "nonen", "mixed", "uncertain"}
CATEGORIES = {
    "strict_phishing",
    "generic_spam",
    "financial_scam",
    "legitimate_or_unknown",
    "unreadable",
}


def replay(output: Path) -> None:
    output = output.resolve()
    if not output.is_relative_to((ROOT / "work").resolve()):
        raise ValueError("Private parser output must stay under ignored work/ storage.")

    acquired = json.loads((WORK / "raw" / "acquisition-v2.json").read_text(encoding="utf-8"))
    pinned = json.loads((EVIDENCE / "acquisition-v2.json").read_text(encoding="utf-8"))
    if acquired != pinned:
        raise ValueError("Acquired snapshot metadata does not match the frozen Phase 6 record.")

    annotation_bytes = (EVIDENCE / "pot-annotation-manifest.json").read_bytes()
    annotations = json.loads(annotation_bytes)
    files = pinned["pot_files"]
    if len(annotations) != 400 or len(files) != 400:
        raise ValueError("The reviewed Phishing Pot sample must contain 400 files and annotations.")

    rows = []
    pot_dir = (WORK / "raw" / "pot").resolve()
    for index, (source, annotation) in enumerate(zip(files, annotations, strict=True)):
        if (
            set(annotation) != LABEL_FIELDS
            or type(annotation["index"]) is not int
            or annotation["index"] != index
            or annotation["raw_sha256"] != source["sha256"]
            or annotation["language"] not in LANGUAGES
            or annotation["category"] not in CATEGORIES
            or type(annotation["fully_reviewed"]) is not bool
        ):
            raise ValueError(f"Reviewed annotation metadata differs at sample index {index}.")

        filename = Path(source["path"]).name
        path = (pot_dir / filename).resolve()
        if path.parent != pot_dir or not 0 < source["bytes"] <= 1_000_000:
            raise ValueError(f"Invalid source path or size at sample index {index}.")
        if path.stat().st_size != source["bytes"]:
            raise ValueError(f"Source size mismatch at sample index {index}.")
        with path.open("rb") as stream:
            data = stream.read(1_000_001)
        if len(data) != source["bytes"] or hashlib.sha256(data).hexdigest() != source["sha256"]:
            raise ValueError(f"Source hash mismatch at sample index {index}.")

        message = BytesParser(policy=policy.default).parsebytes(data)
        subject = str(message.get("Subject", ""))
        rows.append({
            "index": index,
            "file": filename,
            "raw_sha256": source["sha256"],
            "text": "Subject: " + subject + "\n\n" + body_text(message),
            "label": None,
            "source": "PhishingPot",
            "row_id": source["path"],
            "language": "unadjudicated",
        })

    outputs = {
        "pot-parsed-private.json": json.dumps(rows, ensure_ascii=False).encode("utf-8"),
        "pot-annotations-adjudicated-private.json": annotation_bytes,
    }
    output.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        path = output / name
        if path.is_symlink() or (path.exists() and path.read_bytes() != data):
            raise FileExistsError(f"Refusing to replace existing {name}. Use a fresh replay copy.")
    for name, data in outputs.items():
        path = output / name
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(data)
    print(f"Verified {len(rows)} pinned EMLs and reconstructed private parser inputs.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=WORK)
    replay(parser.parse_args().output_dir)


if __name__ == "__main__":
    main()
