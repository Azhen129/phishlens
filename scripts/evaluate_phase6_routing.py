"""Compare format-cleanup routing on previously observed development rows only.

No learned model is fitted or scored, and no Phase 6 final corpus is opened.
Original Phase 5 route records are hash-bound; private email text is not output.
"""
import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from threadpoolctl import threadpool_limits
from backend.analysis import inspect_email
from backend.language_routing_v3 import ROUTING_VERSION, route_email_language
from backend.ml_runtime import _classify_language
from backend.ml_training import load_rows, sha256_file


def frozen_rows(key, path):
    directory = ROOT / "backend/models" / key
    metrics = json.loads((directory / "metrics.json").read_text())
    assert sha256_file(path) == metrics["dataset_sha256"]
    rows, _ = load_rows(path, "email", 100000)
    indexed = {row.identifier: row for row in rows}
    split = json.loads((directory / "splits.json").read_text())["test"]
    result = [indexed[record["sha256"]] for record in split]
    assert all(row.label == record["label"] and row.source == record["source"] for row, record in zip(result, split))
    return result


def summary(records, expected):
    result = {"n": len(records), "corpus_expected_language": expected}
    for policy in ("phase5", "phase6"):
        accepted = [r for r in records if r[policy]["language_routing_status"] == "supported" and r[policy]["detected_language"] == expected]
        result[policy] = {
            "expected_language_accepted": len(accepted),
            "expected_language_coverage": len(accepted) / len(records),
            "statuses": dict(Counter(r[policy]["language_routing_status"] for r in records)),
            "detected_languages": dict(Counter(r[policy]["detected_language"] for r in records)),
            "either_supported": sum(r[policy]["language_routing_status"] == "supported" for r in records),
            "by_label": {str(label): {"n": sum(r["label"] == label for r in records), "accepted": sum(r["label"] == label for r in accepted)} for label in (0, 1)},
        }
    regressions = [r for r in records if r["phase5"]["language_routing_status"] == "supported" and r["phase5"]["detected_language"] == expected and (r["phase6"]["language_routing_status"] != "supported" or r["phase6"]["detected_language"] != expected)]
    result["previously_expected_supported_lost"] = len(regressions)
    result["lost_hashes"] = [r["sha256"] for r in regressions]
    result["recovered_expected_routes"] = sum(r["phase6"]["language_routing_status"] == "supported" and r["phase6"]["detected_language"] == expected and (r["phase5"]["language_routing_status"] != "supported" or r["phase5"]["detected_language"] != expected) for r in records)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "docs/ml/phase6/routing-development.json")
    args = parser.parse_args()
    if args.out.exists():
        raise ValueError("Refusing to overwrite a completed routing report; use a new --out path.")
    old_path = ROOT / "docs/ml/phase5/routing-development.json"
    old = json.loads(old_path.read_text())
    assert old["router_sha256"] == sha256_file(ROOT / "backend/language_routing_v2.py")
    datasets = [
        ("english_main", frozen_rows("email_en", ROOT / "work/phase4/raw/english-train.csv"), "en"),
        ("english_old_external", load_rows(ROOT / "work/phase4/raw/english-external.csv", "email", 100000)[0], "en"),
        ("spanish_old_test", frozen_rows("email", ROOT / "work/phase3/raw/email.csv"), "es"),
    ]
    watched_paths = [ROOT / p for p in ("backend/language_routing_v2.py", "backend/language_routing_v3.py", "backend/text_normalization_v6.py", "backend/analysis.py", "backend/ml_features.py", "backend/ml_runtime.py")]
    watched_paths += [p for p in (ROOT / "backend/models").rglob("*") if p.is_file()]
    watched = {p.relative_to(ROOT).as_posix(): sha256_file(p) for p in watched_paths}
    result = {
        "protocol": ROUTING_VERSION,
        "role": "Previously observed Phase 4 English and original Spanish test rows only. Language applicability diagnostic, not classifier accuracy, new independent evaluation or per-row language truth.",
        "comparison_report_sha256": sha256_file(old_path),
        "code_and_model_sha256": watched,
        "raw_message_text_excluded": True,
        "new_final_data_read": False,
        "datasets": {},
    }
    with threadpool_limits(limits=1):
        for name, rows, expected in datasets:
            original = {r["sha256"]: r for r in old["datasets"][name]["parsed_api"]["records"]}
            assert len(original) == len(rows)
            records = []
            for index, row in enumerate(rows):
                archived = original[row.identifier]
                assert archived["label"] == row.label and archived["source"] == row.source
                scan = inspect_email(row.text, use_ml=False)
                text = "Subject: " + scan["subject"] + "\n\n" + scan["email"]["body"]
                route = route_email_language(text, _classify_language)
                records.append({"sha256": row.identifier, "source": row.source, "label": row.label, "phase5": archived["phase5"], "phase6": route})
                if (index + 1) % 250 == 0:
                    print(name, index + 1, flush=True)
            result["datasets"][name] = {"summary": summary(records, expected), "records": records}
    assert all(sha256_file(ROOT / name) == digest for name, digest in watched.items())
    result["all_watched_files_unchanged"] = True
    result["spanish_nonregression_passed"] = result["datasets"]["spanish_old_test"]["summary"]["previously_expected_supported_lost"] == 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({name: data["summary"] for name, data in result["datasets"].items()}, indent=2))


if __name__ == "__main__":
    main()
