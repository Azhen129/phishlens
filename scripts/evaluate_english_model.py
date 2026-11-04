"""Read-only evaluation of a frozen English classifier and its deployed route.

No fitting, threshold search, network requests, or application database access.
Main held-out rows come from the frozen split manifest. External rows must be
canonical- and globally campaign-disjoint from the complete prepared main CSV.
Public output retains probabilities and hashes, never email text or subjects.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

import numpy as np
from sklearn.metrics import (
    auc, average_precision_score, brier_score_loss, log_loss,
    precision_recall_curve, roc_auc_score,
)

from backend.analysis import inspect_email
from backend.ml_features import hybrid_features
from backend.ml_runtime import MODEL_ROOT, _load
from backend.ml_training import expected_calibration_error, load_rows, sha256_file


def read_json(path: Path) -> dict:
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Evaluation metadata exceeds its reviewed 64 MiB bound.")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Evaluation metadata must be a JSON object.")
    return value


def wilson(events: int, denominator: int) -> dict:
    """Two-sided Wilson score interval; null when a rate is undefined."""
    result = {"events": int(events), "denominator": int(denominator), "rate": None, "wilson_95": None}
    if not denominator:
        return result
    z = 1.959963984540054
    p, z2 = events / denominator, z * z
    center = (p + z2 / (2 * denominator)) / (1 + z2 / denominator)
    radius = z * math.sqrt(p * (1 - p) / denominator + z2 / (4 * denominator**2)) / (1 + z2 / denominator)
    return {**result, "rate": p, "wilson_95": [max(0., center - radius), min(1., center + radius)]}


def classification_metrics(labels, predictions) -> dict:
    y, predicted = np.asarray(labels, dtype=int), np.asarray(predictions, dtype=int)
    if y.shape != predicted.shape or not set(y.tolist()).issubset({0, 1}) or not set(predicted.tolist()).issubset({0, 1}):
        raise ValueError("Invalid binary evaluation labels or prediction shape.")
    tn = int(((y == 0) & (predicted == 0)).sum())
    fp = int(((y == 0) & (predicted == 1)).sum())
    fn = int(((y == 1) & (predicted == 0)).sum())
    tp = int(((y == 1) & (predicted == 1)).sum())
    return {
        "n": len(y), "class_balance": {"0": tn + fp, "1": fn + tp},
        "accuracy": (tp + tn) / len(y) if len(y) else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "confusion_matrix_order": "Rows true legitimate/phishing; columns predicted legitimate/phishing.",
        "true_negatives": tn, "false_positives": fp, "false_negatives": fn, "true_positives": tp,
        "false_positive_rate": wilson(fp, tn + fp),
        "false_negative_rate": wilson(fn, fn + tp),
        "interval_limitation": "Wilson intervals treat rows as independent Bernoulli observations. Campaign correlation can make these intervals too narrow; these are descriptive dataset intervals, not deployment guarantees.",
    }


def probability_metrics(labels, probabilities, threshold: float) -> dict:
    y, p = np.asarray(labels, dtype=int), np.asarray(probabilities, dtype=float)
    if y.shape != p.shape or not np.all(np.isfinite(p)) or np.any((p < 0) | (p > 1)):
        raise ValueError("Invalid frozen probability output.")
    result = classification_metrics(y, p >= threshold)
    result.update({"threshold": threshold, "roc_auc": None, "average_precision": None, "pr_auc_trapezoid": None,
                   "brier_score": None, "expected_calibration_error": None, "log_loss": None, "calibration_bins": []})
    if len(p):
        result["mean_predicted_phishing_probability"] = float(p.mean())
        result["probability_quantiles"] = dict(zip(("min", "p25", "median", "p75", "max"), map(float, np.quantile(p, [0, .25, .5, .75, 1]))))
    if len(set(y.tolist())) != 2:
        result["rank_and_calibration_metrics_unavailable_reason"] = "Subset lacks both labels. ROC-AUC, PR-AUC/AP and two-class calibration summaries are withheld; confusion counts and defined class-specific rates remain reported."
        return result
    precision, recall, _ = precision_recall_curve(y, p)
    ece, bins = expected_calibration_error(y, p)
    result.update({
        "roc_auc": float(roc_auc_score(y, p)), "average_precision": float(average_precision_score(y, p)),
        "pr_auc_trapezoid": float(auc(recall, precision)), "brier_score": float(brier_score_loss(y, p)),
        "expected_calibration_error": float(ece), "log_loss": float(log_loss(y, p, labels=[0, 1])), "calibration_bins": bins,
    })
    return result


def provenance_hash_records(value, location="root"):
    """Walk bounded trusted provenance; tolerate named external/holdout records."""
    if isinstance(value, dict):
        if isinstance(value.get("sha256"), str):
            yield location, value
        for key, child in value.items():
            yield from provenance_hash_records(child, location + "." + str(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from provenance_hash_records(child, location + f"[{index}]")


def external_identity(csv_path: Path, dataset: dict, explicit: Path | None) -> dict:
    actual = sha256_file(csv_path)
    sources = [("frozen_metrics.dataset", dataset)]
    candidates = [explicit] if explicit else [
        csv_path.with_name(csv_path.stem + "-provenance.json"),
        csv_path.with_name("english-provenance.json"),
        csv_path.with_name("english-train-provenance.json"),
    ]
    for path in candidates:
        if path is not None and path.is_file():
            sources.append((str(path.relative_to(PROJECT)) if path.is_relative_to(PROJECT) else path.name, read_json(path)))
        elif explicit:
            raise ValueError("Explicit external provenance file is missing.")
    matching, mismatching = [], []
    for source, document in sources:
        for location, record in provenance_hash_records(document):
            named = str(record.get("path", record.get("file", record.get("filename", "")))).replace("\\", "/").split("/")[-1]
            # A matching exact hash is useful even if the prepared record has no
            # path. A named record with another hash must fail closed.
            if named == csv_path.name and record["sha256"].lower() != actual:
                mismatching.append(source + ":" + location)
            if record["sha256"].lower() == actual:
                matching.append(source + ":" + location)
    if mismatching:
        raise ValueError("External CSV does not match its named provenance SHA-256 record.")
    if explicit and not matching:
        raise ValueError("Explicit external provenance does not bind this external CSV SHA-256.")
    return {"sha256": actual, "provenance_hash_verified": bool(matching), "matching_records": matching,
            "reason": "External hash matches reviewed provenance." if matching else "No adjacent or embedded external prepared-hash record was available; exact evaluated CSV hash is recorded without claiming provenance verification."}


def verify_frozen_rows(training_csv: Path, directory: Path, bundle: dict):
    metrics, experiment, splits, manifest = [read_json(directory / name) for name in ("metrics.json", "experiment.json", "splits.json", "manifest.json")]
    dataset_hash = sha256_file(training_csv)
    if dataset_hash != metrics.get("dataset_sha256") or dataset_hash != metrics.get("dataset", {}).get("prepared", {}).get("sha256"):
        raise ValueError("Main CSV SHA-256 does not match frozen metrics and approved prepared provenance.")
    if not (manifest["version"] == metrics["version"] == bundle["version"]):
        raise ValueError("Frozen artifact, manifest and metrics versions differ.")
    all_rows, cleaning = load_rows(training_csv, "email", 1_000_000)
    rows = all_rows[:int(experiment["max_rows"])]
    by_identifier = {row.identifier: row for row in rows}
    seen_ids, seen_groups = set(), set()
    for name, records in splits.items():
        ids = [record["sha256"] for record in records]
        groups = {record["group_sha256"] for record in records}
        if len(ids) != len(set(ids)) or seen_ids.intersection(ids) or seen_groups.intersection(groups):
            raise ValueError("Frozen fitting/selection/test partitions overlap by canonical row or campaign group.")
        if len(records) != metrics["partitions"][name]["n"]:
            raise ValueError("Frozen split count differs from training metrics.")
        for record in records:
            row = by_identifier.get(record["sha256"])
            if row is None or row.label != int(record["label"]) or row.source != record["source"]:
                raise ValueError("Frozen split row/label/source differs from the prepared main CSV.")
        seen_ids.update(ids)
        seen_groups.update(groups)
    if seen_ids != set(by_identifier):
        raise ValueError("Frozen partitions do not exactly cover the sampled prepared training rows.")
    return [by_identifier[item["sha256"]] for item in splits["test"]], all_rows, metrics, {
        "training_csv_sha256": dataset_hash, "manifest_sha256": sha256_file(directory / "manifest.json"),
        "metrics_sha256": sha256_file(directory / "metrics.json"), "split_manifest_sha256": sha256_file(directory / "splits.json"),
        "frozen_partition_row_overlap": 0, "frozen_partition_group_overlap": 0,
        "held_out_rowset_sha256": hashlib.sha256("\n".join(sorted(item["sha256"] for item in splits["test"])).encode("ascii")).hexdigest(),
        "main_prepared_cleaning": cleaning,
    }


def check_external_disjoint(main_rows, external_rows) -> dict:
    exact = {row.identifier for row in main_rows} & {row.identifier for row in external_rows}
    main_groups = {row.supplied_group for row in main_rows if row.supplied_group.startswith("global:")}
    external_groups = {row.supplied_group for row in external_rows if row.supplied_group.startswith("global:")}
    missing = sum(not row.supplied_group.startswith("global:") for row in [*main_rows, *external_rows])
    if missing:
        raise ValueError("Every main/external prepared row must have a reviewed global: campaign group to verify global non-overlap.")
    overlap = main_groups & external_groups
    if exact or overlap:
        raise ValueError("External rows overlap the prepared main corpus by canonical text or global campaign group.")
    return {"canonical_row_intersection_count": 0, "global_campaign_group_intersection_count": 0,
            "main_global_group_count": len(main_groups), "external_global_group_count": len(external_groups),
            "group_limitations": "Checks the globally prepared campaign components and shared canonical representation. Does not claim that lexical grouping detects every semantic paraphrase or unknown campaign relation."}


def summarize(records: list[dict], threshold: float) -> dict:
    y = np.asarray([row["dataset_label"] for row in records], dtype=int)
    p = np.asarray([row["raw_ml_phishing_probability"] for row in records], dtype=float)
    accepted = [row for row in records if row["english_ml_applied"]]
    abstained = [row for row in records if not row["english_ml_applied"]]
    fallback = [row for row in records if row["assessment_method"] == "heuristic_fallback"]
    by_label = {}
    for label in (0, 1):
        total = int((y == label).sum())
        allowed = sum(row["dataset_label"] == label for row in accepted)
        by_label[str(label)] = {"total": total, "accepted_english": allowed, "abstained_english": total - allowed,
                               "english_coverage": wilson(allowed, total), "heuristic_fallback": sum(row["dataset_label"] == label for row in fallback)}
    return {
        "n": len(records), "source_counts": dict(sorted(Counter(row["source"] for row in records).items())),
        "raw_frozen_english_model_all_rows": probability_metrics(y, p, threshold),
        "language_applicability": {
            "accepted_english": len(accepted), "abstained_english": len(abstained), "english_coverage": wilson(len(accepted), len(records)),
            "by_dataset_label": by_label, "routing_status_counts": dict(Counter(row["language_routing_status"] for row in records)),
            "detected_language_counts": dict(Counter(row["detected_language"] for row in records)),
            "active_classifier_counts": dict(Counter(row["active_classifier"] or "none" for row in records)),
            "abstained_english_label_counts": {str(label): sum(row["dataset_label"] == label for row in abstained) for label in (0, 1)},
            "abstained_english_source_counts": dict(Counter(row["source"] for row in abstained)),
            "heuristic_fallback_label_counts": {str(label): sum(row["dataset_label"] == label for row in fallback) for label in (0, 1)},
            "heuristic_fallback_source_counts": dict(Counter(row["source"] for row in fallback)),
        },
        "deployed_accepted_english_model": probability_metrics(
            [row["dataset_label"] for row in accepted], [row["runtime_ml_phishing_probability"] for row in accepted], threshold),
        "end_to_end_final_binary_assessment": {
            **classification_metrics(y, [row["final_risk"] == "High" for row in records]),
            "positive_policy": "High final risk is counted positive; Medium/Low are counted negative only for this operational summary. Abstentions are reported separately and never silently counted correct. Rule points are not probabilities.",
            "assessment_method_counts": dict(Counter(row["assessment_method"] for row in records)),
            "risk_counts_by_dataset_label": {str(label): dict(Counter(row["final_risk"] for row in records if row["dataset_label"] == label)) for label in (0, 1)},
        },
    }


def evaluate_rows(rows, bundle: dict, name: str) -> tuple[dict, np.ndarray]:
    if not rows:
        raise ValueError(f"{name} has no evaluable rows.")
    probabilities = np.asarray(bundle["model"].predict_proba([row.text for row in rows])[:, 1], dtype=float)
    records, points = [], []
    for index, (row, probability) in enumerate(zip(rows, probabilities)):
        scan = inspect_email(row.text)
        ml, final = scan["ml"], scan["assessment"]
        points.append(scan["score"])
        records.append({
            "sha256": row.identifier, "source": row.source, "dataset_label": row.label,
            "raw_ml_phishing_probability": float(probability),
            "english_ml_applied": bool(ml.get("available") and ml.get("model_key") == "email_en"),
            "language_routing_status": ml.get("language_routing_status", "unrecorded"),
            "detected_language": ml.get("detected_language", "und"),
            "active_classifier": ml.get("model_key") if ml.get("available") else None,
            "runtime_ml_phishing_probability": ml.get("phishing_probability"),
            "runtime_assessment_probability": final.get("phishing_probability"),
            "assessment_method": final["method"], "final_risk": final["risk"],
            "heuristic_rule_points": scan["score"],
        })
        if (index + 1) % 250 == 0:
            print(f"{name}: audited {index + 1}/{len(rows)} real rows", flush=True)
    threshold = float(bundle["threshold"])
    result = summarize(records, threshold)
    result["per_source"] = {source: summarize([record for record in records if record["source"] == source], threshold)
                            for source in sorted({row.source for row in rows})}
    result["prediction_records"] = records
    result["raw_vs_runtime_note"] = "Raw metrics reproduce the frozen original CSV input. Deployed conditional metrics use the actual email parser, language route and inference path. Both probabilities are retained because parser transformations can change input."
    if bundle["metadata"].get("assessment_mode", "ml") == "hybrid":
        selected_p = bundle["hybrid_model"].predict_proba(hybrid_features(probabilities, np.asarray(points)))[:, 1]
    else:
        selected_p = probabilities
    return result, np.asarray(selected_p)


def spanish_preservation_smoke() -> dict:
    path = PROJECT / "fixtures/spanish-account-review.eml"
    text = path.read_text(encoding="utf-8")
    scan, rules = inspect_email(text), inspect_email(text, use_ml=False)
    if not scan["ml"].get("available") or scan["ml"].get("model_key") != "email" or scan["score"] != rules["score"] or scan["evidence"] != rules["evidence"]:
        raise ValueError("Existing Spanish route or separate heuristic evidence failed its preservation smoke check.")
    return {"fixture_sha256": sha256_file(path), "model_key": scan["ml"]["model_key"], "model_version": scan["ml"]["model_version"],
            "supported_languages": scan["ml"]["supported_languages"], "heuristic_evidence_preserved": True,
            "scope": "One routing/preservation fixture only. No Spanish accuracy or generalization estimate is claimed."}


def audit(args) -> dict:
    directory = MODEL_ROOT / "email_en"
    bundle, reason = _load("email_en")
    if bundle is None:
        raise ValueError("Validated frozen English model unavailable: " + reason)
    watched = [directory / name for name in ("model.joblib", "manifest.json", "metrics.json", "splits.json", "experiment.json")]
    watched += [MODEL_ROOT / key / "model.joblib" for key in ("email", "url")]
    watched += [PROJECT / "backend/ml_features.py", PROJECT / "backend/ml_runtime.py", args.csv, args.training_csv]
    before = {str(path): sha256_file(path) for path in watched}
    held_out, main_rows, frozen_metrics, identity = verify_frozen_rows(args.training_csv, directory, bundle)
    external_rows, external_cleaning = load_rows(args.csv, "email", 1_000_000)
    external_provenance = external_identity(args.csv, frozen_metrics["dataset"], args.external_provenance)
    separation = check_external_disjoint(main_rows, external_rows)
    main, selected_main_p = evaluate_rows(held_out, bundle, "frozen main test")
    external, _ = evaluate_rows(external_rows, bundle, "external fixed holdout")
    selected_threshold = float(bundle["hybrid_threshold"] if bundle["metadata"].get("assessment_mode") == "hybrid" else bundle["threshold"])
    reproduction = probability_metrics([row.label for row in held_out], selected_main_p, selected_threshold)
    original = frozen_metrics["selected_test"]
    for key in ("accuracy", "f1", "brier_score", "roc_auc"):
        if abs(reproduction[key] - original[key]) > 1e-10:
            raise ValueError(f"Frozen main held-out {key} was not reproduced.")
    if reproduction["confusion_matrix"] != original["confusion_matrix"]:
        raise ValueError("Frozen held-out confusion matrix was not reproduced.")
    spanish = spanish_preservation_smoke()
    after = {str(path): sha256_file(path) for path in watched}
    if before != after:
        raise ValueError("An artifact, feature/runtime module or prepared dataset changed during evaluation; repeat after all inputs are frozen.")
    return {
        "format_version": 1, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_key": "email_en", "model_version": bundle["version"], "artifact_sha256": before[str(directory / "model.joblib")],
        "locked_ml_threshold": float(bundle["threshold"]), "assessment_mode": bundle["metadata"].get("assessment_mode", "ml"),
        "evaluation_policy": "Read-only post-selection audit. No model/calibrator fitting, threshold tuning, candidate selection or repartitioning. External data were never fitted or used to select this frozen artifact/threshold. Raw corpus labels are not invented verdicts.",
        "identity_and_separation": {**identity, "external": external_provenance, **separation, "external_cleaning": external_cleaning,
                                    "frozen_held_out_reproduction_passed": True, "all_watched_hashes_unchanged": True,
                                    "runtime_code_sha256": before[str(PROJECT / "backend/ml_runtime.py")],
                                    "evaluation_script_sha256": sha256_file(Path(__file__))},
        "frozen_main_test": main, "external_holdout": external, "spanish_preservation_smoke": spanish,
        "limitations": [
            "Source/campaign distributions, dataset annotation, collection era and class prevalence limit generalization. External evaluation is not deployment prevalence calibration.",
            "Conditional English model metrics must be interpreted with both label-specific coverage rates, every abstention count and alternate-language routing counts.",
            "Language identification is imperfect and uses bounded runtime text. Identifier scores are applicability gates, not calibrated language confidence.",
            "Wilson intervals do not account for within-campaign correlation. One-class source subsets lack rank and two-class calibration evidence.",
            "Source labels and row hashes are retained for auditability. Raw emails, subjects, addresses and model feature tokens are excluded from this public JSON.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=PROJECT / "work/phase4/raw/english-external.csv")
    parser.add_argument("--training-csv", type=Path, default=PROJECT / "work/phase4/raw/english-train.csv")
    parser.add_argument("--external-provenance", type=Path)
    parser.add_argument("--out", type=Path, default=PROJECT / "docs/ml/phase4/external-evaluation.json")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Refusing to overwrite an existing evaluation; review it and choose a new --out path.")
    try:
        result = audit(args)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, ensure_ascii=True, allow_nan=False)
            stream.write("\n")
        print(json.dumps({"output": str(args.out), "model_version": result["model_version"],
                          "main_test_n": result["frozen_main_test"]["n"], "external_n": result["external_holdout"]["n"],
                          "external_metrics": result["external_holdout"]["raw_frozen_english_model_all_rows"],
                          "external_coverage": result["external_holdout"]["language_applicability"]}, indent=2, allow_nan=False), flush=True)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f"Frozen English evaluation failed: {error}\n")


if __name__ == "__main__":
    main()
