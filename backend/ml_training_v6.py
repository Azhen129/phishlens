"""Three frozen source-controlled English experiments; final data is never read.

The command accepts only the approved development CSV and provenance. It keeps
all original artifacts and writes unvalidated versions plus public hash-only
memberships. Any independent admission/activation happens in a separate audit.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from scipy.special import expit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC
from threadpoolctl import threadpool_limits

from .ml_features import FEATURE_VERSION, TrainedClassifier
from .ml_training import evaluate, expected_calibration_error, load_provenance, sha256_file, verify_dataset_identity
from .text_normalization_v6 import MAX_CHARACTERS, NORMALIZATION_VERSION, normalize_english_text

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261103
BOOTSTRAP_REPLICATES = 400
PIPELINE_VERSION = "email-source-text-v6"
CANDIDATES = (
    ("word_lr_unweighted", "word", "lr", None),
    ("union_svm_unweighted", "union", "svm", None),
    ("union_svm_balanced", "union", "svm", "balanced"),
)


@dataclass(frozen=True)
class DevelopmentRow:
    text: str
    label: int
    source: str
    group: str
    row_id: str
    role: str


def json_write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")


def load_development(path: Path) -> list[DevelopmentRow]:
    """Validate prepared role/group identities without silently changing rows."""
    csv.field_size_limit(2 * 1024 * 1024)
    rows, identifiers, group_roles, content_groups, content_labels = [], set(), {}, {}, {}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"text", "label", "source", "group", "row_id", "date", "language", "role"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Development CSV lacks the reviewed role/group schema.")
        for item in reader:
            if len(rows) >= 60_000:
                raise ValueError("Development CSV exceeds the reviewed 60,000-row bound.")
            if item["label"] not in {"0", "1"} or item["role"] not in {"train_pool", "validation"}:
                raise ValueError("Unexpected development label or role.")
            if item["language"] != "en":
                raise ValueError("Development rows must have declared English applicability.")
            text, source, group, identifier = item["text"], item["source"], item["group"], item["row_id"]
            if len(text) > MAX_CHARACTERS or len(normalize_english_text(text)) < 5:
                raise ValueError("Development text violates the bounded prepared representation.")
            if not source or len(source) > 100 or any(c in source for c in "\r\n"):
                raise ValueError("Invalid source identity.")
            if not re.fullmatch(r"phase6:[a-f0-9]{64}", group) or not re.fullmatch(r"[a-f0-9]{64}", identifier):
                raise ValueError("Group and row identities must be prepared hashes.")
            canonical = hashlib.sha256(normalize_english_text(text).encode()).hexdigest()
            if canonical != identifier or identifier in identifiers:
                raise ValueError("Development canonical identity mismatch or duplicate row.")
            if group in group_roles and group_roles[group] != item["role"]:
                raise ValueError("A prepared campaign group crosses validation and fitting roles.")
            if canonical in content_groups and content_groups[canonical] != group:
                raise ValueError("Identical content was assigned different campaign groups.")
            label = int(item["label"])
            if canonical in content_labels and content_labels[canonical] != label:
                raise ValueError("Conflicting canonical labels were not quarantined.")
            identifiers.add(identifier)
            group_roles[group] = item["role"]
            content_groups[canonical], content_labels[canonical] = group, label
            rows.append(DevelopmentRow(text, label, source, group, identifier, item["role"]))
    if not rows or {r.role for r in rows} != {"train_pool", "validation"}:
        raise ValueError("Both prepared development roles are required.")
    return sorted(rows, key=lambda r: r.row_id)


def partition_roles(rows: list[DevelopmentRow]) -> dict[str, np.ndarray]:
    labels = np.asarray([row.label for row in rows])
    groups = np.asarray([row.group for row in rows])
    pool = np.asarray([i for i, row in enumerate(rows) if row.role == "train_pool"])
    validation = np.asarray([i for i, row in enumerate(rows) if row.role == "validation"])
    for label in (0, 1):
        if len(set(groups[pool][labels[pool] == label])) < 5:
            raise ValueError("Five-fold development needs at least five groups containing each class.")
    folds = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED).split(np.zeros(len(pool)), labels[pool], groups[pool]))
    parts = {
        "train": np.sort(np.concatenate([pool[folds[i][1]] for i in (2, 3, 4)])),
        "calibration": np.sort(pool[folds[1][1]]),
        "test": np.sort(pool[folds[0][1]]),
        "validation": np.sort(validation),
    }
    seen = set()
    for name, indexes in parts.items():
        if set(labels[indexes]) != {0, 1}:
            raise ValueError(f"Prepared {name} partition lacks a class.")
        current = set(groups[indexes])
        if current & seen:
            raise ValueError("Campaign membership intersects training/calibration/test/validation.")
        seen.update(current)
    assert sum(map(len, parts.values())) == len(rows)
    return parts


def wilson_interval(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0., center - radius), min(1., center + radius)]


def _operating_from_counts(tn, fp, fn, tp) -> dict:
    total = tn + fp + fn + tp
    return {
        "accuracy": (tn + tp) / total if total else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "false_positive_rate": fp / (tn + fp) if tn + fp else None,
        "false_negative_rate": fn / (tp + fn) if tp + fn else None,
    }


def group_bootstrap_intervals(labels, predicted, groups, sources, replicates=BOOTSTRAP_REPLICATES) -> dict:
    """Resample whole groups within their complete source-membership strata."""
    labels, predicted = np.asarray(labels), np.asarray(predicted)
    members = defaultdict(list)
    for i, group in enumerate(groups):
        members[str(group)].append(i)
    counts, strata = [], defaultdict(list)
    for index, group in enumerate(sorted(members)):
        ix = np.asarray(members[group])
        y, pred = labels[ix], predicted[ix]
        counts.append([int(((y == 0) & (pred == 0)).sum()), int(((y == 0) & (pred == 1)).sum()), int(((y == 1) & (pred == 0)).sum()), int(((y == 1) & (pred == 1)).sum())])
        # A cross-source campaign stays intact; it belongs to the stratum of
        # its entire source set instead of being split by message source.
        strata[tuple(sorted({str(sources[i]) for i in ix}))].append(index)
    counts = np.asarray(counts, dtype=np.int64)
    rng = np.random.default_rng(SEED)
    collected = defaultdict(list)
    for _ in range(replicates):
        sample = np.zeros(4, dtype=np.int64)
        for indexes in strata.values():
            sample += counts[rng.choice(indexes, size=len(indexes), replace=True)].sum(axis=0)
        for key, value in _operating_from_counts(*map(int, sample)).items():
            if value is not None:
                collected[key].append(value)
    return {
        "method": "Source-set-stratified whole-campaign bootstrap; percentile 95% intervals, curated-source diagnostic only.",
        "seed": SEED,
        "replicates": replicates,
        "groups": len(members),
        "source_set_strata": len(strata),
        "intervals": {key: [float(v) for v in np.quantile(values, [.025, .975])] if values else None for key, values in collected.items()},
    }


def metric_report(labels, scores, threshold, *, groups=None, sources=None, bootstrap=False, calibrated=True) -> dict:
    y, p = np.asarray(labels, dtype=int), np.asarray(scores, dtype=float)
    if not len(y) or len(y) != len(p) or not np.isfinite(p).all() or not ((p >= 0) & (p <= 1)).all():
        raise ValueError("Metrics require nonempty matching finite unit-interval scores.")
    pred = p >= threshold
    tn, fp = int(((y == 0) & ~pred).sum()), int(((y == 0) & pred).sum())
    fn, tp = int(((y == 1) & ~pred).sum()), int(((y == 1) & pred).sum())
    if set(y) == {0, 1}:
        result = evaluate(y, p, threshold, calibrated=calibrated)
    else:
        ece, bins = expected_calibration_error(y, p)
        result = {"n": len(y), "class_balance": {"0": tn + fp, "1": fn + tp}, "threshold": float(threshold), "confusion_matrix": [[tn, fp], [fn, tp]], "false_positives": fp, "false_negatives": fn, "roc_auc": None, "average_precision": None, "pr_auc_trapezoid": None, "brier_score": float(brier_score_loss(y, p)) if calibrated else None, "log_loss": float(log_loss(y, p, labels=[0, 1])) if calibrated else None, "expected_calibration_error": float(ece) if calibrated else None, "calibration_bins": bins if calibrated else [], "curves": {}}
    result.update(_operating_from_counts(tn, fp, fn, tp))
    result["wilson_95"] = {
        "accuracy": wilson_interval(tn + tp, len(y)),
        "precision": wilson_interval(tp, tp + fp),
        "recall": wilson_interval(tp, tp + fn),
        "false_positive_rate": wilson_interval(fp, tn + fp),
        "false_negative_rate": wilson_interval(fn, tp + fn),
    }
    if bootstrap:
        if groups is None or sources is None or len(groups) != len(y) or len(sources) != len(y):
            raise ValueError("Campaign bootstrap requires matching group/source membership.")
        result["group_bootstrap_95"] = group_bootstrap_intervals(y, pred, groups, sources)
    return result


def constrained_threshold(labels, scores, sources) -> dict:
    """Optimize validation recall under pooled and adequately sized source bounds."""
    y, p, source = np.asarray(labels, dtype=int), np.asarray(scores, dtype=float), np.asarray(sources)
    if len(y) != len(p) or len(y) != len(source) or set(y) != {0, 1} or not np.isfinite(p).all() or not ((p >= 0) & (p <= 1)).all():
        raise ValueError("Threshold selection needs matching validation sources, both labels and valid scores.")
    order = np.argsort(-p, kind="stable")
    ordered_p, ordered_y, ordered_source = p[order], y[order], source[order]
    positive = np.r_[0, np.cumsum(ordered_y == 1)]
    negative = np.r_[0, np.cumsum(ordered_y == 0)]
    ham, phish = int((y == 0).sum()), int((y == 1).sum())
    sources_ham = {}
    for name in sorted(set(source[y == 0])):
        mask = (ordered_y == 0) & (ordered_source == name)
        sources_ham[str(name)] = (int(mask.sum()), np.r_[0, np.cumsum(mask)])
    inside = p[(p > 0) & (p < 1)]
    above = np.nextafter(p[p < 1], np.inf)
    candidates = np.unique(np.r_[inside, above[(above > 0) & (above < 1)], .5, np.nextafter(1., 0.)])
    choices = []
    for threshold in candidates:
        selected = int(np.searchsorted(-ordered_p, -threshold, side="right"))
        fp, tp = int(negative[selected]), int(positive[selected])
        if fp / ham > .01 or wilson_interval(fp, ham)[1] > .02:
            continue
        if any(n >= 200 and (int(prefix[selected]) / n > .01 or wilson_interval(int(prefix[selected]), n)[1] > .02) for n, prefix in sources_ham.values()):
            continue
        choices.append((tp / phish, -fp, tp / max(tp + fp, 1), -abs(float(threshold) - .5), float(threshold)))
    threshold = max(choices)[-1] if choices else float(np.nextafter(1., 0.))
    pred = p >= threshold
    fp, tp = int(((y == 0) & pred).sum()), int(((y == 1) & pred).sum())
    per_source = {}
    for name in sorted(sources_ham):
        mask = (source == name) & (y == 0)
        n, count = int(mask.sum()), int((pred & mask).sum())
        interval = wilson_interval(count, n)
        per_source[name] = {"benign_n": n, "false_positives": count, "false_positive_rate": count / n, "wilson_95": interval, "constraint_required": n >= 200, "constraint_passed": count / n <= .01 and interval[1] <= .02 if n >= 200 else None, "scope": "Prespecified source bound" if n >= 200 else "Insufficient source denominator for the prespecified bound; no safety claim"}
    return {"threshold": threshold, "feasible": bool(choices), "validation_recall": tp / phish, "pooled_false_positives": fp, "pooled_benign_n": ham, "pooled_false_positive_rate": fp / ham, "pooled_wilson_95": wilson_interval(fp, ham), "per_benign_source": per_source, "selection_rule": "Validation recall, fewer pooled FP, precision, proximity to 0.5; both pooled bounds and source bounds for benign n>=200. Final data never read."}


def build_estimator(kind, algorithm, weight):
    word = TfidfVectorizer(preprocessor=normalize_english_text, ngram_range=(1, 2), min_df=3, max_features=40_000, sublinear_tf=True, dtype=np.float64)
    if kind == "union":
        characters = TfidfVectorizer(preprocessor=normalize_english_text, analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=40_000, sublinear_tf=True, dtype=np.float64)
        features = FeatureUnion([("word", word), ("characters", characters)])
    else:
        features = word
    estimator = LogisticRegression(C=.25, class_weight=weight, solver="liblinear", max_iter=2000, random_state=SEED) if algorithm == "lr" else LinearSVC(C=.25, class_weight=weight, max_iter=15_000, tol=.001, random_state=SEED)
    return Pipeline([("features", features), ("classifier", estimator)])


def _compact(metrics):
    return {key: value for key, value in metrics.items() if key not in {"curves", "calibration_bins"}}


def _public_provenance(provenance):
    # Paths (including historical absolute workstation paths) are not copied.
    return {key: provenance[key] for key in ("source_url", "license", "permission_basis", "collection_notes", "validation_scope", "supported_languages") if key in provenance}


def train(args):
    provenance = load_provenance(args.provenance)
    dataset_sha = verify_dataset_identity(args.csv, provenance, "email")
    rows = load_development(args.csv)
    parts = partition_roles(rows)
    y = np.asarray([r.label for r in rows])
    text = np.asarray([r.text for r in rows], dtype=object)
    groups, sources = np.asarray([r.group for r in rows]), np.asarray([r.source for r in rows])
    code = {name: sha256_file(ROOT / name) for name in ("backend/ml_features.py", "backend/ml_training.py", "backend/text_normalization_v6.py", "backend/ml_training_v6.py", "docs/ml/phase6/PROTOCOL.md")}
    identity = {"dataset_sha256": dataset_sha, "provenance_sha256": sha256_file(args.provenance), "code_sha256": code, "candidates": CANDIDATES, "seed": SEED, "fold_roles": {"test": [0], "calibration": [1], "train": [2, 3, 4], "validation": "prepared-source-held-out"}, "sklearn": sklearn.__version__, "numpy": np.__version__}
    run_hash = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:12]
    scratch = args.checkpoint_root / ("run-" + run_hash)
    versions = {name: PIPELINE_VERSION + "-" + hashlib.sha256(json.dumps({**identity, "candidate": name}, sort_keys=True).encode()).hexdigest()[:12] for name, *_ in CANDIDATES}
    selection_path = args.report_root / "selection.json"
    if scratch.exists() or selection_path.exists() or any((args.model_root / version).exists() for version in versions.values()):
        raise ValueError("Refusing to overwrite existing checkpoints, model versions or selection. Reproduce in an isolated copy.")
    scratch.mkdir(parents=True)
    json_write(scratch / "experiment.json", identity)
    splits = {name: [{"sha256": rows[i].row_id, "group_sha256": rows[i].group, "label": rows[i].label, "source": rows[i].source} for i in indexes] for name, indexes in parts.items()}
    partition_summary = {name: {"n": len(indexes), "class_balance": dict(Counter(str(y[i]) for i in indexes)), "sources": dict(Counter(rows[i].source for i in indexes)), "groups": len(set(groups[indexes]))} for name, indexes in parts.items()}
    candidates = {}
    for name, kind, algorithm, weight in CANDIDATES:
        print(f"Fitting {name} on {len(parts['train'])} rows; validation source controls fixed.", flush=True)
        estimator = build_estimator(kind, algorithm, weight).fit(text[parts["train"]], y[parts["train"]])
        calibration = parts["calibration"]
        calibrator = LogisticRegression(C=1., solver="lbfgs", max_iter=2000, random_state=SEED).fit(estimator.decision_function(text[calibration]).reshape(-1, 1), y[calibration])
        classifier = TrainedClassifier(estimator, calibrator)
        scores = classifier.predict_proba(text)[:, 1]
        validation = parts["validation"]
        threshold_choice = constrained_threshold(y[validation], scores[validation], sources[validation])
        threshold = threshold_choice["threshold"]
        reports = {}
        for role in ("validation", "test", "calibration"):
            ix = parts[role]
            reports[role] = metric_report(y[ix], scores[ix], threshold, groups=groups[ix], sources=sources[ix], bootstrap=True)
        per_source = {}
        for role in ("validation", "test"):
            per_source[role] = {}
            for source in sorted(set(sources[parts[role]])):
                ix = parts[role][sources[parts[role]] == source]
                per_source[role][str(source)] = metric_report(y[ix], scores[ix], threshold)
        raw_test = expit(estimator.decision_function(text[parts["test"]]))
        version = versions[name]
        metadata = {"kind": "email", "version": version, "feature_version": FEATURE_VERSION, "feature_code_sha256": code["backend/ml_features.py"], "additional_code_sha256": {"text_normalization_v6.py": code["backend/text_normalization_v6.py"]}, "pipeline_version": PIPELINE_VERSION, "normalization_version": NORMALIZATION_VERSION, "calibrated": True, "validation_passed": threshold_choice["feasible"], "assessment_mode": "ml", "selected_candidate": name, "supported_languages": ["en"], "probability_validated_for_deployment": False, "probability_scope": "Archive decision score; representative deployment calibration not established.", "prediction_warning": "Experimental archive decision score, not confidence or a verified inbox probability. Independent admission pending; a legitimate prediction never verifies safety.", "validation_scope": provenance["validation_scope"], "dataset_source": provenance["source_url"], "dataset_license": provenance["license"], "limitations": ["Source/era/campaign and label/prevalence shift remain; benchmark calibration is not deployment probability.", "No live authentication, reputation, destination fetching or attachment execution is performed.", "Bounded lexical grouping does not prove all semantic campaigns are independent."]}
        bundle = {"format_version": 1, "kind": "email", "version": version, "model": classifier, "threshold": threshold, "hybrid_model": None, "metadata": metadata}
        checkpoint = scratch / (name + ".joblib")
        joblib.dump(bundle, checkpoint, compress=3)
        output = args.model_root / version
        output.mkdir(parents=True)
        (output / "model.joblib").write_bytes(checkpoint.read_bytes())
        artifact_sha = sha256_file(output / "model.joblib")
        metrics = {"format_version": 1, "kind": "email", "version": version, "candidate": name, "created_at": datetime.now(timezone.utc).isoformat(), "dataset": _public_provenance(provenance), "dataset_sha256": dataset_sha, "provenance_sha256": identity["provenance_sha256"], "group_intersection_count": 0, "partitions": partition_summary, "threshold_selection": threshold_choice, "validation": reports["validation"], "selected_test": reports["test"], "calibration": reports["calibration"], "per_source": per_source, "calibration_before_test": metric_report(y[parts["test"]], raw_test, .5), "calibration_before_scope": "Native Logistic Regression score at its default 0.5 operating point; selection uses calibrated scores only" if algorithm == "lr" else "Arbitrary sigmoid of SVM margin at 0.5, uncalibrated diagnostic only; selection uses calibrated scores only", "calibration_slope": float(calibrator.coef_[0, 0]), "calibration_intercept": float(calibrator.intercept_[0]), "deployment_gate": {"passed": threshold_choice["feasible"], "scope": "Archived validation FPR constraints only; independent admission pending. Manifest remains unvalidated."}, "code_sha256": code, "independent_evaluation_pending": True, "final_data_read": False}
        json_write(output / "metrics.json", metrics)
        json_write(output / "experiment.json", {**identity, "candidate": name})
        json_write(output / "splits.json", splits)
        json_write(output / "manifest.json", {"format_version": 1, "kind": "email", "version": version, "artifact": "model.joblib", "metrics_file": "metrics.json", "sha256": artifact_sha, "sklearn_version": sklearn.__version__, "validated": False, "metadata": metadata})
        relative = output.resolve().relative_to(ROOT).as_posix() if output.resolve().is_relative_to(ROOT) else output.name
        candidates[name] = {"version": version, "directory": relative, "selected_candidate": name, "threshold": threshold, "model_sha256": artifact_sha, "validation": _compact(reports["validation"]), "internal_test": _compact(reports["test"]), "validation_constraints_feasible": threshold_choice["feasible"], "threshold_selection": threshold_choice}
        print(json.dumps({"candidate": name, "version": version, "threshold": threshold, "validation_recall": reports["validation"]["recall"], "validation_fpr": reports["validation"]["false_positive_rate"], "constraint_feasible": threshold_choice["feasible"]}), flush=True)
    eligible = [name for name, value in candidates.items() if value["validation_constraints_feasible"]]
    selected = max(eligible, key=lambda name: (candidates[name]["validation"]["recall"], -candidates[name]["validation"]["false_positive_rate"], -candidates[name]["validation"]["log_loss"], name)) if eligible else None
    selection = {**(candidates[selected] if selected else {"selected_candidate": None}), "candidates": candidates, "primary_eligible_for_independent_admission": selected is not None, "selection_rule": "Validation recall, lower pooled FPR, lower validation logloss, deterministic name; no final-data candidate switching.", "dataset_sha256": dataset_sha, "provenance_sha256": identity["provenance_sha256"], "code_sha256": code, "final_data_read": False, "all_three_artifacts_frozen_before_final": True, "partitions": partition_summary}
    assert sha256_file(args.csv) == dataset_sha and sha256_file(args.provenance) == identity["provenance_sha256"]
    assert all(sha256_file(ROOT / name) == digest for name, digest in code.items())
    json_write(selection_path, selection)
    print(json.dumps({"selected_candidate": selected, "model_versions": versions, "no_final_data_read": True}, indent=2), flush=True)
    return selection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=ROOT / "work/phase6/raw/development.csv")
    parser.add_argument("--provenance", type=Path, default=ROOT / "work/phase6/raw/provenance.json")
    parser.add_argument("--model-root", type=Path, default=ROOT / "backend/models/email_en_v6")
    parser.add_argument("--report-root", type=Path, default=ROOT / "docs/ml/phase6")
    parser.add_argument("--checkpoint-root", type=Path, default=ROOT / "work/phase6/experiments")
    args = parser.parse_args()
    with threadpool_limits(limits=1):
        train(args)


if __name__ == "__main__":
    main()
