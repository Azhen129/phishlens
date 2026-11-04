"""Reproducible licensed-data training, leakage controls, calibration and evaluation.

Run with ``python -m backend.ml_training --help``. Dataset files are data only.
No dataset Python, URLs or HTML are executed or visited. No app database is read.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import platform
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, average_precision_score, brier_score_loss, confusion_matrix,
    f1_score, log_loss, precision_recall_curve, precision_score, recall_score, roc_auc_score,
    roc_curve, auc,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from .ml_features import (
    CalibratedHybrid, FEATURE_VERSION, TrainedClassifier, UrlLexicalTransformer,
    canonical_text, hostname_text, hybrid_features, normalize_email_text, normalize_url_text,
)

SEED = 20261102
PARTITIONS = {"train": [0, 1, 2, 3, 4], "calibration": [5], "hybrid_fit": [6], "hybrid_calibration": [7], "validation": [8], "test": [9]}


@dataclass
class Row:
    text: str
    label: int
    source: str
    identifier: str
    supplied_group: str = ""


class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))
        self.size = [1] * n

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        a, b = self.find(a), self.find(b)
        if a == b:
            return
        if self.size[a] < self.size[b]:
            a, b = b, a
        self.parent[b] = a
        self.size[a] += self.size[b]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_provenance(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = ("source_url", "license", "permission_basis", "collection_notes")
    if not all(isinstance(data.get(k), str) and data[k].strip() for k in required):
        raise ValueError("Provenance must explicitly document source_url, license, permission_basis and collection_notes.")
    if data.get("approved_for_training") is not True:
        raise ValueError("Provenance must set approved_for_training=true after license and label review.")
    return data


def verify_dataset_identity(csv_path: Path, provenance: dict, kind: str):
    if provenance.get("task") != kind:
        raise ValueError("Provenance task does not match the requested training kind.")
    expected = provenance.get("prepared", {}).get("sha256", "")
    if not isinstance(expected, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        raise ValueError("Approved provenance must bind prepared.sha256 to the exact training CSV.")
    actual = sha256_file(csv_path)
    if not hmac.compare_digest(expected.lower(), actual):
        raise ValueError("Training CSV SHA-256 does not match the approved provenance.")
    languages = provenance.get("supported_languages")
    if kind == "email" and (not isinstance(languages, list) or not languages or not all(isinstance(v, str) and re.fullmatch(r"[a-z]{2}", v) for v in languages) or not isinstance(provenance.get("validation_scope"), str) or not provenance["validation_scope"].strip()):
        raise ValueError("Email provenance must declare supported_languages and an explicit validation_scope.")
    return actual


def load_rows(path: Path, kind: str, max_rows=50_000):
    csv.field_size_limit(2 * 1024 * 1024)
    by_key: dict[str, Row] = {}
    conflicts: set[str] = set()
    stats = Counter()
    normalize = normalize_email_text if kind == "email" else normalize_url_text
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not {"text", "label"}.issubset(reader.fieldnames or []):
            raise ValueError("CSV needs text,label columns; source and group are optional.")
        for item in reader:
            stats["input_rows"] += 1
            if stats["input_rows"] > 1_000_000:
                raise ValueError("Dataset exceeds the reviewed one-million-row input bound.")
            if item.get("label", "").strip() not in {"0", "1"}:
                raise ValueError("Labels must be exactly 0 (legitimate) or 1 (phishing).")
            raw_text = str(item.get("text", ""))[:16000 if kind == "email" else 8192]
            text = raw_text if kind == "email" else normalize(raw_text)
            if len(normalize(text).strip()) < 5:
                stats["empty_or_too_short"] += 1
                continue
            label = int(item["label"])
            canonical = canonical_text(text, kind)
            key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if key in by_key:
                stats["exact_duplicate_rows"] += 1
                if by_key[key].label != label:
                    conflicts.add(key)
                continue
            by_key[key] = Row(text, label, str(item.get("source") or "unspecified")[:100], key, str(item.get("group") or "")[:500])
    for key in conflicts:
        by_key.pop(key, None)
    stats["conflicting_exact_groups_quarantined"] = len(conflicts)
    rows = sorted(by_key.values(), key=lambda r: r.identifier)
    stats["unique_before_sampling"] = len(rows)
    if len(rows) > max_rows:
        # SHA ordering is a reproducible label-blind sample, not first-N rows.
        rows = rows[:max_rows]
        stats["sampling_rows_removed"] = stats["unique_before_sampling"] - len(rows)
    stats["retained_rows"] = len(rows)
    return rows, dict(stats)


def shingles(text: str, kind: str) -> frozenset[int]:
    canonical = canonical_text(text, kind)
    if kind == "email":
        canonical = re.sub(r"https?://\S+", " URLTOKEN ", canonical)
        canonical = re.sub(r"\b[^\s@]+@[^\s@]+\b", " EMAILTOKEN ", canonical)
        canonical = re.sub(r"\d+", "NUMTOKEN", canonical)
        tokens = re.findall(r"[\w]+", canonical)[:600]
        chunks = [" ".join(tokens[i:i + 5]) for i in range(max(1, len(tokens) - 4))]
    else:
        canonical = re.sub(r"\d+", "#", canonical)
        chunks = [canonical[i:i + 5] for i in range(max(1, len(canonical) - 4))][:600]
    return frozenset(int.from_bytes(hashlib.blake2b(c.encode(), digest_size=8).digest(), "big") for c in chunks if c)


def build_groups(rows: list[Row], kind: str, threshold=.90, max_comparisons=5_000_000):
    """Exact prefix-filter Jaccard join over a documented bounded representation.

    Unlike an LSH-only search, prefix filtering does not silently omit pairs
    meeting the specified Jaccard threshold. A comparison-bound breach fails
    training rather than claiming that an incomplete audit passed.
    """
    uf = UnionFind(len(rows))
    fingerprints = [shingles(r.text, kind) for r in rows]
    frequencies = Counter(v for values in fingerprints for v in values)
    index: dict[int, list[int]] = defaultdict(list)
    comparisons = pairs = 0
    for i in sorted(range(len(rows)), key=lambda j: (len(fingerprints[j]), rows[j].identifier)):
        values = fingerprints[i]
        if not values:
            continue
        ordered = sorted(values, key=lambda v: (frequencies[v], v))
        prefix_length = len(values) - math.ceil(threshold * len(values)) + 1
        candidates = set()
        for token in ordered[:prefix_length]:
            candidates.update(index[token])
        for j in sorted(candidates):
            other = fingerprints[j]
            if len(other) < threshold * len(values):
                continue
            comparisons += 1
            if comparisons > max_comparisons:
                raise ValueError("Near-duplicate audit exceeded its comparison bound; reduce reviewed sample size or increase --max-comparisons explicitly.")
            intersection = len(values & other)
            if intersection / (len(values) + len(other) - intersection) >= threshold:
                uf.union(i, j)
                pairs += 1
        for token in ordered[:prefix_length]:
            index[token].append(i)
    supplied = {}
    for i, row in enumerate(rows):
        if row.supplied_group:
            # Reviewed multi-corpus preparation can explicitly supply a global
            # campaign component. Other datasets keep source-local group IDs.
            key = row.supplied_group if row.supplied_group.startswith("global:") else row.source + "|" + row.supplied_group
            if key in supplied:
                uf.union(i, supplied[key])
            else:
                supplied[key] = i
    domain_count = 0
    if kind == "url":
        import tldextract
        extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
        domains = {}
        for i, row in enumerate(rows):
            try:
                host = urlsplit(normalize_url_text(row.text)).hostname or ""
                result = extract(host)
                key = result.top_domain_under_public_suffix or host
            except ValueError:
                key = ""
            if key:
                if key in domains:
                    uf.union(i, domains[key])
                else:
                    domains[key] = i
        domain_count = len(domains)
    # Stable group IDs avoid dependence on union representative order.
    members = defaultdict(list)
    for i in range(len(rows)):
        members[uf.find(i)].append(i)
    group_ids = {}
    for indexes in members.values():
        group_id = min(rows[i].identifier for i in indexes)
        for i in indexes:
            group_ids[i] = group_id
    return np.asarray([group_ids[i] for i in range(len(rows))]), {
        "near_duplicate_threshold": threshold,
        "near_duplicate_representation": "email first600 tokens, 5-word shingles, URL/email/number placeholders; URL first600 character5-grams with digit placeholders",
        "near_duplicate_algorithm": "deterministic exact prefix-filter Jaccard join; fail closed at comparison bound",
        "near_duplicate_comparisons": comparisons, "near_duplicate_pairs": pairs,
        "groups": len(members), "largest_group": max((len(x) for x in members.values()), default=0),
        "url_registered_domain_groups": domain_count,
        "source_separation": "Source labels are retained for error analysis. Lexical campaign and URL registered-domain groups are disjoint; whole-source holdout is not assumed possible when labels depend on corpus source.",
    }


def grouped_partitions(labels, groups, seed=SEED):
    labels, groups = np.asarray(labels), np.asarray(groups)
    for label in (0, 1):
        if len(set(groups[labels == label])) < 10:
            raise ValueError("Need at least ten independent groups containing each class for ten-fold partitioning.")
    folds = list(StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=seed).split(np.zeros(len(labels)), labels, groups))
    partitions = {name: np.sort(np.concatenate([folds[i][1] for i in fold_ids])) for name, fold_ids in PARTITIONS.items()}
    seen_groups = set()
    for name, indexes in partitions.items():
        if set(labels[indexes]) != {0, 1}:
            raise ValueError(f"Grouped {name} partition lacks a class; dataset/group structure is insufficient for this protocol.")
        current = set(groups[indexes])
        if seen_groups & current:
            raise AssertionError("Group leakage detected")
        seen_groups.update(current)
    return partitions


def expected_calibration_error(labels, p, bins=10):
    labels, p = np.asarray(labels), np.asarray(p)
    entries, error = [], 0.0
    for i in range(bins):
        mask = (p >= i / bins) & (p < (i + 1) / bins if i < bins - 1 else p <= 1)
        n = int(mask.sum())
        if n:
            predicted, observed = float(p[mask].mean()), float(labels[mask].mean())
            error += n / len(labels) * abs(predicted - observed)
            entries.append({"bin": i, "n": n, "predicted": predicted, "observed": observed})
    return error, entries


def evaluate(labels, probabilities, threshold=.5, calibrated=True):
    y, p = np.asarray(labels, dtype=int), np.asarray(probabilities, dtype=float)
    predicted = (p >= threshold).astype(int)
    precision, recall, pr_thresholds = precision_recall_curve(y, p)
    fpr, tpr, roc_thresholds = roc_curve(y, p)
    ece, calibration = expected_calibration_error(y, p)
    return {
        "n": len(y), "class_balance": {str(v): int((y == v).sum()) for v in (0, 1)},
        "threshold": float(threshold), "accuracy": float(accuracy_score(y, predicted)),
        "precision": float(precision_score(y, predicted, zero_division=0)),
        "recall": float(recall_score(y, predicted, zero_division=0)),
        "f1": float(f1_score(y, predicted, zero_division=0)),
        "legitimate_precision": float(precision_score(y, predicted, pos_label=0, zero_division=0)),
        "legitimate_recall": float(recall_score(y, predicted, pos_label=0, zero_division=0)),
        "legitimate_f1": float(f1_score(y, predicted, pos_label=0, zero_division=0)),
        "confusion_matrix": confusion_matrix(y, predicted, labels=[0, 1]).tolist(),
        "false_positives": int(((predicted == 1) & (y == 0)).sum()),
        "false_negatives": int(((predicted == 0) & (y == 1)).sum()),
        "false_positive_rate": float(((predicted == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)),
        "false_negative_rate": float(((predicted == 0) & (y == 1)).sum() / max((y == 1).sum(), 1)),
        "roc_auc": float(roc_auc_score(y, p)),
        "average_precision": float(average_precision_score(y, p)),
        "pr_auc_trapezoid": float(auc(recall, precision)),
        "brier_score": float(brier_score_loss(y, p)) if calibrated else None,
        "log_loss": float(log_loss(y, p, labels=[0, 1])) if calibrated else None,
        "expected_calibration_error": float(ece) if calibrated else None,
        "calibration_bins": calibration if calibrated else [],
        "curves": {"roc": {"fpr": fpr.tolist(), "tpr": tpr.tolist()}, "pr": {"recall": recall.tolist(), "precision": precision.tolist()}},
    }


def operating_threshold(labels, probabilities):
    # The prespecified grid is searched only on selection-validation examples.
    choices = []
    for threshold in np.linspace(.10, .90, 81):
        predicted = np.asarray(probabilities) >= threshold
        choices.append((f1_score(labels, predicted, zero_division=0), recall_score(labels, predicted, zero_division=0), -abs(threshold - .5), float(threshold)))
    return max(choices)[3]


def hybrid_selection_exclusions(kind, hybrid):
    reasons = []
    if kind == "url":
        reasons.append("Known URL source scheme/path artifacts: hybrid remains diagnostic only; primary classifier uses hostname-only features.")
    slope = float(hybrid.calibrator.coef_[0, 0])
    heuristic_coefficient = float(hybrid.estimator.coef_[0, 1])
    if slope <= 0 or slope * heuristic_coefficient < 0:
        reasons.append("Nonpositive final calibration slope or negative effective heuristic coefficient violates prespecified security-monotonicity admission policy.")
    return reasons


def build_estimator(kind, baseline, seed=SEED, max_features=40_000):
    classifier = LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced", random_state=seed, solver="liblinear") if baseline == "logistic_regression" else LinearSVC(C=1.0, class_weight="balanced", random_state=seed, max_iter=10000, tol=.001)
    if kind == "email":
        features = TfidfVectorizer(preprocessor=normalize_email_text, lowercase=True, ngram_range=(1, 2), min_df=2, max_features=max_features, sublinear_tf=True, dtype=np.float64)
    else:
        features = FeatureUnion([
            ("characters", TfidfVectorizer(preprocessor=hostname_text, analyzer="char", ngram_range=(3, 5), min_df=2, max_features=max_features, sublinear_tf=True, dtype=np.float64)),
            ("lexical", Pipeline([("features", UrlLexicalTransformer(policy="hostname")), ("scale", StandardScaler(with_mean=False))])),
        ])
    return Pipeline([("features", features), ("classifier", classifier)])


def fit_sigmoid(scores, labels, seed):
    calibrator = LogisticRegression(C=100.0, solver="lbfgs", max_iter=1000, random_state=seed)
    calibrator.fit(np.asarray(scores).reshape(-1, 1), labels)
    return calibrator


def heuristic_points(rows: list[Row], kind: str):
    # Runtime ML is explicitly disabled while measuring the existing rules.
    from .analysis import inspect_email, inspect_url_submission
    scores = []
    for row in rows:
        try:
            scan = inspect_email(row.text, use_ml=False) if kind == "email" else inspect_url_submission(row.text, use_ml=False)
            scores.append(scan["score"])
        except ValueError:
            # Invalid URL strings have no valid API analysis. Their ML-only
            # performance is still measured; hybrid heuristic is missing=0.
            scores.append(0)
    return np.asarray(scores, dtype=float)


def source_bias_audit(rows: list[Row], kind: str):
    summary = {}
    for label in (0, 1):
        items = [r for r in rows if r.label == label]
        lengths = [len(r.text) for r in items]
        entry = {"n": len(items), "sources": dict(Counter(r.source for r in items)), "text_length_quantiles": dict(zip(["min", "median", "p95", "max"], map(float, np.quantile(lengths, [0, .5, .95, 1]))))}
        if kind == "url":
            parsed = []
            for row in items:
                try:
                    parsed.append(urlsplit(normalize_url_text(row.text)))
                except ValueError:
                    pass
            entry["https_fraction"] = sum(p.scheme == "https" for p in parsed) / max(len(parsed), 1)
            entry["root_without_query_fraction"] = sum(p.path in {"", "/"} and not p.query for p in parsed) / max(len(parsed), 1)
        summary[str(label)] = entry
    return {"scope": "retained reviewed sample; descriptive source bias, not independent performance evidence", "by_label": summary}


def url_counterfactuals(texts):
    variants = {"forced_https": [], "forced_http": [], "benign_long_path_query": []}
    for text in texts:
        p = urlsplit(normalize_url_text(text))
        variants["forced_https"].append(p._replace(scheme="https").geturl())
        variants["forced_http"].append(p._replace(scheme="http").geturl())
        variants["benign_long_path_query"].append(p._replace(path="/documentation/" + "ordinary-project-notes/" * 15, query="language=en&view=summary&reference=" + "a" * 160, fragment="section").geturl())
    return variants


def json_write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False), encoding="utf-8")


def save_figures(output: Path, metrics: dict):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(2, 2, figsize=(11, 8), constrained_layout=True)
    matrix = np.asarray(metrics["selected_test"]["confusion_matrix"])
    axes[0, 0].imshow(matrix, cmap="Blues")
    for (i, j), value in np.ndenumerate(matrix):
        axes[0, 0].text(j, i, str(value), ha="center", va="center", color="white" if value > matrix.max() / 2 else "black")
    axes[0, 0].set(xticks=[0, 1], yticks=[0, 1], xticklabels=["Legitimate", "Phishing"], yticklabels=["Legitimate", "Phishing"], xlabel="Predicted label", ylabel="Dataset label", title="Held-out test confusion matrix")
    for name, candidate in metrics["candidates"].items():
        test = candidate["test"]
        axes[0, 1].plot(test["curves"]["roc"]["fpr"], test["curves"]["roc"]["tpr"], label=f"{name}: {test['roc_auc']:.3f}")
        axes[1, 0].plot(test["curves"]["pr"]["recall"], test["curves"]["pr"]["precision"], label=f"{name}: AP {test['average_precision']:.3f}")
    axes[0, 1].plot([0, 1], [0, 1], "k--", linewidth=.8)
    axes[0, 1].set(xlabel="False-positive rate", ylabel="True-positive rate", title="Held-out ROC curves")
    axes[1, 0].set(xlabel="Recall", ylabel="Precision", title="Held-out precision–recall curves")
    bins = metrics["selected_test"]["calibration_bins"]
    axes[1, 1].plot([0, 1], [0, 1], "k--", linewidth=.8)
    axes[1, 1].plot([b["predicted"] for b in bins], [b["observed"] for b in bins], "o-", label="Selected assessment")
    axes[1, 1].set(xlabel="Mean predicted phishing probability", ylabel="Observed phishing fraction", title="Held-out reliability diagram", xlim=(0, 1), ylim=(0, 1))
    for axis in axes.flat:
        if axis is not axes[0, 0]:
            axis.legend(fontsize=7)
            axis.grid(alpha=.2)
    fig.suptitle(f"PhishLens {metrics['kind']} | {metrics['version']} | dataset-conditioned evaluation", fontsize=12)
    fig.savefig(output / "evaluation.png", dpi=160)
    fig.savefig(output / "evaluation.svg")
    plt.close(fig)


def train(args):
    provenance = load_provenance(args.provenance)
    verify_dataset_identity(args.csv, provenance, args.kind)
    rows, cleaning = load_rows(args.csv, args.kind, args.max_rows)
    if min(Counter(r.label for r in rows).values(), default=0) < 50 or {r.label for r in rows} != {0, 1}:
        raise ValueError("At least fifty unique real examples of each class are required.")
    print(f"Loaded {len(rows)} reviewed {args.kind} rows. Auditing lexical near duplicates and domains...", flush=True)
    groups, group_audit = build_groups(rows, args.kind, max_comparisons=args.max_comparisons)
    y = np.asarray([r.label for r in rows])
    partitions = grouped_partitions(y, groups, args.seed)
    split_audit = {name: {"n": len(indexes), "class_balance": {str(v): int((y[indexes] == v).sum()) for v in (0, 1)}, "group_count": len(set(groups[indexes])), "sources": dict(Counter(rows[i].source for i in indexes))} for name, indexes in partitions.items()}
    texts = np.asarray([r.text for r in rows], dtype=object)
    points = heuristic_points(rows, args.kind)
    candidates, models = {}, {}
    for baseline in ("logistic_regression", "linear_svm"):
        print(f"Fitting {baseline} on {len(partitions['train'])} training examples...", flush=True)
        base = build_estimator(args.kind, baseline, args.seed, args.max_features)
        base.fit(texts[partitions["train"]], y[partitions["train"]])
        cal = partitions["calibration"]
        classifier = TrainedClassifier(base, fit_sigmoid(base.decision_function(texts[cal]), y[cal], args.seed))
        p = classifier.predict_proba(texts)[:, 1]
        hfit, hcal = partitions["hybrid_fit"], partitions["hybrid_calibration"]
        hybrid_base = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000, random_state=args.seed)
        hybrid_base.fit(hybrid_features(p[hfit], points[hfit]), y[hfit])
        hybrid = CalibratedHybrid(hybrid_base, fit_sigmoid(hybrid_base.decision_function(hybrid_features(p[hcal], points[hcal])), y[hcal], args.seed))
        hybrid_p = hybrid.predict_proba(hybrid_features(p, points))[:, 1]
        val = partitions["validation"]
        for mode, probabilities in (("ml", p), ("hybrid", hybrid_p)):
            threshold = operating_threshold(y[val], probabilities[val])
            name = baseline + "_" + mode
            candidates[name] = {"validation": evaluate(y[val], probabilities[val], threshold), "threshold": threshold, "mode": mode, "baseline": baseline}
            if mode == "ml":
                # Raw sigmoid-transformed SVM margins are only a diagnostic;
                # they are never exposed as calibrated runtime probabilities.
                margin = np.clip(base.decision_function(texts), -40, 40)
                raw_p = 1 / (1 + np.exp(-margin))
                candidates[name]["calibration_comparison"] = {
                    "uncalibrated_diagnostic": "LR native sigmoid probability; SVM arbitrary sigmoid margin transform (not calibrated confidence). Neither diagnostic is displayed in the application.",
                    "held_out_sigmoid_coefficient": float(classifier.calibrator.coef_[0, 0]),
                    "held_out_sigmoid_intercept": float(classifier.calibrator.intercept_[0]),
                    "validation_before": evaluate(y[val], raw_p[val]),
                    "test_before": None,
                }
                models[baseline + "_raw"] = raw_p
            models[name] = (classifier, hybrid, probabilities)
    # Protocol policies are fixed before final training: URL ML-only avoids a
    # learned hybrid exploiting documented scheme/path source shortcuts. Email
    # hybrids with a negative rule coefficient are not operationally selected.
    eligible = []
    for name, candidate in candidates.items():
        reasons = hybrid_selection_exclusions(args.kind, models[name][1]) if candidate["mode"] == "hybrid" else []
        if candidate["mode"] == "hybrid" and getattr(args, "email_ml_only", False):
            reasons.append("English protocol prespecifies ML-only final assessment; heuristic points and evidence remain independently displayed. Hybrid is diagnostic only.")
        candidate["eligible_for_selection"] = not reasons
        candidate["selection_exclusions"] = reasons
        if not reasons:
            eligible.append(name)
    # Only validation results participate in model/mode/threshold selection.
    selected = max(eligible, key=lambda n: (candidates[n]["validation"]["f1"], candidates[n]["validation"]["recall"], -candidates[n]["validation"]["brier_score"], n == "logistic_regression_ml"))
    test = partitions["test"]
    for name, candidate in candidates.items():
        candidate["test"] = evaluate(y[test], models[name][2][test], candidate["threshold"])
        if candidate["mode"] == "ml":
            candidate["calibration_comparison"]["test_before"] = evaluate(y[test], models[candidate["baseline"] + "_raw"][test])
    selected_test = candidates[selected]["test"]
    validation_passed = selected_test["f1"] >= .70 and selected_test["roc_auc"] >= .75 and selected_test["brier_score"] <= .25 and min(selected_test["class_balance"].values()) >= 10
    code_identity = {"training_code_sha256": sha256_file(Path(__file__)), "feature_code_sha256": sha256_file(Path(__file__).with_name("ml_features.py")), "provenance_sha256": sha256_file(args.provenance)}
    version_digest = hashlib.sha256((sha256_file(args.csv) + json.dumps({"kind": args.kind, "seed": args.seed, "max_features": args.max_features, "max_rows": args.max_rows, "email_ml_only": getattr(args, "email_ml_only", False), "feature_version": FEATURE_VERSION, "partitions": PARTITIONS, "sklearn_version": sklearn.__version__, **code_identity}, sort_keys=True)).encode()).hexdigest()[:12]
    version = f"{args.kind}-{FEATURE_VERSION}-{version_digest}"
    limitations = [
        "Dataset-conditioned calibrated probabilities are not a guarantee of field performance or confirmed maliciousness.",
        "Labels and source collection biases are inherited from the documented dataset; source-level and temporal generalization are not established.",
        "Lexical near-duplicate grouping does not detect all semantic paraphrases. Email inputs are bounded to16000 characters; URL inputs to8192.",
        "No destination fetching, DNS, reputation lookup, authentication verification or attachment execution is performed by the model.",
    ]
    limitations.extend(str(value) for value in provenance.get("limitations", []))
    if args.kind == "url":
        limitations.append("The UCI source has strong collection artifacts (legitimate URLs predominantly HTTPS and short/root paths). Primary ML intentionally uses hostname-only features; path/scheme signals remain heuristic observations. Hostname collection bias and external prevalence shift remain unresolved.")
    selected_classifier, selected_hybrid, selected_probabilities = models[selected]
    selected_ml_p = selected_classifier.predict_proba(texts[test])[:, 1]
    error_summary = {"false_positives": [], "false_negatives": [], "by_source": {}}
    pred = selected_probabilities[test] >= candidates[selected]["threshold"]
    by_source = defaultdict(Counter)
    for position, i in enumerate(test):
        error = "false_positives" if pred[position] and y[i] == 0 else "false_negatives" if not pred[position] and y[i] == 1 else None
        by_source[rows[i].source]["n"] += 1
        by_source[rows[i].source]["phishing" if y[i] else "legitimate"] += 1
        if error:
            by_source[rows[i].source][error] += 1
            if len(error_summary[error]) < 30:
                error_summary[error].append({"sha256": rows[i].identifier, "source": rows[i].source, "dataset_label": int(y[i]), "predicted_probability": float(selected_probabilities[i]), "heuristic_score": float(points[i])})
    error_summary["by_source"] = {s: dict(counts) for s, counts in by_source.items()}
    metrics = {"format_version": 1, "kind": args.kind, "version": version, "created_at": datetime.now(timezone.utc).isoformat(), "dataset": provenance, "dataset_sha256": sha256_file(args.csv), "cleaning": cleaning, "group_audit": group_audit, "partitions": split_audit, "group_intersection_count": 0, "selected_candidate": selected, "selection_rule": "Among prespecified-policy eligible candidates, maximum positive-class F1 on selection validation; tie by recall, Brier, then simpler LR ML-only. No held-out test data used to fit or select any model, calibrator, threshold or combination.", "candidates": candidates, "selected_test": selected_test, "selected_base_ml_test": evaluate(y[test], selected_ml_p, .5), "heuristic_only_test": evaluate(y[test], points[test] / 100, .60, calibrated=False), "source_bias_audit": source_bias_audit(rows, args.kind), "hybrid_parameters": {"features": ["logit(calibrated_ml_probability)", "heuristic_score/100"], "coefficients": selected_hybrid.estimator.coef_.tolist(), "intercept": selected_hybrid.estimator.intercept_.tolist(), "calibration_coefficient": selected_hybrid.calibrator.coef_.tolist(), "calibration_intercept": selected_hybrid.calibrator.intercept_.tolist()}, "errors": error_summary, "deployment_gate": {"passed": validation_passed, "prespecified_requirements": "test positive F1>=0.70, ROC-AUC>=0.75, Brier<=0.25, at least10 examples of each label"}, "limitations": limitations}
    source_labels = defaultdict(list)
    for i in partitions["train"]:
        source_labels[rows[i].source].append(int(y[i]))
    source_majority = {source: int(np.mean(labels) >= .5) for source, labels in source_labels.items()}
    fallback_label = int(np.mean(y[partitions["train"]]) >= .5)
    source_predictions = np.asarray([source_majority.get(rows[i].source, fallback_label) for i in test])
    metrics["source_only_baseline"] = {
        "method": "Predict training-majority label for the recorded corpus source; unknown source uses training class majority. Source is never a classifier feature. High performance exposes corpus/label confounding rather than phishing detection.",
        "source_training_majorities": source_majority,
        "accuracy": float(accuracy_score(y[test], source_predictions)),
        "f1": float(f1_score(y[test], source_predictions, zero_division=0)),
        "confusion_matrix": confusion_matrix(y[test], source_predictions, labels=[0, 1]).tolist(),
    }
    if args.kind == "url":
        diagnostics = {}
        ml_threshold = candidates[candidates[selected]["baseline"] + "_ml"]["threshold"]
        hybrid_threshold = candidates[candidates[selected]["baseline"] + "_hybrid"]["threshold"]
        baseline_hybrid_p = selected_hybrid.predict_proba(hybrid_features(selected_ml_p, points[test]))[:, 1]
        for scenario, variant_texts in url_counterfactuals(texts[test]).items():
            variant_p = selected_classifier.predict_proba(variant_texts)[:, 1]
            variant_rows = [Row(t, int(y[i]), rows[i].source, rows[i].identifier) for t, i in zip(variant_texts, test)]
            variant_points = heuristic_points(variant_rows, "url")
            variant_hybrid = selected_hybrid.predict_proba(hybrid_features(variant_p, variant_points))[:, 1]
            max_delta = float(np.max(np.abs(variant_p - selected_ml_p)))
            if max_delta > 1e-10:
                raise AssertionError("Hostname feature policy failed scheme/path/query invariance check")
            diagnostics[scenario] = {"scope": "counterfactual robustness diagnostic with inherited original labels; not a new independently labeled benchmark", "n": len(test), "ml_max_probability_change": max_delta, "ml_prediction_flip_count": int(np.sum((variant_p >= ml_threshold) != (selected_ml_p >= ml_threshold))), "hybrid_mean_probability_change": float(np.mean(np.abs(variant_hybrid - baseline_hybrid_p))), "hybrid_prediction_flip_count": int(np.sum((variant_hybrid >= hybrid_threshold) != (baseline_hybrid_p >= hybrid_threshold))), "ml_metrics_inherited_labels": evaluate(y[test], variant_p, ml_threshold)}
        metrics["counterfactual_stress_diagnostics"] = diagnostics
    output = args.out
    output.mkdir(parents=True, exist_ok=True)
    config = {"command": [sys.executable, "-m", "backend.ml_training", *sys.argv[1:]], "seed": args.seed, "kind": args.kind, "max_rows": args.max_rows, "max_features": args.max_features, "max_comparisons": args.max_comparisons, "feature_version": FEATURE_VERSION, "sklearn_version": sklearn.__version__, "python": platform.python_version(), "split_folds": PARTITIONS, "preprocessing": "bounded NFKC, inert HTML-to-text email normalization; URL hostname-only char3-5gram TFIDF plus10 hostname-local lexical features; scheme/path/query excluded by prespecified source-bias policy", "hyperparameters": {"LR_C": 1.0, "SVC_C": 1.0, "calibration_C": 100.0, "hybrid_C": 1.0}, "validation_threshold_grid": {"min": .10, "max": .90, "step": .01}}
    metadata = {"kind": args.kind, "version": version, "calibrated": True, "validation_passed": validation_passed, "assessment_mode": candidates[selected]["mode"], "selected_candidate": selected, "feature_version": FEATURE_VERSION, "sklearn_version": sklearn.__version__, "calibration": "disjoint held-out sigmoid calibration for base model and learned hybrid", "limitations": limitations, "dataset_source": provenance["source_url"], "dataset_license": provenance["license"], "held_out_metrics": {k: v for k, v in selected_test.items() if k not in {"curves", "calibration_bins"}}, "input_max_characters": 16000 if args.kind == "email" else 8192, "supported_languages": provenance.get("supported_languages", []), "validation_scope": provenance.get("validation_scope", "Dataset-conditioned evaluation; external deployment generalization has not been established.")}
    metadata["dataset_name"] = provenance.get("name", "Reviewed licensed corpus")
    artifact = {"format_version": 1, "kind": args.kind, "version": version, "model": selected_classifier, "hybrid_model": selected_hybrid, "threshold": operating_threshold(y[partitions["validation"]], selected_classifier.predict_proba(texts[partitions["validation"]])[:, 1]), "hybrid_threshold": candidates[selected]["threshold"] if candidates[selected]["mode"] == "hybrid" else operating_threshold(y[partitions["validation"]], selected_hybrid.predict_proba(hybrid_features(selected_classifier.predict_proba(texts[partitions["validation"]])[:, 1], points[partitions["validation"]]))[:, 1]), "metadata": metadata}
    config.update(code_identity)
    config["email_ml_only"] = getattr(args, "email_ml_only", False)
    metadata.update(code_identity)
    metrics.update(code_identity)
    joblib.dump(artifact, output / "model.joblib", compress=3)
    json_write(output / "metrics.json", metrics)
    json_write(output / "experiment.json", config)
    json_write(output / "splits.json", {name: [{"sha256": rows[i].identifier, "group_sha256": str(groups[i]), "label": int(y[i]), "source": rows[i].source} for i in indexes] for name, indexes in partitions.items()})
    json_write(output / "manifest.json", {"format_version": 1, "kind": args.kind, "version": version, "artifact": "model.joblib", "sha256": sha256_file(output / "model.joblib"), "sklearn_version": sklearn.__version__, "validated": validation_passed, "metadata": metadata, "metrics_file": "metrics.json"})
    save_figures(output, metrics)
    print(json.dumps({"version": version, "selected": selected, "validated": validation_passed, "test": {k: v for k, v in selected_test.items() if k not in {"curves", "calibration_bins"}}}, indent=2), flush=True)
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=["email", "url"], required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--max-rows", type=int, default=50_000)
    parser.add_argument("--max-features", type=int, default=40_000)
    parser.add_argument("--max-comparisons", type=int, default=5_000_000)
    parser.add_argument("--email-ml-only", action="store_true", help="Prespecify ML-only selection; keep learned hybrids as evaluation diagnostics.")
    args = parser.parse_args()
    if not 100 <= args.max_rows <= 200_000 or not 100 <= args.max_features <= 100_000 or args.max_comparisons < 1:
        parser.error("Reviewed bounds: max-rows100..200000; max-features100..100000; comparisons positive.")
    try:
        train(args)
    except (ValueError, csv.Error) as exc:
        parser.exit(2, f"Training stopped: {exc}\n")


if __name__ == "__main__":
    main()
