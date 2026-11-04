"""Explicit, offline TF-IDF + Logistic Regression training with provenance gate.

No synthetic examples or dataset downloads are supplied. Run with --help.
The application does not load arbitrary pickles or advertise this model as
validated until a human reviews provenance and held-out metrics.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path, help="CSV with text,label columns (label 0=legitimate, 1=phishing)")
    parser.add_argument("--provenance", required=True, type=Path, help="JSON with source_url, license, permission_basis, collection_notes")
    parser.add_argument("--out", type=Path, default=Path("backend/models"))
    args = parser.parse_args()
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    import joblib

    provenance = json.loads(args.provenance.read_text(encoding="utf-8"))
    required = {"source_url", "license", "permission_basis", "collection_notes"}
    if not required <= provenance.keys() or not all(isinstance(provenance[k], str) and provenance[k].strip() for k in required):
        parser.error("Document source_url, license, permission_basis and collection_notes before training. Do not use data without legal permission.")
    texts, labels, seen = [], [], set()
    conflicts = 0
    with args.csv.open(encoding="utf-8-sig", newline="") as stream:
        rows = csv.DictReader(stream)
        if not {"text", "label"} <= set(rows.fieldnames or []):
            parser.error("CSV needs text,label columns.")
        for row in rows:
            text = " ".join(row["text"].split()).strip()
            if not text:
                continue
            try:
                label = int(row["label"])
                if label not in (0, 1):
                    raise ValueError()
            except ValueError:
                parser.error("Labels must be 0 or 1.")
            digest = hashlib.sha256(text.lower().encode()).hexdigest()
            if digest in seen:
                conflicts += 1
                continue
            seen.add(digest)
            texts.append(text)
            labels.append(label)
    balance = {str(label): labels.count(label) for label in (0, 1)}
    if min(balance.values()) < 20:
        parser.error("Need at least 20 unique real, legally usable messages per class for a minimal stratified split. This minimum alone does not establish representativeness.")
    train_x, test_x, train_y, test_y = train_test_split(texts, labels, test_size=0.25, random_state=42, stratify=labels)
    # Fit vocabulary/IDF solely on training samples; never before splitting.
    model = Pipeline([("tfidf", TfidfVectorizer(min_df=2, max_features=50000, ngram_range=(1, 2), sublinear_tf=True)), ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42))])
    model.fit(train_x, train_y)
    predicted = model.predict(test_x)
    metrics = {"model_version": "tfidf-logreg-v1", "dataset_sha256": hashlib.sha256(args.csv.read_bytes()).hexdigest(), "provenance": provenance, "class_balance": balance, "duplicate_rows_removed": conflicts, "split": {"seed": 42, "strategy": "stratified", "test_fraction": 0.25, "train_samples": len(train_x), "test_samples": len(test_x)}, "classification_report": classification_report(test_y, predicted, target_names=["legitimate", "phishing"], output_dict=True, zero_division=0), "confusion_matrix": confusion_matrix(test_y, predicted, labels=[0, 1]).tolist(), "limitations": "Uncalibrated baseline. Exact normalized duplicates are removed, but near-duplicates, sender/campaign overlap, temporal and domain leakage require dataset-specific review. No probability, field performance or generalization guarantee. App remains rules-only until reviewed integration."}
    args.out.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.out / "tfidf-logreg-v1.joblib")
    (args.out / "tfidf-logreg-v1.metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
