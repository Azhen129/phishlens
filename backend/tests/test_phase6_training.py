"""Constraint, leakage and artifact tests; synthetic rows are software fixtures.

No metric from this file is a trained PhishLens accuracy claim.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np
import pytest
from threadpoolctl import threadpool_limits

from backend.ml_training_v6 import (
    constrained_threshold,
    group_bootstrap_intervals,
    load_development,
    metric_report,
    partition_roles,
    train,
)
from backend.text_normalization_v6 import normalize_english_text


def row(text, label, source, role, group=None):
    identifier = hashlib.sha256(normalize_english_text(text).encode()).hexdigest()
    return {"text": text, "label": str(label), "source": source, "group": group or "phase6:" + identifier, "row_id": identifier, "date": "", "language": "en", "role": role}


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["text", "label", "source", "group", "row_id", "date", "language", "role"])
        writer.writeheader()
        writer.writerows(rows)


def test_small_bad_source_cannot_hide_inside_a_large_pooled_denominator():
    labels = np.r_[np.zeros(2000), np.ones(40)]
    scores = np.r_[np.full(1800, .1), np.full(10, .9), np.full(190, .1), np.full(40, .8)]
    sources = np.asarray(["large"] * 1800 + ["small"] * 200 + ["phishing"] * 40)
    # A pooled-only threshold of .8 would have recall1 and FPR0.5%, while the
    # 200-row smaller legitimate source suffers a 5% false-positive rate.
    choice = constrained_threshold(labels, scores, sources)
    assert choice["feasible"] is True
    assert choice["validation_recall"] == 0
    assert choice["per_benign_source"]["small"]["false_positives"] == 0
    assert choice["per_benign_source"]["small"]["constraint_passed"] is True


def test_small_source_is_reported_as_insufficient_instead_of_declared_safe():
    labels = np.r_[np.zeros(2100), np.ones(40)]
    scores = np.r_[np.full(2000, .1), np.full(2, .9), np.full(98, .1), np.full(40, .8)]
    sources = np.asarray(["large"] * 2000 + ["small"] * 100 + ["phishing"] * 40)
    choice = constrained_threshold(labels, scores, sources)
    small = choice["per_benign_source"]["small"]
    assert choice["feasible"] and choice["validation_recall"] == 1
    assert small["false_positives"] == 2
    assert small["constraint_required"] is False
    assert small["constraint_passed"] is None
    assert small["wilson_95"][1] > .02


def test_insufficient_global_control_is_not_manufactured_into_validation():
    labels = np.r_[np.zeros(100), np.ones(20)]
    scores = np.r_[np.full(100, .1), np.full(20, .9)]
    choice = constrained_threshold(labels, scores, np.asarray(["legitimate"] * 100 + ["phishing"] * 20))
    assert choice["feasible"] is False
    assert choice["pooled_false_positives"] == 0
    assert choice["pooled_wilson_95"][1] > .02


def test_exact_unit_score_false_positives_cannot_be_hidden_above_one():
    labels = np.r_[np.zeros(200), np.ones(20)]
    scores = np.r_[np.ones(10), np.zeros(190), np.full(20, .8)]
    choice = constrained_threshold(labels, scores, np.asarray(["legitimate"] * 200 + ["phishing"] * 20))
    assert choice["feasible"] is False
    assert 0 < choice["threshold"] < 1
    assert choice["pooled_false_positives"] == 10


def test_campaign_group_crossing_heldout_role_fails_closed(tmp_path):
    path = tmp_path / "development.csv"
    group = "phase6:" + "a" * 64
    write_csv(path, [row("Project meeting notes reference 1", 0, "a", "train_pool", group), row("Please verify the account reference 2", 1, "b", "validation", group)])
    with pytest.raises(ValueError, match="crosses"):
        load_development(path)


def test_stratified_pool_folds_cannot_move_prepared_validation_rows(tmp_path):
    path = tmp_path / "development.csv"
    data = [row(f"Project message reference {i} labelword {i % 2}", i % 2, "pool", "train_pool") for i in range(100)]
    data += [row(f"Held out reference {i} labelword {i % 2}", i % 2, "heldout", "validation") for i in range(20)]
    write_csv(path, data)
    rows = load_development(path)
    parts = partition_roles(rows)
    assert {rows[i].row_id for i in parts["validation"]} == {item["row_id"] for item in data if item["role"] == "validation"}
    seen = set()
    for indexes in parts.values():
        current = {rows[i].group for i in indexes}
        assert not current & seen
        seen.update(current)
    assert sum(map(len, parts.values())) == len(data)


def test_one_class_source_has_no_invented_rank_metric():
    metrics = metric_report([0, 0, 0], [.1, .8, .2], .5)
    assert metrics["confusion_matrix"] == [[2, 1], [0, 0]]
    assert metrics["recall"] is None
    assert metrics["roc_auc"] is None and metrics["average_precision"] is None
    assert metrics["false_positive_rate"] == 1 / 3


def test_cross_source_campaign_stays_whole_during_source_bootstrap():
    report = group_bootstrap_intervals([0, 1, 0, 1], [0, 1, 1, 1], ["campaign", "campaign", "a", "b"], ["a", "b", "a", "b"])
    assert report["groups"] == 3 and report["source_set_strata"] == 3
    assert report["replicates"] == 400
    assert report["intervals"]["accuracy"] == [.75, .75]


def test_real_pipeline_roundtrip_never_reads_final_and_preserves_existing_versions(tmp_path, monkeypatch):
    path = tmp_path / "development.csv"
    data = []
    for i in range(100):
        label = i % 2
        text = ("Please verify your account password immediately" if label else "Project agenda notes for our meeting tomorrow") + f" reference {i}"
        data.append(row(text, label, "software-pool", "train_pool"))
    for i in range(275):
        label = int(i >= 250)
        text = ("Please verify your account password immediately" if label else "Project agenda notes for our meeting tomorrow") + f" heldout reference {i}"
        data.append(row(text, label, "software-heldout", "validation"))
    write_csv(path, data)
    provenance = tmp_path / "provenance.json"
    final = tmp_path / "final-must-not-be-read.csv"
    final.write_text("PROTECTED FINAL INPUT", encoding="utf-8")
    synthetic_profile_path = "/".join(("C:", "Users", "private-workstation", "development.csv"))
    provenance.write_text(json.dumps({"task": "email", "approved_for_training": True, "supported_languages": ["en"], "source_url": "https://example.test/software-fixtures", "license": "Synthetic software fixtures only", "permission_basis": "Test-authored software fixtures, never classifier evaluation ground truth", "collection_notes": "Software artifact roundtrip only", "validation_scope": "Software fixture checks only, not an accuracy claim", "prepared": {"path": synthetic_profile_path, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}, "final": {"path": str(final), "sha256": "a" * 64}}), encoding="utf-8")
    original_open = Path.open

    def guarded_open(self, *args, **kwargs):
        if self.resolve() == final.resolve():
            raise AssertionError("Training must never read final evaluation rows")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    args = argparse.Namespace(csv=path, provenance=provenance, model_root=tmp_path / "models", report_root=tmp_path / "reports", checkpoint_root=tmp_path / "checkpoints")
    with threadpool_limits(limits=1):
        result = train(args)
    assert len(result["candidates"]) == 3
    assert result["final_data_read"] is False
    originals = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.rglob("*") if p.is_file() and p != final}
    for p in (tmp_path / "models").glob("*/manifest.json"):
        manifest = json.loads(p.read_text())
        assert manifest["validated"] is False
        assert manifest["metadata"]["probability_validated_for_deployment"] is False
        assert hashlib.sha256((p.parent / "model.joblib").read_bytes()).hexdigest() == manifest["sha256"]
    for p in list((tmp_path / "models").rglob("*.json")) + list((tmp_path / "reports").glob("*.json")):
        assert "private-workstation" not in p.read_text()
        assert str(tmp_path) not in p.read_text()
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        train(args)
    assert all(hashlib.sha256(p.read_bytes()).hexdigest() == digest for p, digest in originals.items())
