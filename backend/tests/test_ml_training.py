"""Algorithm regression fixtures, never used as a shipped training corpus."""
import csv
import hashlib
import json
import socket
from types import SimpleNamespace

import joblib
import numpy as np
import pytest

from backend.ml_features import (
    EMAIL_MAX_CHARS, URL_MAX_CHARS, TrainedClassifier, UrlLexicalTransformer,
    canonical_text, hybrid_features, normalize_email_text, normalize_url_text,
    url_lexical_vector, hostname_text,
)
from backend.ml_training import (
    Row, build_estimator, build_groups, evaluate, expected_calibration_error,
    fit_sigmoid, grouped_partitions, load_provenance, load_rows,
    operating_threshold, shingles,
    url_counterfactuals,
    verify_dataset_identity, hybrid_selection_exclusions,
)


def fixture_row(text, label=0, source="unit-fixture", group=""):
    return Row(text, label, source, hashlib.sha256(text.encode()).hexdigest(), group)


def test_preprocessing_is_inert_bounded_and_unicode_normalized():
    result = normalize_email_text('<p>URGENT &amp; Café</p><script>steal()</script><img src="https://never-visit.test/x">')
    assert "urgent & café" in result
    assert "steal" not in result and "never-visit" not in result
    assert len(normalize_email_text("A" * 100_000)) <= EMAIL_MAX_CHARS
    assert len(normalize_url_text("https://example.test/" + "x" * 100_000)) <= URL_MAX_CHARS


def test_passive_url_features_never_access_network(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("ML preprocessing must remain offline")
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    vector = url_lexical_vector("http://user:pass@127.0.0.1/path?x=1")
    assert len(vector) == 22
    assert vector[15] == 1 and vector[16] == 1
    transformed = UrlLexicalTransformer().fit_transform(["https://localhost/", "http://169.254.169.254/"])
    assert transformed.shape == (2, 22)
    assert np.isfinite(transformed.toarray()).all()


def test_exact_duplicate_conflicts_quarantined_and_sample_deterministic(tmp_path):
    path = tmp_path / "rows.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["text", "label", "source"])
        writer.writeheader()
        writer.writerows([
            {"text": "Ordinary team meeting", "label": 0, "source": "test"},
            {"text": " ORDINARY  team meeting ", "label": 1, "source": "test"},
            {"text": "Independent benign example", "label": 0, "source": "test"},
            {"text": "Other distinct credential example", "label": 1, "source": "test"},
        ])
    rows, stats = load_rows(path, "email", max_rows=100)
    assert len(rows) == 2
    assert stats["conflicting_exact_groups_quarantined"] == 1
    again, _ = load_rows(path, "email", max_rows=100)
    assert [r.identifier for r in rows] == [r.identifier for r in again]


def test_email_loader_preserves_header_body_boundary_for_heuristics(tmp_path):
    path = tmp_path / "raw.csv"
    raw = "Subject: Preserve header boundary\n\nActual body https://example.test/path"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerow({"text": raw, "label": 0})
    rows, _ = load_rows(path, "email")
    assert rows[0].text == raw


def test_hostname_feature_policy_excludes_known_scheme_path_shortcuts():
    variants = ["http://same.example.test/a", "https://same.example.test/", "https://same.example.test/" + "long-path/" * 50 + "?query=abc"]
    assert len({hostname_text(v) for v in variants}) == 1
    features = UrlLexicalTransformer(policy="hostname").fit_transform(variants).toarray()
    assert features.shape == (3, 10)
    assert np.allclose(features, features[0])
    counterfactual = url_counterfactuals(variants)
    assert set(counterfactual) == {"forced_https", "forced_http", "benign_long_path_query"}
    for urls in counterfactual.values():
        assert all(hostname_text(v) == "same.example.test" for v in urls)


def test_source_provenance_requires_explicit_review(tmp_path):
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps({"source_url": "https://official.example.test", "license": "CC BY 4.0", "permission_basis": "fixture", "collection_notes": "unit test"}))
    with pytest.raises(ValueError, match="approved_for_training"):
        load_provenance(path)
    data = json.loads(path.read_text())
    data["approved_for_training"] = True
    path.write_text(json.dumps(data))
    assert load_provenance(path)["license"] == "CC BY 4.0"


def test_approved_provenance_binds_csv_task_hash_and_language_scope(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text("text,label\nfixture sample,0\n", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    provenance = {"task": "email", "prepared": {"sha256": digest}, "supported_languages": ["es"], "validation_scope": "Spanish unit fixture"}
    assert verify_dataset_identity(path, provenance, "email") == digest
    with pytest.raises(ValueError, match="task"):
        verify_dataset_identity(path, provenance, "url")
    with pytest.raises(ValueError, match="supported_languages"):
        verify_dataset_identity(path, {**provenance, "supported_languages": []}, "email")
    path.write_text("text,label\nchanged input,1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        verify_dataset_identity(path, provenance, "email")


@pytest.mark.parametrize("raw_coefficient,slope,excluded", [(1.0, 1.0, False), (-1.0, 1.0, True), (-1.0, -1.0, True), (1.0, 0.0, True)])
def test_hybrid_monotonicity_includes_final_calibration(raw_coefficient, slope, excluded):
    hybrid = SimpleNamespace(estimator=SimpleNamespace(coef_=np.asarray([[1., raw_coefficient]])), calibrator=SimpleNamespace(coef_=np.asarray([[slope]])))
    assert bool(hybrid_selection_exclusions("email", hybrid)) is excluded
    assert hybrid_selection_exclusions("url", hybrid)


def test_lexical_near_duplicates_grouped_before_splitting():
    tokens = [f"word{chr(97 + i // 26)}{chr(97 + i % 26)}" for i in range(150)]
    first = " ".join(tokens)
    second = " ".join(tokens[:-1] + ["replacement"])
    unrelated = "independent discussion about garden colors and autumn landscapes"
    a, b = shingles(first, "email"), shingles(second, "email")
    assert len(a & b) / len(a | b) >= .9
    groups, audit = build_groups([fixture_row(first), fixture_row(second), fixture_row(unrelated)], "email")
    assert groups[0] == groups[1] and groups[0] != groups[2]
    assert audit["near_duplicate_pairs"] == 1


def test_near_duplicate_audit_matches_bruteforce_on_small_fixture():
    base = " ".join(f"token{chr(97 + i // 26)}{chr(97 + i % 26)}" for i in range(80))
    samples = [base, base.replace("tokenaa", "changed"), base + " appendix", "entirely unrelated fixture message about weather"]
    rows = [fixture_row(s) for s in samples]
    groups, _ = build_groups(rows, "email")
    for i, row in enumerate(rows):
        for j in range(i):
            a, b = shingles(row.text, "email"), shingles(rows[j].text, "email")
            if len(a & b) / len(a | b) >= .9:
                assert groups[i] == groups[j]


def test_near_duplicate_comparison_limit_fails_closed():
    rows = [fixture_row("same long message repeated for deterministic unit testing " + str(i)) for i in range(5)]
    with pytest.raises(ValueError, match="comparison bound"):
        build_groups(rows, "email", max_comparisons=1)


def test_explicit_global_campaign_constraints_span_sources():
    rows = [fixture_row("historic phishing body template", source="mailbox-old", group="global:campaign-1"), fixture_row("recent altered campaign wording", source="mailbox-new", group="global:campaign-1"), fixture_row("independent routine discussion", source="mailbox-third", group="local-1"), fixture_row("another ordinary project note", source="mailbox-fourth", group="local-1")]
    groups, _ = build_groups(rows, "email")
    assert groups[0] == groups[1]
    assert groups[2] != groups[3]


def test_url_groups_use_offline_registered_and_private_domains(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("PSL must come from the offline package snapshot")
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    rows = [fixture_row("https://one.example.co.uk/path"), fixture_row("http://two.example.co.uk/other"), fixture_row("https://independent.co.uk/")]
    groups, audit = build_groups(rows, "url")
    assert groups[0] == groups[1] and groups[0] != groups[2]
    assert audit["url_registered_domain_groups"] == 2


def test_grouped_partitions_are_deterministic_and_disjoint():
    labels = np.asarray([i % 2 for i in range(200)])
    groups = np.asarray([f"independent-{i}" for i in range(200)])
    a = grouped_partitions(labels, groups)
    b = grouped_partitions(labels, groups)
    seen = set()
    for name, indexes in a.items():
        assert np.array_equal(indexes, b[name])
        assert not seen & set(groups[indexes])
        seen.update(groups[indexes])
        assert set(labels[indexes]) == {0, 1}
    assert len(seen) == len(groups)


def test_insufficient_independent_groups_rejected():
    with pytest.raises(ValueError, match="independent groups"):
        grouped_partitions(np.asarray([0, 1] * 10), np.asarray(["all-one-campaign"] * 20))


@pytest.mark.parametrize("kind", ["email", "url"])
@pytest.mark.parametrize("algorithm", ["logistic_regression", "linear_svm"])
def test_real_estimators_and_calibration_serialize(tmp_path, kind, algorithm):
    # Tiny algorithm fixtures verify execution/serialization only. Their metrics
    # are never presented as scientific performance or shipped app artifacts.
    negatives = ["ordinary meeting agenda project update fixture" + str(i) if kind == "email" else f"https://project{i}.test/agenda" for i in range(12)]
    positives = ["urgent account password credential verification fixture" + str(i) if kind == "email" else f"http://credential-user{i}@192.0.2.20/login" for i in range(12)]
    X, y = negatives + positives, np.asarray([0] * 12 + [1] * 12)
    model = build_estimator(kind, algorithm, max_features=500)
    model.fit(X, y)
    calibrated = TrainedClassifier(model, fit_sigmoid(model.decision_function(X), y, 12))
    path = tmp_path / "fixture.joblib"
    joblib.dump(calibrated, path)
    loaded = joblib.load(path)
    p = loaded.predict_proba([negatives[0], positives[0]])
    assert p.shape == (2, 2) and np.isfinite(p).all()
    assert np.allclose(p.sum(axis=1), 1)
    assert loaded.classes_.tolist() == [0, 1]


def test_evaluation_reports_both_classes_and_real_confusion_counts():
    metrics = evaluate([0, 0, 1, 1], [.1, .8, .4, .9], .5)
    assert metrics["confusion_matrix"] == [[1, 1], [1, 1]]
    assert metrics["accuracy"] == .5
    assert metrics["false_positives"] == 1 and metrics["false_negatives"] == 1
    assert metrics["false_positive_rate"] == .5
    assert metrics["false_negative_rate"] == .5
    assert metrics["log_loss"] > 0
    assert metrics["legitimate_recall"] == .5
    assert 0 <= metrics["roc_auc"] <= 1
    assert evaluate([0, 1], [.1, .9], calibrated=False)["brier_score"] is None


def test_hybrid_features_logit_and_rule_points_are_distinct():
    values = hybrid_features([0, .5, 1], [-10, 50, 200])
    assert np.isfinite(values).all()
    assert values[:, 1].tolist() == [0, .5, 1]
    assert values[1, 0] == 0


def test_calibration_bins_include_probability_one_and_threshold_is_bounded():
    error, bins = expected_calibration_error([0, 1], [0, 1])
    assert error == 0 and sum(b["n"] for b in bins) == 2
    threshold = operating_threshold([0, 0, 1, 1], [.1, .2, .3, .4])
    assert .1 <= threshold <= .9
