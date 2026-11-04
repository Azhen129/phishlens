"""Preparation invariants; synthetic fixtures are never evaluation data."""
import pytest

from scripts.prepare_english_dataset import (
    deduplicate, global_groups, has_subject_annotation, separate_external,
)


def example(subject, body, label=0, source="main", external=False):
    return {"text": "Subject: " + subject + "\n\n" + body, "label": label,
            "source": source, "group": "", "row_id": subject, "date": "",
            "language": "en", "external": external}


@pytest.mark.parametrize("subject", ["[spam] Invoice", "Re: [PHISH] account", "[ phishing ] Notice"])
def test_acquisition_subject_annotations_quarantined(subject):
    assert has_subject_annotation("Subject: " + subject + "\n\nordinary body")


@pytest.mark.parametrize("body", ["We discuss [spam] filtering.", "Forwarded subject: [phish] investigation."])
def test_annotation_rule_preserves_security_evidence_in_body(body):
    assert not has_subject_annotation("Subject: Security discussion\n\n" + body)


def test_conflicting_canonical_labels_are_quarantined_not_majority_voted():
    rows = [example("Conflict", "Identical source email.", 0),
            example("Conflict", "Identical source email.", 1),
            example("Conflict", "Identical source email.", 1)]
    retained, audit = deduplicate(rows)
    assert retained == []
    assert audit["conflicting_canonical_groups_quarantined"] == 1
    assert audit["conflicting_rows_quarantined"] == 3


def test_exact_external_copy_cannot_reenter_main():
    rows = [example("Duplicate", "Same real message text.", 0, "main"),
            example("Duplicate", "Same real message text.", 0, "holdout", True)]
    retained, audit = deduplicate(rows)
    assert len(retained) == 1 and retained[0]["external"]
    assert retained[0]["source"] == "holdout"
    assert audit["main_copies_touching_exact_external"] == 1


def test_transitive_cross_source_campaign_touching_external_is_fully_purged():
    copied_body = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau"
    rows = [
        example("Different historical title", copied_body, 1, "old-inbox"),
        example("Global linked subject", copied_body, 1, "new-inbox", True),
        example("RE: Global linked subject", "A different reply body containing details unrelated to the earlier template.", 0, "other-corpus"),
        example("Unrelated legitimate meeting", "Please attend our quarterly planning discussion about staffing schedules and office renovation.", 0, "ham"),
        example("Unrelated malicious notice", "Credentials overdue authenticate access immediately using the provided fraudulent account destination.", 1, "old-inbox"),
    ]
    retained, _ = deduplicate(rows)
    groups, _ = global_groups(retained, max_comparisons=10_000)
    main, external, excluded, candidates = separate_external(retained, groups, 100)
    assert len(external) == 1 and len(excluded) == 2
    assert len(main) == len(candidates) == 2
    assert {r["source"] for r in excluded} == {"old-inbox", "other-corpus"}
    assert all(r["group"].startswith("global:") for r in [*main, *external, *excluded])
    assert not ({r["group"] for r in main} & {r["group"] for r in external})
