"""Publish the frozen external evaluation's limitations; never refit or rescore.

Only release metadata in the English manifest changes. Weights, thresholds,
training metrics, split membership and the original evaluation stay untouched.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation", type=Path, default=ROOT / "docs/ml/phase4/external-evaluation.json")
    args = parser.parse_args()
    directory = ROOT / "backend/models/email_en"
    manifest_path = directory / "manifest.json"
    evaluation_path = args.evaluation.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    assert manifest["version"] == evaluation["model_version"]
    artifact_hash = hashlib.sha256((directory / "model.joblib").read_bytes()).hexdigest()
    assert artifact_hash == manifest["sha256"]
    result = evaluation["external_holdout"]["raw_frozen_english_model_all_rows"]
    recall, brier = result["recall"], result["brier_score"]
    warning = (f"Limited English research model: frozen external phishing recall was {recall:.1%} "
               f"and Brier score {brier:.3f}. Historical-corpus calibration did not transfer to newer email. "
               "A legitimate prediction must not be treated as safety; review heuristic evidence.")
    metadata = manifest["metadata"]
    metadata["prediction_warning"] = warning
    metadata["probability_scope"] = "Historical English corpus only; weak external calibration"
    metadata["release_evaluation"] = {
        "path": str(evaluation_path.relative_to(ROOT)).replace("\\", "/"),
        "sha256": hashlib.sha256(evaluation_path.read_bytes()).hexdigest(),
        "model_sha256": artifact_hash,
        "internal_gate_passed": True,
        "external_calibration_validated": False,
        "external_recall": recall, "external_brier_score": brier,
        "note": "Post-evaluation disclosure only. No model, threshold, heuristic score, split, or calibration fitting changed after external evaluation.",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(warning)


if __name__ == "__main__":
    main()
