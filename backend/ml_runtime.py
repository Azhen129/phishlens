"""Local, fail-closed loading and bounded inference for validated PhishLens models.

Only project-owned artifacts are accepted.  Joblib is never used on an upload,
URL, or user-selected path.  A checksum detects corruption, not a malicious
administrator replacing both a trusted artifact and its manifest.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from pathlib import Path
from typing import Any

MODEL_ROOT = Path(__file__).resolve().parent / "models"
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_EMAIL_CHARACTERS = 16000
MAX_URL_CHARACTERS = 8192
MODEL_SPECS = {
    "email": ("email", "Spanish email classifier", ["es"]),
    "email_en": ("email", "English email classifier", ["en"]),
    "url": ("url", "Hostname URL classifier", []),
}
_cache: dict[str, tuple[tuple, dict | None, str]] = {}
_lock = threading.RLock()
_language_identifier = None


def clear_cache() -> None:
    """Used by tests and an explicit process restart, never an upload endpoint."""
    with _lock:
        _cache.clear()


def _json_file(path: Path, limit: int = 2 * 1024 * 1024) -> dict:
    if path.stat().st_size > limit:
        raise ValueError("Model metadata exceeds the local size bound.")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Model metadata must be an object.")
    return result


def _stamp(directory: Path) -> tuple:
    entries = [str(directory.resolve())]
    for name in ("manifest.json", "model.joblib", "metrics.json", "admission.json"):
        try:
            stat = (directory / name).stat()
            entries.append((stat.st_mtime_ns, stat.st_size))
        except OSError:
            entries.append(None)
    for path in (Path(__file__).with_name(name) for name in ("ml_features.py", "ml_features_v3.py", "text_normalization_v6.py")):
        try:
            stat = path.stat()
            entries.append((str(path), stat.st_mtime_ns, stat.st_size))
        except OSError:
            entries.append(None)
    return tuple(entries)


def _model_directory(kind: str) -> Path:
    """Only a reviewed versioned English subdirectory may be selected."""
    directory = MODEL_ROOT / kind
    config_path = MODEL_ROOT / "active-models.json"
    if kind == "email_en" and config_path.exists():
        if not config_path.resolve().is_relative_to(MODEL_ROOT.resolve()):
            raise ValueError("Active configuration is outside the trusted root.")
        config = _json_file(config_path, limit=16 * 1024)
        if set(config) != {"email_en"}:
            raise ValueError("Unsupported active model configuration.")
        selected = config.get("email_en")
        if not isinstance(selected, str) or not re.fullmatch(r"(?:email_en_v5/email-multiscale-v3|email_en_v6/email-source-text-v6)-[a-f0-9]{12}", selected):
            raise ValueError("Unsupported English model selection.")
        directory = MODEL_ROOT / selected
    if not directory.resolve().is_relative_to(MODEL_ROOT.resolve()):
        raise ValueError("Model directory is outside its trusted root.")
    return directory


def _threshold(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("Invalid classification threshold.")
    value = float(value)
    if not math.isfinite(value) or not 0 < value < 1:
        raise ValueError("Invalid classification threshold.")
    return value


def _load(kind: str, *, use_active: bool = True) -> tuple[dict | None, str]:
    if kind not in MODEL_SPECS:
        return None, "Unsupported model kind; heuristic analysis remains available."
    expected_kind, model_name, expected_languages = MODEL_SPECS[kind]
    try:
        # Only offline audit code opts out of activation to reproduce a fixed
        # original baseline. Runtime callers always use the default selection.
        directory = _model_directory(kind) if use_active else MODEL_ROOT / kind
    except (OSError, ValueError, TypeError):
        return None, "The selected local model configuration is invalid; heuristic analysis remains available."
    stamp = _stamp(directory)
    with _lock:
        cached = _cache.get(kind)
        if cached and cached[0] == stamp:
            return cached[1], cached[2]
        bundle, reason = None, "Validated local model is unavailable; heuristic analysis remains available."
        try:
            root = MODEL_ROOT.resolve()
            if not directory.resolve().is_relative_to(root):
                raise ValueError("Model directory is outside the configured root.")
            manifest = _json_file(directory / "manifest.json")
            if manifest.get("format_version") != 1 or manifest.get("kind") != expected_kind:
                raise ValueError("Unsupported model manifest.")
            if manifest.get("artifact") != "model.joblib" or manifest.get("metrics_file") != "metrics.json":
                raise ValueError("Unsupported artifact path.")
            metadata = manifest.get("metadata")
            if manifest.get("validated") is not True or not isinstance(metadata, dict):
                raise ValueError("The local model has not passed validation.")
            if metadata.get("calibrated") is not True or metadata.get("validation_passed") is not True:
                raise ValueError("Calibration and validation evidence is required.")
            if expected_kind == "email" and metadata.get("supported_languages") != expected_languages:
                raise ValueError("The email artifact does not match this classifier's evaluated language scope.")
            version = manifest.get("version")
            if not isinstance(version, str) or not 1 <= len(version) <= 120:
                raise ValueError("Invalid model version.")
            if directory.parent.name in {"email_en_v5", "email_en_v6"} and version != directory.name:
                raise ValueError("Selected version directory and manifest differ.")
            artifact = directory / "model.joblib"
            metrics = directory / "metrics.json"
            if not artifact.resolve().is_relative_to(directory.resolve()) or not metrics.resolve().is_relative_to(directory.resolve()):
                raise ValueError("Artifacts may not resolve outside their model directory.")
            if not 0 < artifact.stat().st_size <= MAX_ARTIFACT_BYTES:
                raise ValueError("Model artifact exceeds the local size bound.")
            # Full held-out ROC/PR curves can exceed the small manifest bound.
            # They are trusted local evaluation data, still capped independently.
            evaluation = _json_file(metrics, limit=16 * 1024 * 1024)
            if evaluation.get('kind') != expected_kind or evaluation.get('version') != version or evaluation.get('deployment_gate', {}).get('passed') is not True:
                raise ValueError('Evaluation evidence does not match the validated model.')
            expected_hash = manifest.get("sha256")
            if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                raise ValueError("Artifact integrity information is missing.")
            digest = hashlib.sha256()
            with artifact.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != expected_hash:
                raise ValueError("Model checksum does not match its manifest.")
            admission = None
            if version.startswith("email-source-text-v6-"):
                admission_path = directory / "admission.json"
                if not admission_path.resolve().is_relative_to(directory.resolve()):
                    raise ValueError("Admission metadata is outside its model directory.")
                admission = _json_file(admission_path, limit=16 * 1024)
                if (admission.get("format_version") != 1
                    or admission.get("version") != version
                    or admission.get("model_sha256") != expected_hash
                    or admission.get("approved_for_limited_use") is not True
                    or metadata.get("independent_admission_passed") is not True):
                    raise ValueError("The Phase 6 model requires hash-bound limited-use admission.")
            # Optional dependencies stay inside this guarded path. A rules-only
            # installation must still start if sklearn/joblib are unavailable.
            import joblib
            import sklearn
            from .ml_features import FEATURE_VERSION
            if manifest.get("sklearn_version") != sklearn.__version__:
                raise ValueError("The model and installed scikit-learn versions differ.")
            if metadata.get("feature_version") != FEATURE_VERSION:
                raise ValueError("The model preprocessing version is incompatible.")
            expected_feature_hash = metadata.get("feature_code_sha256")
            if expected_feature_hash and expected_feature_hash != hashlib.sha256((Path(__file__).resolve().parent / "ml_features.py").read_bytes()).hexdigest():
                raise ValueError("The model preprocessing code changed after training.")
            additional = metadata.get("additional_code_sha256", {})
            if not isinstance(additional, dict) or not set(additional).issubset({"ml_features_v3.py", "text_normalization_v6.py"}):
                raise ValueError("Unsupported additional model code identity.")
            if version.startswith("email-multiscale-v3-") and set(additional) != {"ml_features_v3.py"}:
                raise ValueError("The multiscale model requires its exact feature code identity.")
            if admission is not None and set(additional) != {"text_normalization_v6.py"}:
                raise ValueError("The source-controlled model requires its exact normalization identity.")
            for filename, expected in additional.items():
                if not isinstance(expected, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
                    raise ValueError("Invalid additional preprocessing checksum.")
                path = Path(__file__).resolve().parent / filename
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected.lower():
                    raise ValueError("Additional model preprocessing changed after training.")
            loaded = joblib.load(artifact)
            if not isinstance(loaded, dict) or loaded.get("format_version") != 1 or loaded.get("kind") != expected_kind or loaded.get("version") != version:
                raise ValueError("Model bundle does not match its manifest.")
            if not callable(getattr(loaded.get("model"), "predict_proba", None)):
                raise ValueError("A calibrated probability estimator is required.")
            if list(getattr(loaded["model"], "classes_", [])) != [0, 1]:
                raise ValueError("The model class mapping is incompatible.")
            threshold = _threshold(loaded.get("threshold"))
            if admission is not None and _threshold(admission.get("threshold")) != threshold:
                raise ValueError("The local classifier threshold differs from its limited-use admission.")
            if loaded.get("hybrid_model") is not None:
                if not callable(getattr(loaded["hybrid_model"], "predict_proba", None)):
                    raise ValueError("Invalid hybrid estimator.")
                _threshold(loaded.get("hybrid_threshold"))
            loaded["metadata"] = metadata
            loaded["artifact_sha256"] = expected_hash
            loaded["model_key"] = kind
            loaded["model_name"] = model_name
            bundle, reason = loaded, "Local archive classifier loaded. Review its documented scope."
        except FileNotFoundError:
            reason = "Trained local model files are missing; heuristic analysis remains available."
        except (ImportError, OSError, ValueError, TypeError, KeyError, AttributeError, EOFError, RuntimeError):
            # No submitted text, pickle internals, filesystem paths or traceback
            # are returned to the browser on a load failure.
            reason = "Local model is missing, corrupted, unvalidated or incompatible; heuristic analysis remains available."
        except Exception:
            # A damaged trusted pickle can raise additional decoder exceptions.
            # The pre-existing passive analysis must remain usable.
            reason = "Local model could not be loaded safely; heuristic analysis remains available."
        _cache[kind] = (stamp, bundle, reason)
        return bundle, reason


def _public_metadata(bundle: dict) -> dict:
    metadata = bundle["metadata"]
    # Publication notes update the scope disclosure, not preserved baseline
    # weights/manifests or stored historical records. Bind notes to both model
    # version and artifact hash; malformed optional notes retain archive text.
    release = {}
    try:
        notes = _json_file(MODEL_ROOT / "release-notes.json", limit=64 * 1024)
        entry = notes.get("models", {}).get(bundle["version"], {})
        if notes.get("format_version") == 1 and entry.get("artifact_sha256") == bundle["artifact_sha256"]:
            release = entry
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    limitations = metadata.get("limitations", [])
    if not isinstance(limitations, list):
        limitations = [str(limitations)]
    return {
        "model_version": bundle["version"],
        "model_key": bundle.get("model_key"),
        "model_name": bundle.get("model_name"),
        "classifier_decision": "Experimental" if bundle.get("model_key") == "email_en" and metadata.get("independent_admission_passed") is not True else "Approved for limited use",
        "calibrated": True,
        "probability_validated_for_deployment": False,
        "score_type": "archive_calibrated_decision_score",
        "limitations": [str(value)[:2000] for value in limitations[:20]],
        "dataset": metadata.get("dataset", metadata.get("dataset_name", "See model provenance documentation.")),
        "validation_scope": metadata.get("validation_scope", "Held-out dataset evaluation; deployment prevalence and new campaigns can differ."),
        "artifact_sha256": bundle["artifact_sha256"],
        "supported_languages": metadata.get("supported_languages", []),
        "dataset_source": str(metadata.get("dataset_source", "See model provenance documentation."))[:2000],
        "dataset_license": str(metadata.get("dataset_license", "See model provenance documentation."))[:500],
        "calibration_method": str(metadata.get("calibration", "See held-out calibration documentation."))[:1000],
        "prediction_warning": str(release.get("prediction_warning", metadata.get("prediction_warning", "")))[:2000],
        "probability_scope": str(release.get("probability_scope", metadata.get("probability_scope", "Documented calibration corpus only")))[:500],
    }


def model_status() -> dict:
    result = {}
    for kind in MODEL_SPECS:
        bundle, reason = _load(kind)
        result[kind] = {"available": bundle is not None, "reason": reason, "model_key": kind, "model_name": MODEL_SPECS[kind][1], "supported_languages": MODEL_SPECS[kind][2]}
        if bundle:
            result[kind].update(_public_metadata(bundle))
    return result


def _probability(estimator: Any, values: Any) -> float:
    classes = list(estimator.classes_)
    if classes != [0, 1]:
        raise ValueError("Unsupported model class mapping.")
    prediction = estimator.predict_proba(values)
    if len(prediction) != 1 or len(prediction[0]) != 2:
        raise ValueError("Invalid prediction shape.")
    probability = float(prediction[0][1])
    if not math.isfinite(probability) or not 0 <= probability <= 1:
        raise ValueError("Invalid predicted probability.")
    return probability


def _classify_language(text: str) -> tuple[str, float]:
    global _language_identifier
    if _language_identifier is None:
        from langid.langid import LanguageIdentifier, model
        with _lock:
            if _language_identifier is None:
                # Keep all 97 languages: constraining this identifier to en/es
                # would force unsupported languages into a supported route.
                _language_identifier = LanguageIdentifier.from_modelstring(model, norm_probs=True)
    language, score = _language_identifier.classify(text)
    return str(language), float(score)


def _meaningful_language_text(text: str) -> bool:
    return len(re.findall(r"[^\W\d_]", text, re.UNICODE)) >= 40 and len(text.split()) >= 8


def _phase4_email_language_route(text: str) -> dict:
    """Conservative applicability gate; identifier scores are never probabilities.

    Require 40 letters, 8 words, and an internal langid score >= .90. Check
    at most 12 meaningful paragraph/sentence/48-word windows, sampled across
    the bounded input, as well as the full text. Any high-scoring conflicting
    meaningful chunk causes mixed-language abstention. Short brand names and
    signatures cannot alone create a conflicting chunk. This gate is imperfect
    language identification, not evidence of phishing or calibrated confidence.
    """
    gate_note = "Language applicability uses all langid languages and up to 12 meaningful chunks of the first 16,000 characters; short, uncertain, mixed, or unsupported text uses heuristic fallback. Language identification is imperfect."
    cleaned = re.sub(r"(?:https?://|www\.)\S+|[\w.+-]+@[\w.-]+", " ", str(text)[:MAX_EMAIL_CHARACTERS], flags=re.I)
    cleaned = re.sub(r"(?im)^(?:subject|from|to|cc|date|reply-to):\s*", "", cleaned).strip()
    result = {"detected_language": "und", "language_routing_status": "uncertain", "language_routing_limitation": gate_note}
    if not _meaningful_language_text(cleaned):
        return {**result, "language_routing_status": "too_short", "reason": "Email language could not be established from sufficient text (at least 40 letters and 8 words). No ML phishing probability was produced; heuristic analysis remains available."}
    try:
        language, score = _classify_language(cleaned)
        if not math.isfinite(score) or score < .90:
            return {**result, "reason": "Email language identification is uncertain. No language-specific ML phishing probability was produced; heuristic analysis remains available."}
        # Paragraphs and sentences detect meaningful bilingual sections; word
        # windows also catch language changes inside a single long sentence.
        pieces = re.split(r"\n\s*\n|(?<=[.!?。؟])\s+", cleaned)
        words = cleaned.split()
        if len(words) > 48:
            pieces.extend(" ".join(words[start:start + 48]) for start in range(0, len(words), 32))
        pieces = list(dict.fromkeys(piece.strip() for piece in pieces if _meaningful_language_text(piece)))
        if len(pieces) > 12:
            pieces = [pieces[round(index * (len(pieces) - 1) / 11)] for index in range(12)]
        for piece in pieces:
            chunk_language, chunk_score = _classify_language(piece)
            if math.isfinite(chunk_score) and chunk_score >= .90 and chunk_language != language:
                return {**result, "detected_language": "mixed", "language_routing_status": "mixed", "reason": "Meaningful email sections were identified as different languages. Mixed-language inputs are outside the validated classifier scope; no ML phishing probability was produced and heuristic analysis was retained."}
        if language not in {"en", "es"}:
            return {**result, "detected_language": language, "language_routing_status": "unsupported", "reason": f"Detected email language '{language}' is outside the validated English and Spanish classifier scopes. No ML phishing probability was produced; heuristic analysis remains available."}
        return {**result, "detected_language": language, "language_routing_status": "supported", "reason": "Input routed to its validated language-specific email classifier."}
    except Exception:
        return {**result, "reason": "Email language identification is unavailable. No language-specific ML phishing probability was produced; heuristic analysis remains available."}


def _email_language_route(text: str) -> dict:
    # The routing module keeps optional ML imports inside a guarded function.
    from .language_routing_v3 import route_email_language
    return route_email_language(text, _classify_language)


def _language_supported(text: str, metadata: dict) -> bool:
    """Retained for scope audits; uses the same gate as deployed routing."""
    supported = metadata.get("supported_languages", [])
    if not supported:
        return True
    if not isinstance(supported, list) or not all(isinstance(item, str) for item in supported):
        return False
    route = _email_language_route(text)
    return route["language_routing_status"] == "supported" and route["detected_language"] in supported


def assess(kind: str, text: str, heuristic_score: int, heuristic_risk: str) -> tuple[dict, dict]:
    """Return separate ML and final assessment objects without altering evidence."""
    fallback = {"method": "heuristic_fallback", "score": heuristic_score, "risk": heuristic_risk, "label": heuristic_risk + " heuristic risk", "limitations": ["Rule points are not a probability. Absence of indicators does not establish safety."]}
    bounded = str(text)[:MAX_EMAIL_CHARACTERS if kind == "email" else MAX_URL_CHARACTERS]
    route = {}
    model_key = kind
    if kind == "email":
        route = _email_language_route(bounded)
        if route["language_routing_status"] != "supported":
            return {"available": False, "model_loaded": False, **route}, fallback
        model_key = "email_en" if route["detected_language"] == "en" else "email"
    bundle, reason = _load(model_key)
    if bundle is None:
        return {"available": False, "model_loaded": False, **route, "model_key": model_key, "model_name": MODEL_SPECS.get(model_key, (None, None))[1], "supported_languages": MODEL_SPECS.get(model_key, (None, None, []))[2], "reason": reason}, fallback
    if kind == "email" and route["detected_language"] not in bundle["metadata"].get("supported_languages", []):
        return {"available": False, "model_loaded": True, **_public_metadata(bundle), **route, "reason": "The selected classifier does not cover the detected email language; no ML phishing probability was produced."}, fallback
    try:
        probability = _probability(bundle["model"], [bounded])
        threshold = _threshold(bundle["threshold"])
        ml = {"available": True, **_public_metadata(bundle), **route, "reason": reason, "classification": "Phishing" if probability >= threshold else "Legitimate", "phishing_probability": round(probability, 8), "decision_score": round(probability, 8), "classification_threshold": threshold, "input_truncated": len(str(text)) > len(bounded)}
        metadata = bundle["metadata"]
        mode = metadata.get("assessment_mode", "ml")
        final_probability = probability
        if mode == "hybrid":
            if bundle.get("hybrid_model") is None:
                raise ValueError("Selected hybrid estimator is missing.")
            clipped = min(1 - 1e-6, max(1e-6, probability))
            final_probability = _probability(bundle["hybrid_model"], [[math.log(clipped / (1 - clipped)), heuristic_score / 100]])
            threshold = _threshold(bundle["hybrid_threshold"])
        elif mode != "ml":
            raise ValueError("Unknown validated assessment mode.")
        assessment = {"method": "validated_hybrid" if mode == "hybrid" else "ml", "score": round(final_probability * 100), "score_is_probability_percent": False, "score_is_decision_percent": True, "probability_validated_for_deployment": False, "score_type": "archive_calibrated_decision_score", "decision_score": round(final_probability, 8), "risk": "High" if final_probability >= threshold else "Low", "label": "Phishing" if final_probability >= threshold else "Legitimate", "phishing_probability": round(final_probability, 8), "classification_threshold": threshold, "model_version": bundle["version"], "limitations": ml["limitations"] + ["This archive-calibrated decision score is not validated field probability or confidence. Legacy probability fields are retained for saved-result compatibility.", "A legitimate prediction does not verify safety. Heuristic observations remain separate and should still be reviewed."]}
        return ml, assessment
    except Exception:
        return {"available": False, **route, "model_key": model_key, "reason": "Local model inference failed; the existing heuristic analysis was retained."}, fallback
