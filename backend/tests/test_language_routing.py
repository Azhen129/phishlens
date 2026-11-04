"""Applicability and routing regression tests, not classifier accuracy claims.

Natural-language strings here exercise the independent routing contract. The
held-out real-data classifier results live in the trained artifact reports.
"""
import pytest

from backend import ml_runtime


ENGLISH_LEGITIMATE = (
    "Please review the attached agenda for our project meeting tomorrow. "
    "We will discuss progress and plan the next stage together."
)
ENGLISH_PHISHING = (
    "Your account will be suspended unless you verify your password immediately. "
    "Please confirm your account credentials now to prevent the loss of access."
)
SPANISH = (
    "Su cuenta requiere una verificación urgente. Confirme su contraseña para "
    "evitar la suspensión y revise los detalles de seguridad inmediatamente."
)
FRENCH = (
    "Veuillez trouver le compte rendu de notre réunion. Nous allons discuter des "
    "prochains travaux et organiser les projets de notre équipe."
)
ARABIC = (
    "يرجى مراجعة جدول أعمال اجتماع المشروع غدًا. سنناقش التقدم المحرز "
    "ونخطط للمرحلة التالية معًا خلال اجتماع فريق العمل."
)


@pytest.mark.parametrize("text,language", [
    (ENGLISH_LEGITIMATE, "en"), (ENGLISH_PHISHING, "en"), (SPANISH, "es"),
])
def test_supported_languages_use_actual_full_language_identifier(text, language):
    route = ml_runtime._email_language_route(text)
    assert route["language_routing_status"] == "supported"
    assert route["detected_language"] == language
    assert "confidence" not in route and "phishing_probability" not in route


@pytest.mark.parametrize("text,language", [(FRENCH, "fr"), (ARABIC, "ar")])
def test_other_languages_are_not_forced_into_english_or_spanish(text, language):
    route = ml_runtime._email_language_route(text)
    assert route["language_routing_status"] == "unsupported"
    assert route["detected_language"] == language
    ml, final = ml_runtime.assess("email", text, 23, "Low")
    assert not ml["available"]
    assert "phishing_probability" not in ml
    assert final["method"] == "heuristic_fallback"
    assert final["score"] == 23


@pytest.mark.parametrize("text", [
    ENGLISH_LEGITIMATE + "\n\n" + SPANISH,
    SPANISH + "\n\n" + ENGLISH_LEGITIMATE,
    (ENGLISH_LEGITIMATE.replace(".", "") + " ") * 4 + (SPANISH.replace(".", "") + " ") * 4,
])
def test_meaningful_mixed_language_sections_abstain(text):
    route = ml_runtime._email_language_route(text)
    assert route["language_routing_status"] == "mixed"
    assert route["detected_language"] == "mixed"
    ml, final = ml_runtime.assess("email", text, 47, "Medium")
    assert not ml["available"] and "phishing_probability" not in ml
    assert final["score"] == 47 and final["risk"] == "Medium"


def test_english_brand_word_does_not_make_spanish_message_mixed():
    route = ml_runtime._email_language_route(SPANISH + "\n\nMicrosoft Teams")
    assert route["language_routing_status"] == "supported"
    assert route["detected_language"] == "es"


@pytest.mark.parametrize("text", ["", "hello", "Microsoft Teams", "Verifique su cuenta"])
def test_short_inputs_do_not_receive_unjustified_language_predictions(text):
    route = ml_runtime._email_language_route(text)
    assert route["language_routing_status"] == "too_short"
    assert route["detected_language"] == "und"


def test_uncertain_identifier_score_is_used_only_for_abstention(monkeypatch):
    class UncertainIdentifier:
        def classify(self, text):
            return "en", .70
    monkeypatch.setattr(ml_runtime, "_language_identifier", UncertainIdentifier())
    ml, final = ml_runtime.assess("email", ENGLISH_LEGITIMATE, 15, "Low")
    assert ml["language_routing_status"] == "uncertain"
    assert not ml["available"] and "phishing_probability" not in ml
    assert not any("confidence" in key or "score" in key for key in ml)
    assert final["method"] == "heuristic_fallback"


def test_language_identifier_failure_preserves_rules(monkeypatch):
    def fail(text):
        raise RuntimeError("private identifier details")
    monkeypatch.setattr(ml_runtime, "_classify_language", fail)
    ml, final = ml_runtime.assess("email", ENGLISH_PHISHING, 42, "Medium")
    assert not ml["available"]
    assert "private" not in ml["reason"]
    assert final["score"] == 42


class ConstantEstimator:
    classes_ = [0, 1]

    def __init__(self, probability):
        self.probability = probability

    def predict_proba(self, values):
        return [[1 - self.probability, self.probability] for _ in values]


def bundle(key, language, probability):
    return {
        "model": ConstantEstimator(probability), "threshold": .5,
        "version": key + "-routing-unit-fixture", "model_key": key,
        "model_name": ml_runtime.MODEL_SPECS[key][1], "artifact_sha256": "0" * 64,
        "metadata": {"supported_languages": [language], "assessment_mode": "ml"},
    }


@pytest.mark.parametrize("text,key,language,probability", [
    (ENGLISH_PHISHING, "email_en", "en", .87),
    (ENGLISH_LEGITIMATE, "email_en", "en", .87),
    (SPANISH, "email", "es", .12),
])
def test_router_selects_correct_estimator_without_changing_heuristics(monkeypatch, text, key, language, probability):
    calls = []

    def load(selected):
        calls.append(selected)
        return bundle(selected, language, probability), "Unit routing estimator"

    monkeypatch.setattr(ml_runtime, "_load", load)
    ml, final = ml_runtime.assess("email", text, 23, "Low")
    assert calls == [key]
    assert ml["available"] and ml["model_key"] == key
    assert ml["detected_language"] == language
    assert ml["phishing_probability"] == probability
    assert final["method"] == "ml" and final["score"] == round(probability * 100)


def test_missing_english_model_never_uses_loaded_spanish_model(monkeypatch):
    calls = []

    def load(selected):
        calls.append(selected)
        return (bundle("email", "es", .99), "Spanish loaded") if selected == "email" else (None, "English model unavailable")

    monkeypatch.setattr(ml_runtime, "_load", load)
    ml, final = ml_runtime.assess("email", ENGLISH_PHISHING, 44, "Medium")
    assert calls == ["email_en"]
    assert ml["model_key"] == "email_en" and not ml["available"]
    assert "phishing_probability" not in ml
    assert final["score"] == 44 and final["method"] == "heuristic_fallback"


def test_wrong_language_scope_on_selected_bundle_abstains(monkeypatch):
    monkeypatch.setattr(ml_runtime, "_load", lambda selected: (bundle("email", "es", .99), "Wrong bundle"))
    ml, final = ml_runtime.assess("email", ENGLISH_PHISHING, 44, "Medium")
    assert not ml["available"] and "phishing_probability" not in ml
    assert final["score"] == 44


def test_status_exposes_three_distinct_classifiers_not_duplicate_aliases(monkeypatch):
    calls = []

    def load(selected):
        calls.append(selected)
        return None, "Unit status fixture"

    monkeypatch.setattr(ml_runtime, "_load", load)
    statuses = ml_runtime.model_status()
    assert calls == ["email", "email_en", "url"]
    assert set(statuses) == {"email", "email_en", "url"}
    assert statuses["email"]["supported_languages"] == ["es"]
    assert statuses["email_en"]["supported_languages"] == ["en"]


def test_url_inference_does_not_apply_email_language_gate(monkeypatch):
    def forbidden(text):
        raise AssertionError("URL inference must retain its own existing scope")
    monkeypatch.setattr(ml_runtime, "_email_language_route", forbidden)
    monkeypatch.setattr(ml_runtime, "_load", lambda selected: (bundle("url", "", .42), "URL fixture"))
    ml, final = ml_runtime.assess("url", "https://example.test", 5, "Low")
    assert ml["available"] and ml["model_key"] == "url"
    assert final["method"] == "ml"
