"""Software/routing fixtures, never classifier accuracy or training ground truth."""
import socket

import pytest

from backend import language_routing_v2 as old
from backend.language_routing_v3 import prepare_language_text, route_email_language
from backend.ml_runtime import _classify_language
from backend.text_normalization_v6 import (
    ENTITY_NAMES,
    FORMAT_OBFUSCATORS,
    MAX_CHARACTERS,
    normalize_english_text,
    remove_format_obfuscators,
)

ENGLISH = "Please review the attached agenda for our project meeting tomorrow. We will discuss progress and plan the next stage together."
SPANISH = "Su cuenta requiere una verificación urgente. Confirme su contraseña para evitar la suspensión y revise los detalles de seguridad inmediatamente."
UNSUPPORTED = [
    ("fr", "Veuillez trouver le compte rendu de notre réunion. Nous allons discuter des prochains travaux et organiser les projets de notre équipe."),
    ("ru", "Пожалуйста, прочитайте отчет о нашей последней встрече. Завтра мы обсудим следующие шаги совместного проекта и рабочий график команды."),
    ("ar", "يرجى مراجعة جدول أعمال اجتماع المشروع غدًا. سنناقش التقدم المحرز ونخطط للمرحلة التالية معًا خلال اجتماع فريق العمل."),
]


def test_new_english_representation_is_inert_bounded_and_source_neutral(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Text preprocessing must not use network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    value = '<p>Pl\u200bease review https://one.example.test/account for ana@example.test.</p><script>executeThis()</script>'
    normalized = normalize_english_text(value)
    assert normalized == "please review urltoken for emailtoken ."
    assert "execute" not in normalized and "example" not in normalized
    assert normalize_english_text("a " * MAX_CHARACTERS) == "a " * (MAX_CHARACTERS // 2 - 1) + "a"
    assert len(normalize_english_text("x" * (MAX_CHARACTERS * 2))) <= MAX_CHARACTERS


def test_narrow_format_cleanup_preserves_accents_and_scripts():
    text = "verificación contraseña áéíóú ñ Пожалуйста العربية"
    obfuscated = "".join(character + "".join(FORMAT_OBFUSCATORS) for character in text)
    assert remove_format_obfuscators(obfuscated) == text
    assert normalize_english_text(text) == text.casefold()
    # A Cyrillic lookalike remains Cyrillic; the language gate cannot invent
    # English by mapping an unsupported script into Latin characters.
    assert remove_format_obfuscators("pаssword") == "pаssword"


def test_known_anonymization_markers_are_harmonized_for_every_input():
    anonymized = "Please contact [NAME] at [EMAIL_ADDRESS] and review [URL] on [DATE]."
    literal = "Please contact at ana@example.test and review https://example.test/update on ."
    assert normalize_english_text(anonymized) == normalize_english_text(literal)
    assert normalize_english_text(" ".join("[" + entity + "]" for entity in ENTITY_NAMES)) == "emailtoken urltoken"
    assert normalize_english_text("[name] [url] [email_address] [Unrecognized]") == "urltoken emailtoken [unrecognized]"


@pytest.mark.parametrize("punctuation", [".", ",", ";", ":", "!", "?", ")", "]", "}"])
def test_anonymization_does_not_create_a_sentence_punctuation_shortcut(punctuation):
    for literal, marker in (("https://example.test/update", "[URL]"), ("ana@example.test", "[EMAIL_ADDRESS]")):
        assert normalize_english_text("Please review " + literal + punctuation) == normalize_english_text("Please review " + marker + punctuation)


@pytest.mark.parametrize("text,language", [(ENGLISH, "en"), (SPANISH, "es"), *[(text, language) for language, text in UNSUPPORTED]])
def test_supported_and_unsupported_actual_language_paths_are_preserved(text, language):
    result = route_email_language(text, _classify_language)
    assert result["detected_language"] == language
    assert result["language_routing_status"] == ("supported" if language in {"en", "es"} else "unsupported")
    assert not any("confidence" in key or "probability" in key for key in result)


@pytest.mark.parametrize("character", sorted(FORMAT_OBFUSCATORS))
def test_format_obfuscated_english_recovers_without_transliteration(character):
    text = character.join(ENGLISH)
    result = route_email_language(text, _classify_language)
    assert result["language_routing_status"] == "supported"
    assert result["detected_language"] == "en"


def test_short_mixed_uncertain_and_failed_routes_keep_fallback():
    assert route_email_language("hello", _classify_language)["language_routing_status"] == "too_short"
    assert route_email_language(ENGLISH + "\n\n" + SPANISH, _classify_language)["language_routing_status"] == "mixed"
    assert route_email_language(ENGLISH, lambda value: ("en", float("nan")))["language_routing_status"] == "uncertain"
    assert route_email_language(ENGLISH, lambda value: ("en", .70))["language_routing_status"] == "uncertain"

    def failed(value):
        raise ValueError("private failure")

    result = route_email_language(ENGLISH, failed)
    assert result["language_routing_status"] == "uncertain"
    assert "private" not in result["reason"]


def test_format_cleanup_does_not_apply_html_normalization_twice():
    escaped_markup = "Literal &lt;script&gt;visible English documentation&lt;/script&gt;. " + ENGLISH
    assert prepare_language_text(escaped_markup) == old.prepare_language_text(escaped_markup)
    assert "visible english documentation" in prepare_language_text(escaped_markup)
