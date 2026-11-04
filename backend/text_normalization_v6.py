"""Bounded inert English experiment preprocessing, separate from old models.

No script, URL, attachment or network client is executed here. The narrow
format cleanup is also available to the language gate without importing ML
dependencies. Spanish letters and non-Latin scripts are never transliterated.
"""
from __future__ import annotations

import re

NORMALIZATION_VERSION = "english-format-address-v6"
MAX_CHARACTERS = 16_000
FORMAT_OBFUSCATORS = frozenset("\u00ad\u200b\u200c\u200d\u2060\ufeff")
_FORMAT_TRANSLATION = {ord(character): None for character in FORMAT_OBFUSCATORS}
_ADDRESS = re.compile(r"[\w.+-]{1,128}@[\w](?:[\w.-]{0,251}[\w])?", re.UNICODE)
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
ENTITY_NAMES = (
    "PGP", "EMOJI", "SYMBOL", "NAME", "USERNAME", "INITIALS",
    "EMAIL_ADDRESS", "PHONE_NUMBER", "ADDRESS", "ORGANIZATION", "URL",
    "IP_ADDRESS", "FILE_PATH", "FILE_NAME", "FILE", "DATE", "TIME",
    "FINANCIAL_INFO", "PRODUCT", "REFERENCE_NUMBER",
)
_ENTITY = re.compile(r"\[(" + "|".join(ENTITY_NAMES) + r")\]", re.IGNORECASE)


def _entity_replacement(match: re.Match) -> str:
    name = match.group(1).upper()
    return " urltoken " if name == "URL" else " emailtoken " if name == "EMAIL_ADDRESS" else " "


def _url_replacement(match: re.Match) -> str:
    # Preserve sentence punctuation just as it remains after an anonymized
    # [URL] marker. These characters are not inspected as a live destination.
    value = match.group(0)
    destination = value.rstrip(".,;:!?)]}")
    return " urltoken " + value[len(destination):]


def remove_format_obfuscators(value: str) -> str:
    """Remove only six known invisible format characters from bounded input."""
    return str(value)[:MAX_CHARACTERS].translate(_FORMAT_TRANSLATION)


def normalize_english_text(value: str) -> str:
    """Use inert text and source-neutral address tokens for a new English model.

    Explicit length/character-ratio features are not emitted. Known anonymized
    entity markers are harmonized for every source and inference input: URL and
    email markers share the literal-address tokens; other markers are removed.
    Actual submitted values remain available to the unchanged parser/rules.
    This representation is an experiment, not a proven obfuscation defense.
    """
    # Lazy import keeps rules-only startup independent of optional NumPy/sklearn.
    from .ml_features import normalize_email_text

    text = remove_format_obfuscators(normalize_email_text(str(value)))
    text = _ENTITY.sub(_entity_replacement, text)
    text = _URL.sub(_url_replacement, text)
    text = _ADDRESS.sub(" emailtoken ", text)
    return " ".join(text.split())[:MAX_CHARACTERS]
