"""Phase 6 format-cleanup wrapper around the frozen Phase 5 routing policy.

Only the prepared language representation changes: six invisible format
characters are removed. Thresholds, all-97-language identification, substantial
mixed-language policy, bounds, and explicit fallbacks remain the same as v2.
The v2 module itself remains untouched for archived comparisons.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Callable

from . import language_routing_v2 as previous
from .text_normalization_v6 import remove_format_obfuscators

ROUTING_VERSION = "language-format-v3"


def prepare_language_text(value: str) -> str:
    # Prepare exactly once: repeated HTML unescaping/normalization can alter
    # literal escaped markup even when no invisible characters are present.
    return " ".join(remove_format_obfuscators(previous.prepare_language_text(value)).split())


def route_email_language(text: str, classify: Callable[[str], tuple[str, float]]) -> dict:
    note = (
        "Offline language applicability uses all 97 languages and the preserved "
        "Phase 5 bounds and mixed-language policy. Six invisible format characters "
        "are removed from inert text. No script or homoglyph transliteration is "
        "used. Obfuscation and language identification can still cause errors."
    )
    result = {
        "detected_language": "und",
        "language_routing_status": "uncertain",
        "language_routing_version": ROUTING_VERSION,
        "language_routing_limitation": note,
    }
    try:
        cleaned = prepare_language_text(text)
        if previous.letter_count(cleaned) < previous.MIN_LETTERS or len(cleaned.split()) < previous.MIN_WORDS:
            return {**result, "language_routing_status": "too_short", "reason": "Insufficient meaningful email text for language applicability. No ML prediction was produced; heuristic analysis remains available."}
        language, score = classify(cleaned)
        if not math.isfinite(float(score)) or score < .90:
            return {**result, "reason": "Email language identification is uncertain. No language-specific ML prediction was produced; heuristic analysis remains available."}
        if language not in {"en", "es"}:
            return {**result, "detected_language": language, "language_routing_status": "unsupported", "reason": f"Detected language '{language}' is outside the English/Spanish model scopes. No ML prediction was produced; heuristic analysis remains available."}
        totals, words_by_language = Counter(), Counter()
        windows = previous.language_windows(cleaned)
        considered_letters = sum(previous.letter_count(window) for window in windows)
        for window in windows:
            observed, internal_score = classify(window)
            if math.isfinite(float(internal_score)) and internal_score >= .95:
                totals[observed] += previous.letter_count(window)
                words_by_language[observed] += len(window.split())
        for other, count in totals.items():
            if other != language and count >= previous.MIXED_LETTERS and words_by_language[other] >= previous.MIXED_WORDS and count / max(considered_letters, 1) >= previous.MIXED_SHARE:
                return {**result, "detected_language": "mixed", "language_routing_status": "mixed", "reason": "Substantial meaningful email sections were identified as different languages. Mixed-language inputs use heuristic fallback; no language-specific ML prediction was produced."}
        return {**result, "detected_language": language, "language_routing_status": "supported", "reason": "Input routed to its language-specific classifier; language applicability does not establish that the input resembles training data."}
    except Exception:
        return {**result, "reason": "Email language identification is unavailable. No ML prediction was produced; heuristic analysis remains available."}
