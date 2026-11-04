"""Bounded offline language applicability, independent from phishing scoring.

Full-text identification uses every langid language. Disjoint windows avoid
counting one confusing phrase repeatedly. A competing language must account
for a substantial amount of text before declaring an email mixed. Identifier
scores are private gate signals, never phishing probability or confidence.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Callable

ROUTING_VERSION = "language-proportion-v2"
MAX_CHARACTERS = 16000
MAX_WINDOWS = 12
WINDOW_WORDS = 32
MIN_LETTERS = 40
MIN_WORDS = 8
MIXED_SHARE = .20
MIXED_LETTERS = 80
MIXED_WORDS = 16


def letter_count(value: str) -> int:
    return len(re.findall(r"[^\W\d_]", value, re.UNICODE))


def prepare_language_text(value: str) -> str:
    # Same inert HTML/NFKC normalization used by the models; bounded before
    # parsing, and no network access or supplied markup rendering.
    value = str(value)[:MAX_CHARACTERS]
    value = re.sub(r"(?im)^(?:subject|from|to|cc|date|reply-to):\s*", "", value)
    # Keep optional sklearn/numpy dependencies off the module-import path so
    # a rules-only app can start and return the guarded unavailable fallback.
    from .ml_features import normalize_email_text
    value = normalize_email_text(value)
    # Strip addresses only after inert HTML parsing: otherwise a raw href with
    # no intervening space can consume its anchor's first visible word.
    value = re.sub(r"(?:https?://|www\.)\S+|[\w.+-]+@[\w.-]+", " ", value, flags=re.I)
    return " ".join(value.split())


def language_windows(value: str) -> list[str]:
    # Sentences preserve a real short bilingual block. Long sentences are cut
    # into nonoverlapping32-word spans. Small adjacent sentences are joined
    # until there is enough evidence; tiny tails merge with their predecessor.
    sentences = re.split(r"(?<=[.!?。؟])\s+", value)
    windows, pending = [], []
    for sentence in sentences:
        words = sentence.split()
        for start in range(0, len(words), WINDOW_WORDS):
            pending.extend(words[start:start + WINDOW_WORDS])
            joined = " ".join(pending)
            if len(pending) >= 16 and letter_count(joined) >= 80:
                windows.append(joined)
                pending = []
    if pending:
        if windows:
            windows[-1] += " " + " ".join(pending)
        else:
            windows.append(" ".join(pending))
    if len(windows) > MAX_WINDOWS:
        windows = [windows[round(i * (len(windows) - 1) / (MAX_WINDOWS - 1))] for i in range(MAX_WINDOWS)]
    return windows


def route_email_language(text: str, classify: Callable[[str], tuple[str, float]]) -> dict:
    note = "Offline language applicability uses all97 languages, inert bounded text and up to12 disjoint meaningful windows. Substantial competing-language content abstains; small ambiguous fragments do not veto the full message. Language identification remains imperfect."
    result = {"detected_language": "und", "language_routing_status": "uncertain", "language_routing_version": ROUTING_VERSION, "language_routing_limitation": note}
    try:
        cleaned = prepare_language_text(text)
        if letter_count(cleaned) < MIN_LETTERS or len(cleaned.split()) < MIN_WORDS:
            return {**result, "language_routing_status": "too_short", "reason": "Insufficient meaningful email text for language applicability. No ML prediction was produced; heuristic analysis remains available."}
        language, score = classify(cleaned)
        if not math.isfinite(float(score)) or score < .90:
            return {**result, "reason": "Email language identification is uncertain. No language-specific ML prediction was produced; heuristic analysis remains available."}
        if language not in {"en", "es"}:
            return {**result, "detected_language": language, "language_routing_status": "unsupported", "reason": f"Detected language '{language}' is outside the English/Spanish model scopes. No ML prediction was produced; heuristic analysis remains available."}
        totals, words_by_language = Counter(), Counter()
        windows = language_windows(cleaned)
        considered_letters = sum(letter_count(window) for window in windows)
        for window in windows:
            observed, internal_score = classify(window)
            if math.isfinite(float(internal_score)) and internal_score >= .95:
                totals[observed] += letter_count(window)
                words_by_language[observed] += len(window.split())
        for other, count in totals.items():
            if other != language and count >= MIXED_LETTERS and words_by_language[other] >= MIXED_WORDS and count / max(considered_letters, 1) >= MIXED_SHARE:
                return {**result, "detected_language": "mixed", "language_routing_status": "mixed", "reason": "Substantial meaningful email sections were identified as different languages. Mixed-language inputs use heuristic fallback; no language-specific ML prediction was produced."}
        return {**result, "detected_language": language, "language_routing_status": "supported", "reason": "Input routed to its language-specific classifier; language applicability does not establish that the input resembles training data."}
    except Exception:
        return {**result, "reason": "Email language identification is unavailable. No ML prediction was produced; heuristic analysis remains available."}
