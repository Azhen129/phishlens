"""Offline, bounded preprocessing shared by PhishLens training and inference.

No network client, name resolver, email renderer or attachment executor exists
in this module. Classes live here so trusted, locally trained joblib artifacts
can be deserialized without importing the training command.
"""
from __future__ import annotations

import html
import ipaddress
import math
import re
import unicodedata
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin

FEATURE_VERSION = "passive-text-v2"
EMAIL_MAX_CHARS = 16_000
URL_MAX_CHARS = 8192


class _TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style", "noscript"}:
            self.hidden += 1
        elif tag.lower() in {"p", "div", "br", "li", "tr"}:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "noscript"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def normalize_email_text(value: str) -> str:
    text = str(value)[:EMAIL_MAX_CHARS]
    if re.search(r"</?(?:html|body|div|p|a|script|style|table)\b", text, re.I):
        parser = _TextOnly()
        try:
            parser.feed(text)
            text = " ".join(parser.parts)
        except (ValueError, RecursionError):
            text = re.sub(r"<[^>]{0,1000}>", " ", text)
    text = unicodedata.normalize("NFKC", html.unescape(text))
    return " ".join(text.split()).casefold()[:EMAIL_MAX_CHARS]


def normalize_url_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value).strip())[:URL_MAX_CHARS]
    try:
        parts = urlsplit(text if "://" in text else "https://" + text)
        # Lowercase the scheme/host, preserving case-sensitive paths and values.
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, parts.fragment))[:URL_MAX_CHARS]
    except ValueError:
        return text


def hostname_text(value: str) -> str:
    """Feature policy chosen before evaluation to remove known source shortcuts."""
    try:
        return (urlsplit(normalize_url_text(value)).hostname or "invalid-host").lower().rstrip(".")
    except ValueError:
        return "invalid-host"


def hostname_lexical_vector(value: str) -> list[float]:
    host = hostname_text(value)
    counts = Counter(host)
    entropy = -sum((n / max(len(host), 1)) * math.log2(n / max(len(host), 1)) for n in counts.values())
    try:
        ipaddress.ip_address(host)
        ip_literal = 1.0
    except ValueError:
        ip_literal = 0.0
    labels = host.split(".")
    return [len(host), len(labels), host.count("-"), sum(c.isdigit() for c in host), entropy, sum(ord(c) > 127 for c in host), float("xn--" in host), ip_literal, max(map(len, labels), default=0), host.count(".")]


def canonical_text(value: str, kind: str) -> str:
    """Conservative exact-duplicate key; never used as the model's label."""
    if kind == "email":
        return normalize_email_text(value).casefold()
    value = normalize_url_text(value)
    try:
        p = urlsplit(value)
        host = (p.hostname or "").lower().rstrip(".")
        if host.startswith("www."):
            host = host[4:]
        query = "&".join(f"{k}={v}" for k, v in sorted(parse_qsl(p.query, keep_blank_values=True, max_num_fields=200)))
        return host + (unquote(p.path) or "/") + ("?" + query if query else "")
    except ValueError:
        return value.casefold()


def url_lexical_vector(value: str) -> list[float]:
    text = normalize_url_text(value)
    try:
        p = urlsplit(text)
        host = p.hostname or ""
        path, query = p.path, p.query
        credential = float(p.username is not None)
        try:
            ipaddress.ip_address(host)
            ip_literal = 1.0
        except ValueError:
            ip_literal = 0.0
    except ValueError:
        host, path, query, credential, ip_literal = "", "", "", 0.0, 0.0
    counts = Counter(text)
    entropy = -sum((n / max(len(text), 1)) * math.log2(n / max(len(text), 1)) for n in counts.values())
    return [
        len(text), len(host), len(path), len(query), text.count("-"),
        sum(c.isdigit() for c in text), text.count("."), host.count("."),
        text.count("%"), text.count("@"), text.count("?"), text.count("="),
        path.count("/"), query.count("&"), entropy, credential, ip_literal,
        float(text.startswith("https://")), float("xn--" in host),
        sum(ord(c) > 127 for c in host), sum(not c.isalnum() for c in text),
        len(text) / max(len(host), 1),
    ]


URL_FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length", "hyphen_count",
    "digit_count", "dot_count", "host_dot_count", "percent_count", "at_count",
    "question_count", "equals_count", "path_slashes", "query_separators",
    "character_entropy", "userinfo", "ip_literal", "https_scheme", "punycode",
    "unicode_host_characters", "special_characters", "url_host_length_ratio",
]


class UrlLexicalTransformer(TransformerMixin, BaseEstimator):
    def __init__(self, policy="full"):
        self.policy = policy

    def fit(self, X, y=None):
        self.n_features_in_ = 10 if self.policy == "hostname" else len(URL_FEATURE_NAMES)
        return self

    def transform(self, X):
        transform = hostname_lexical_vector if self.policy == "hostname" else url_lexical_vector
        return sparse.csr_matrix(np.asarray([transform(v) for v in X], dtype=np.float64))

    def get_feature_names_out(self, input_features=None):
        names = ["host_length", "label_count", "host_hyphens", "host_digits", "host_entropy", "unicode_host_characters", "punycode", "ip_literal", "longest_host_label", "host_dots"] if self.policy == "hostname" else URL_FEATURE_NAMES
        return np.asarray(names, dtype=object)


def hybrid_features(probabilities, heuristic_scores):
    p = np.clip(np.asarray(probabilities, dtype=float), 1e-6, 1 - 1e-6)
    h = np.clip(np.asarray(heuristic_scores, dtype=float), 0, 100) / 100
    return np.column_stack((np.log(p / (1 - p)), h))


class TrainedClassifier:
    """A frozen base pipeline plus sigmoid fitted on disjoint calibration data."""
    def __init__(self, estimator, calibrator):
        self.estimator = estimator
        self.calibrator = calibrator
        self.classes_ = np.asarray([0, 1])

    def decision_function(self, X):
        return np.asarray(self.estimator.decision_function(X), dtype=float)

    def predict_proba(self, X):
        scores = self.decision_function(X).reshape(-1, 1)
        return self.calibrator.predict_proba(scores)

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= .5).astype(int)


class CalibratedHybrid:
    """Transparent two-feature logistic combiner and separate sigmoid calibration."""
    def __init__(self, estimator, calibrator):
        self.estimator = estimator
        self.calibrator = calibrator
        self.classes_ = np.asarray([0, 1])

    def predict_proba(self, X):
        raw = self.estimator.decision_function(X).reshape(-1, 1)
        return self.calibrator.predict_proba(raw)

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= .5).astype(int)
