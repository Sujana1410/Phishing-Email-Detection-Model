"""
features.py
------------
Feature extraction for the phishing email classifier.

Combines TF-IDF text features with a handful of hand-crafted numeric
features (URL count, suspicious keyword hits, urgency indicators, etc.)
so the model can key off both wording and structural red flags.
"""

import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

URL_REGEX = re.compile(r"https?://[^\s]+")
IP_URL_REGEX = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

SUSPICIOUS_KEYWORDS = [
    "verify", "suspend", "urgent", "immediately", "confirm", "click here",
    "password", "update your", "limited time", "act now", "claim",
    "refund", "winner", "won", "security alert", "unusual activity",
    "restricted", "locked", "expire", "final notice", "credentials",
]

SENSITIVE_WORD_PATTERNS = [
    r"\bssn\b", r"\bsocial security\b", r"\bcredit card\b", r"\bcvv\b",
    r"\bbank account\b", r"\bpin\b",
]


def count_urls(text: str) -> int:
    return len(URL_REGEX.findall(text))


def has_ip_url(text: str) -> int:
    return 1 if IP_URL_REGEX.search(text) else 0


def count_suspicious_keywords(text: str) -> int:
    lowered = text.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered)


def count_sensitive_requests(text: str) -> int:
    lowered = text.lower()
    return sum(1 for pat in SENSITIVE_WORD_PATTERNS if re.search(pat, lowered))


def exclamation_count(text: str) -> int:
    return text.count("!")


def uppercase_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    upper = sum(1 for c in letters if c.isupper())
    return upper / len(letters)


def extract_numeric_features(text: str) -> list:
    return [
        count_urls(text),
        has_ip_url(text),
        count_suspicious_keywords(text),
        count_sensitive_requests(text),
        exclamation_count(text),
        round(uppercase_ratio(text), 4),
        len(text),
    ]


FEATURE_NAMES = [
    "url_count",
    "has_ip_url",
    "suspicious_keyword_count",
    "sensitive_request_count",
    "exclamation_count",
    "uppercase_ratio",
    "text_length",
]


class NumericFeatureExtractor(BaseEstimator, TransformerMixin):
    """Sklearn-compatible transformer wrapping extract_numeric_features
    so it can be used inside a FeatureUnion/Pipeline alongside TF-IDF."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.array([extract_numeric_features(t) for t in X])
