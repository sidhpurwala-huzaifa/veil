"""The built-in deterministic detection tier: regex + checksum validators.

Confidence values reflect how much a match alone proves. A Luhn-valid card
number is near-certain (0.99); a phone-shaped digit run is weak evidence
(0.65) and relies on the policy threshold to stay quiet in noisy text.
Overlaps (a card number that also looks phone-shaped) are resolved by the
engine in favor of the higher-confidence finding.
"""

from __future__ import annotations

from .base import RegexDetector
from . import validators


def default_detectors() -> list[RegexDetector]:
    return [
        RegexDetector(
            "EMAIL",
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}",
            confidence=0.95,
        ),
        RegexDetector(
            "CREDIT_CARD",
            r"\b\d(?:[ -]?\d){12,18}\b",
            confidence=0.99,
            validator=validators.luhn,
        ),
        RegexDetector(
            "US_SSN",
            # Dashed form only: bare 9-digit runs are too noisy for a default.
            r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
            confidence=0.85,
        ),
        RegexDetector(
            "PHONE",
            # Separator-bearing NANP-style, or explicit international +digits.
            r"(?:\+\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b|\+\d{7,15}\b",
            confidence=0.65,
            validator=validators.phone_digit_count,
        ),
        RegexDetector(
            "IP_ADDRESS",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            confidence=0.9,
            validator=validators.ipv4_octets,
        ),
        RegexDetector(
            "IBAN",
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
            confidence=0.99,
            validator=validators.iban_mod97,
        ),
        RegexDetector(
            "AWS_ACCESS_KEY",
            r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])",
            confidence=0.99,
        ),
        RegexDetector(
            "API_KEY",
            r"\bsk-[A-Za-z0-9_-]{20,}\b|\bghp_[A-Za-z0-9]{36}\b",
            confidence=0.95,
        ),
    ]
