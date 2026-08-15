"""The built-in deterministic detection tier: regex + checksum validators.

Confidence values reflect how much a match alone proves. A Luhn-valid card
number is near-certain (0.99); a phone-shaped digit run is weak evidence
(0.65) and relies on the policy threshold to stay quiet in noisy text.
Overlaps (a card number that also looks phone-shaped) are resolved by the
engine in favor of the higher-confidence finding.
"""

from __future__ import annotations

import re

from .base import Detector, RegexDetector
from .context import ContextBooster
from . import validators
from ..types import Finding


def _dob_regex() -> RegexDetector:
    """Date-of-birth regex shared by default detectors and locale packs."""
    return RegexDetector(
        "DATE_OF_BIRTH",
        r"\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b"
        r"|\b\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2}\b",
        confidence=0.45,
        validator=validators.valid_date,
    )


DOB_KEYWORDS_EN = [
    "dob", "born", "birthday", "date of birth", "birth date", "birthdate",
]


def _passport_regex() -> RegexDetector:
    """Passport-number regex shared by default detectors and locale packs.

    Covers US (9 digits), UK (9 digits), EU (1-2 letters + 6-7 digits),
    and most other national formats.
    """
    return RegexDetector(
        "PASSPORT",
        r"\b[A-Z]{0,2}\d{6,9}\b",
        confidence=0.40,
    )


PASSPORT_KEYWORDS_EN = [
    "passport", "passport number", "passport no", "passport#",
]


def default_detectors() -> list[Detector]:
    return [
        # -- existing (hardened) -----------------------------------------------
        _email_detector(),
        RegexDetector(
            "CREDIT_CARD",
            r"\b\d(?:[ -]?\d){12,18}\b",
            confidence=0.99,
            validator=validators.luhn,
        ),
        RegexDetector(
            "US_SSN",
            r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
            confidence=0.85,
            validator=validators.ssn_not_itin,
        ),
        RegexDetector(
            "PHONE",
            # International: +CC with flexible digit groups (validator gates on count).
            # US domestic: (xxx) xxx-xxxx.
            # Negative lookbehind for 'v' and version-like context.
            r"(?<!v)(?<!\d\.)"
            r"(?:"
            r"(?:\+\d{1,3}[ .\-]?)"
            r"(?:\(?\d{1,5}\)?[ .\-]?)?"
            r"(?:\d[\d .\-]{4,12}\d)"
            r"|"
            r"(?:\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4})"
            r")",
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
            # OpenAI (sk-), Anthropic (sk-ant-), Stripe (sk_live_, sk_test_,
            # pk_live_, pk_test_), GitHub PAT (ghp_).
            r"\bsk-[A-Za-z0-9_-]{20,}\b"
            r"|\bsk-ant-[A-Za-z0-9_-]{20,}\b"
            r"|\b[sp]k_(?:live|test)_[A-Za-z0-9]{24,}\b"
            r"|\bghp_[A-Za-z0-9]{36}\b",
            confidence=0.95,
        ),
        # -- new: credentials / secrets ----------------------------------------
        RegexDetector(
            "US_ITIN",
            r"\b9\d{2}-[7-9]\d-\d{4}\b",
            confidence=0.85,
        ),
        _private_key_detector(),
        RegexDetector(
            "JWT",
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            confidence=0.95,
            validator=validators.jwt_structure,
        ),
        RegexDetector(
            "SLACK_TOKEN",
            r"\bxox[bpras]-[A-Za-z0-9-]{10,}\b",
            confidence=0.99,
        ),
        RegexDetector(
            "GCP_API_KEY",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            confidence=0.95,
        ),
        RegexDetector(
            "GENERIC_SECRET",
            r"(?i)(?:password|passwd|secret|token|api_key|apikey|api-key)\s*[=:]\s*[\"']?([^\s\"']{8,})",
            confidence=0.70,
        ),
        # -- new: network / infra ----------------------------------------------
        RegexDetector(
            "IPV6_ADDRESS",
            # Single broad pattern that captures full compressed and expanded
            # forms.  The validator does the structural check; the regex just
            # grabs hex-colon runs long enough to be plausible.
            r"(?<![:\w])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![:\w])"
            r"|(?<![:\w])::(?![:\w])",
            confidence=0.9,
            validator=validators.ipv6_structure,
        ),
        RegexDetector(
            "MAC_ADDRESS",
            r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b",
            confidence=0.85,
        ),
        RegexDetector(
            "URL",
            r"https?://[^\s<>\"']+",
            confidence=0.7,
        ),
        # -- context-gated personal identifiers --------------------------------
        ContextBooster(
            _dob_regex(),
            keywords=DOB_KEYWORDS_EN,
            boost=0.40,
            window=80,
        ),
        ContextBooster(
            _passport_regex(),
            keywords=PASSPORT_KEYWORDS_EN,
            boost=0.45,
            window=60,
        ),
    ]


class _EmailDetector:
    """Email detector that rejects matches inside URLs (scheme://user@host)."""

    name = "regex:email"

    _PATTERN = re.compile(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}"
    )
    _SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in self._PATTERN.finditer(text):
            if self._inside_url(text, m.start()):
                continue
            findings.append(
                Finding(
                    entity_type="EMAIL",
                    start=m.start(),
                    end=m.end(),
                    text=m.group(0),
                    confidence=0.95,
                    detector=self.name,
                )
            )
        return findings

    def _inside_url(self, text: str, pos: int) -> bool:
        """Check whether *pos* falls inside a scheme://... URL."""
        before = text[:pos]
        scheme_end = before.rfind("://")
        if scheme_end == -1:
            return False
        # No whitespace between :// and the match → we're inside a URL.
        segment = before[scheme_end:]
        return " " not in segment and "\t" not in segment and "\n" not in segment


def _email_detector() -> _EmailDetector:
    return _EmailDetector()


class _PrivateKeyDetector:
    """Multiline detector for PEM-encoded private key blocks."""

    name = "regex:private_key"

    _PATTERN = re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        r"[\s\S]*?"
        r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    )

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in self._PATTERN.finditer(text):
            findings.append(
                Finding(
                    entity_type="PRIVATE_KEY",
                    start=m.start(),
                    end=m.end(),
                    text=m.group(0),
                    confidence=0.99,
                    detector=self.name,
                )
            )
        return findings


def _private_key_detector() -> _PrivateKeyDetector:
    return _PrivateKeyDetector()
