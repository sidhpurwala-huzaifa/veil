"""Locale-specific detector packs (opt-in, not included in defaults).

Usage::

    from veil import Scrubber, default_detectors
    from veil.detectors.locale import locale_detectors

    scrubber = Scrubber(detectors=default_detectors() + locale_detectors("GB"))
"""

from __future__ import annotations

from .base import Detector, RegexDetector
from . import validators

_LOCALE_REGISTRY: dict[str, list[Detector]] = {}


def _register(locale: str, detectors: list[Detector]) -> None:
    _LOCALE_REGISTRY[locale.upper()] = detectors


def locale_detectors(locale: str) -> list[Detector]:
    """Return detectors for a given locale code (e.g. ``"GB"``, ``"CA"``, ``"IN"``)."""
    key = locale.upper()
    if key not in _LOCALE_REGISTRY:
        available = ", ".join(sorted(_LOCALE_REGISTRY)) or "(none)"
        raise ValueError(f"Unknown locale {key!r}; available: {available}")
    return list(_LOCALE_REGISTRY[key])


def available_locales() -> list[str]:
    """Return sorted list of registered locale codes."""
    return sorted(_LOCALE_REGISTRY)


# -- Great Britain -------------------------------------------------------------

_register("GB", [
    RegexDetector(
        "UK_NINO",
        r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        confidence=0.90,
        validator=validators.nino_prefix,
    ),
])

# -- Canada --------------------------------------------------------------------

_register("CA", [
    RegexDetector(
        "CA_SIN",
        r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b",
        confidence=0.85,
        validator=validators.luhn_9,
    ),
])

# -- India ---------------------------------------------------------------------

_register("IN", [
    RegexDetector(
        "AADHAAR",
        r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b",
        confidence=0.90,
        validator=validators.verhoeff,
    ),
])

# -- European Union (VAT IDs) -------------------------------------------------

# Simplified: 2-letter country + digits, varying length per country.
# The validator checks basic structural rules; full per-country check-digit
# algorithms are deferred to Tier 2.
_register("EU", [
    RegexDetector(
        "EU_VAT",
        r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{2,12}\b",
        confidence=0.80,
    ),
])
