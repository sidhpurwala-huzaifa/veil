"""Locale-specific detector packs (opt-in, not included in defaults).

Each locale pack can contribute two things:

1. **Locale-specific regex detectors** — e.g. UK_NINO, CA_SIN, AADHAAR.
2. **Context keywords** — translations that let the context-gated DOB and
   PASSPORT detectors fire on non-English text (e.g. "Geburtsdatum" for
   German, "passeport" for French).

Usage::

    from veil import Scrubber, default_detectors
    from veil.detectors.locale import locale_detectors

    # English defaults + German locale keywords + German regex detectors
    scrubber = Scrubber(detectors=default_detectors() + locale_detectors("DE"))

    # Stack multiple locales
    scrubber = Scrubber(
        detectors=default_detectors()
                  + locale_detectors("DE")
                  + locale_detectors("FR")
    )
"""

from __future__ import annotations

from .base import Detector, RegexDetector
from .context import ContextBooster
from . import validators
from .builtin import _dob_regex, _passport_regex

_LOCALE_REGISTRY: dict[str, list[Detector]] = {}


def _register(
    locale: str,
    detectors: list[Detector],
    *,
    dob_keywords: list[str] | None = None,
    passport_keywords: list[str] | None = None,
) -> None:
    """Register a locale pack with optional context keyword extensions."""
    pack: list[Detector] = list(detectors)
    if dob_keywords:
        pack.append(ContextBooster(
            _dob_regex(),
            keywords=dob_keywords,
            boost=0.40,
            window=80,
        ))
    if passport_keywords:
        pack.append(ContextBooster(
            _passport_regex(),
            keywords=passport_keywords,
            boost=0.45,
            window=60,
        ))
    _LOCALE_REGISTRY[locale.upper()] = pack


def locale_detectors(locale: str) -> list[Detector]:
    """Return detectors for a given locale code (e.g. ``"GB"``, ``"DE"``, ``"FR"``)."""
    key = locale.upper()
    if key not in _LOCALE_REGISTRY:
        available = ", ".join(sorted(_LOCALE_REGISTRY)) or "(none)"
        raise ValueError(f"Unknown locale {key!r}; available: {available}")
    return list(_LOCALE_REGISTRY[key])


def available_locales() -> list[str]:
    """Return sorted list of registered locale codes."""
    return sorted(_LOCALE_REGISTRY)


# ── Great Britain ─────────────────────────────────────────────────────────────

_register("GB", [
    RegexDetector(
        "UK_NINO",
        r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        confidence=0.90,
        validator=validators.nino_prefix,
    ),
])

# ── Canada ────────────────────────────────────────────────────────────────────

_register("CA", [
    RegexDetector(
        "CA_SIN",
        r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b",
        confidence=0.85,
        validator=validators.luhn_9,
    ),
])

# ── India ─────────────────────────────────────────────────────────────────────

_register("IN", [
    RegexDetector(
        "AADHAAR",
        r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b",
        confidence=0.90,
        validator=validators.verhoeff,
    ),
],
    dob_keywords=["जन्म तिथि", "जन्म दिनांक"],
    passport_keywords=["पासपोर्ट"],
)

# ── European Union (VAT IDs) ─────────────────────────────────────────────────

_register("EU", [
    RegexDetector(
        "EU_VAT",
        r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{2,12}\b",
        confidence=0.80,
    ),
])

# ── Germany ───────────────────────────────────────────────────────────────────

_register("DE", [],
    dob_keywords=["geburtsdatum", "geboren", "geb."],
    passport_keywords=["reisepass", "passnummer", "ausweisnummer"],
)

# ── France ────────────────────────────────────────────────────────────────────

_register("FR", [],
    dob_keywords=["date de naissance", "né le", "née le"],
    passport_keywords=["passeport", "numéro de passeport"],
)

# ── Spain ─────────────────────────────────────────────────────────────────────

_register("ES", [],
    dob_keywords=["fecha de nacimiento", "nacido el", "nacida el"],
    passport_keywords=["pasaporte", "número de pasaporte"],
)

# ── Portugal / Brazil ─────────────────────────────────────────────────────────

_register("PT", [],
    dob_keywords=["data de nascimento", "nascido em", "nascida em"],
    passport_keywords=["passaporte", "número do passaporte"],
)

# ── Italy ─────────────────────────────────────────────────────────────────────

_register("IT", [],
    dob_keywords=["data di nascita", "nato il", "nata il"],
    passport_keywords=["passaporto", "numero di passaporto"],
)

# ── Russia ────────────────────────────────────────────────────────────────────

_register("RU", [],
    dob_keywords=["дата рождения"],
    passport_keywords=["паспорт", "номер паспорта"],
)

# ── China ─────────────────────────────────────────────────────────────────────

_register("ZH", [],
    dob_keywords=["出生日期", "生日"],
    passport_keywords=["护照", "护照号码"],
)

# ── Japan ─────────────────────────────────────────────────────────────────────

_register("JA", [],
    dob_keywords=["生年月日"],
    passport_keywords=["パスポート", "旅券番号"],
)

# ── Korea ─────────────────────────────────────────────────────────────────────

_register("KO", [],
    dob_keywords=["생년월일"],
    passport_keywords=["여권", "여권번호"],
)

# ── Arabic ────────────────────────────────────────────────────────────────────

_register("AR", [],
    dob_keywords=["تاريخ الميلاد", "تاريخ الولادة"],
    passport_keywords=["جواز سفر", "رقم جواز السفر"],
)

# ── Hebrew ────────────────────────────────────────────────────────────────────

_register("HE", [],
    dob_keywords=["תאריך לידה"],
    passport_keywords=["דרכון", "מספר דרכון"],
)

# ── Thai ──────────────────────────────────────────────────────────────────────

_register("TH", [],
    dob_keywords=["วันเกิด", "วันเดือนปีเกิด"],
    passport_keywords=["หนังสือเดินทาง"],
)
