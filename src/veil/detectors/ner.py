"""Tier 2 NER detector backed by spaCy.

A single ``NerDetector`` runs one ``nlp(text)`` call and emits findings for
every entity type the model produces that maps to a veil entity type.  The
mapping and per-type confidence are both configurable.

Requires the ``ner`` extra::

    pip install veil-pii[ner]
    python -m spacy download en_core_web_sm   # or any other model
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..types import Finding

if TYPE_CHECKING:
    import spacy.language

# ── spaCy label → veil entity type ──────────────────────────────────────────

DEFAULT_ENTITY_MAP: dict[str, str] = {
    "PERSON": "PERSON_NAME",
    "PER": "PERSON_NAME",       # xx_ent_wiki / multilingual models
    "ORG": "ORGANIZATION",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
    "DATE": "DATE_TIME",
    "NORP": "NORP_GROUP",
}

# Confidence values reflect NER evidence strength.  Model softmax is *not*
# used because it is poorly calibrated; these fixed values keep the policy
# threshold contract meaningful.
DEFAULT_CONFIDENCE_MAP: dict[str, float] = {
    "PERSON_NAME": 0.85,
    "ORGANIZATION": 0.80,
    "LOCATION": 0.75,
    "DATE_TIME": 0.75,
    "NORP_GROUP": 0.70,
}

_DEFAULT_CONFIDENCE_FALLBACK = 0.70


def _load_spacy(model: str) -> spacy.language.Language:
    """Load a spaCy model, raising a clear error if spaCy is missing."""
    try:
        import spacy
    except ImportError:
        raise ImportError(
            "spaCy is required for NER detection. "
            "Install it with:  pip install veil-pii[ner]"
        ) from None

    try:
        return spacy.load(model)
    except OSError:
        raise OSError(
            f"spaCy model {model!r} not found. "
            f"Install it with:  python -m spacy download {model}"
        ) from None


class NerDetector:
    """Tier 2 NER detector — wraps a spaCy NLP pipeline.

    One detector instance, one ``nlp()`` call per text, multiple entity types
    produced.  Works with any spaCy model (any language) that includes a NER
    component.

    Parameters
    ----------
    model:
        Name of the spaCy model to load (e.g. ``"en_core_web_sm"``,
        ``"de_core_news_sm"``).
    entity_map:
        Override the spaCy-label → veil-entity-type mapping.
    confidence_map:
        Override the per-veil-type confidence values.
    """

    def __init__(
        self,
        model: str = "en_core_web_sm",
        entity_map: dict[str, str] | None = None,
        confidence_map: dict[str, float] | None = None,
    ):
        self._nlp = _load_spacy(model)
        self._entity_map = entity_map or dict(DEFAULT_ENTITY_MAP)
        self._confidence_map = confidence_map or dict(DEFAULT_CONFIDENCE_MAP)
        self._model_name = model
        self.name = f"ner:{model}"

    def detect(self, text: str) -> list[Finding]:
        doc = self._nlp(text)
        findings: list[Finding] = []
        for ent in doc.ents:
            veil_type = self._entity_map.get(ent.label_)
            if veil_type is None:
                continue
            confidence = self._confidence_map.get(
                veil_type, _DEFAULT_CONFIDENCE_FALLBACK
            )
            findings.append(
                Finding(
                    entity_type=veil_type,
                    start=ent.start_char,
                    end=ent.end_char,
                    text=ent.text,
                    confidence=confidence,
                    detector=self.name,
                )
            )
        return findings


def ner_detectors(
    model: str | list[str] = "en_core_web_sm",
    **kwargs,
) -> list[NerDetector]:
    """Convenience factory — returns NER detector(s).

    Pass a single model name or a list of model names (e.g. for multilingual
    support).  Each model becomes one ``NerDetector``.  Returns a list so
    callers can write ``default_detectors() + ner_detectors()``.

    Accepts the same keyword arguments as ``NerDetector``.
    """
    models = [model] if isinstance(model, str) else model
    return [NerDetector(model=m, **kwargs) for m in models]
