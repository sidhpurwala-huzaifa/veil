"""Detector protocol and the reusable regex+validator detector.

A detector is anything with a `name` and a `detect(text) -> list[Finding]`.
That's the whole plugin surface: NER models, LLM classifiers, and
org-specific matchers all implement this one protocol and drop into the
same Scrubber pipeline.
"""

from __future__ import annotations

import re
from typing import Callable, Protocol, runtime_checkable

from ..types import Finding


@runtime_checkable
class Detector(Protocol):
    name: str

    def detect(self, text: str) -> list[Finding]: ...


class RegexDetector:
    """Pattern match gated by an optional validator.

    The validator is what separates "looks like a card number" from "passes
    Luhn" — matches that fail validation are dropped entirely, not down-scored,
    so downstream consumers can trust the stated confidence.
    """

    def __init__(
        self,
        entity_type: str,
        pattern: str | re.Pattern[str],
        confidence: float = 0.8,
        validator: Callable[[str], bool] | None = None,
        flags: int = 0,
        name: str | None = None,
    ):
        self.entity_type = entity_type
        self.pattern = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
        self.confidence = confidence
        self.validator = validator
        self.name = name or f"regex:{entity_type.lower()}"

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validator is not None and not self.validator(value):
                continue
            findings.append(
                Finding(
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=value,
                    confidence=self.confidence,
                    detector=self.name,
                )
            )
        return findings
