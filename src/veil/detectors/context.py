"""Context-aware confidence scoring for detectors.

Some entity patterns (dates, passport numbers, bare digit runs) are too
noisy on their own.  ContextBooster wraps any Detector and adjusts finding
confidence based on nearby keyword proximity — keeping RegexDetector simple
while making context opt-in and composable.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Sequence

from ..types import Finding
from .base import Detector


class ContextBooster:
    """Wraps a Detector; boosts confidence when keywords appear nearby.

    If ``require_context`` is True (the default), findings without a nearby
    keyword are dropped entirely — the base detector's confidence is set low
    enough that the policy threshold filters it.  With a keyword present,
    ``boost`` is added and the finding passes.
    """

    def __init__(
        self,
        detector: Detector,
        keywords: Sequence[str],
        boost: float = 0.35,
        window: int = 80,
        *,
        require_context: bool = True,
    ):
        self._detector = detector
        self._keywords = [k.lower() for k in keywords]
        self._boost = boost
        self._window = window
        self._require_context = require_context

    @property
    def name(self) -> str:  # noqa: D401 — simple delegation
        return self._detector.name

    def detect(self, text: str) -> list[Finding]:
        text_lower = text.lower()
        results: list[Finding] = []
        for f in self._detector.detect(text):
            region_start = max(0, f.start - self._window)
            region_end = min(len(text), f.end + self._window)
            region = text_lower[region_start:region_end]
            has_keyword = any(kw in region for kw in self._keywords)
            if has_keyword:
                new_conf = min(f.confidence + self._boost, 1.0)
                results.append(replace(f, confidence=new_conf))
            elif not self._require_context:
                results.append(f)
            # else: no keyword + require_context → drop
        return results
