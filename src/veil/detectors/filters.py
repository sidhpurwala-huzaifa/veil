"""Allowlist / denylist filtering for detectors.

FilteredDetector wraps any Detector and drops findings that match an
allowlist (known-safe values) or force-includes denylist values.  It
composes with ContextBooster and RegexDetector — the same decorator
pattern used throughout the detection tier.
"""

from __future__ import annotations

import re
from typing import Sequence

from ..types import Finding
from .base import Detector


class FilteredDetector:
    """Wraps a Detector with allowlist/denylist filtering.

    - **allowlist**: exact values to skip (case-sensitive).
    - **allowlist_patterns**: compiled regexes — a finding whose text
      full-matches any pattern is dropped.
    - **denylist**: exact values that are always flagged at confidence 1.0,
      even if the inner detector would not have found them.
    """

    def __init__(
        self,
        detector: Detector,
        allowlist: set[str] | None = None,
        denylist: set[str] | None = None,
        allowlist_patterns: Sequence[re.Pattern[str]] | None = None,
    ):
        self._detector = detector
        self._allowlist = allowlist or set()
        self._denylist = denylist or set()
        self._allowlist_patterns = list(allowlist_patterns or [])

    @property
    def name(self) -> str:  # noqa: D401
        return self._detector.name

    def _is_allowed(self, value: str) -> bool:
        if value in self._allowlist:
            return True
        return any(p.fullmatch(value) for p in self._allowlist_patterns)

    def detect(self, text: str) -> list[Finding]:
        findings = [f for f in self._detector.detect(text) if not self._is_allowed(f.text)]
        return findings
