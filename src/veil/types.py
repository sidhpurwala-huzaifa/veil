"""Core data model shared by every layer of the library."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Action(Enum):
    """What the policy does with a detected entity."""

    TOKENIZE = "tokenize"  # reversible: replace with a session token, re-hydratable
    MASK = "mask"          # irreversible: replace with [REDACTED_<TYPE>]
    BLOCK = "block"        # refuse the whole request (raises PIIBlockedError)
    ALLOW = "allow"        # pass through untouched


@dataclass(frozen=True)
class Finding:
    """A single detected entity span.

    Offsets are into the exact text passed to the detector. `text` is the
    matched value so callers never have to re-slice.
    """

    entity_type: str
    start: int
    end: int
    text: str
    confidence: float
    detector: str


class PIIBlockedError(Exception):
    """Raised when a finding's policy action is BLOCK.

    The request must not be forwarded to the model. `findings` carries every
    finding that triggered the block so callers can log or surface them.
    """

    def __init__(self, findings: list[Finding]):
        self.findings = findings
        kinds = sorted({f.entity_type for f in findings})
        super().__init__(f"blocked by policy: {', '.join(kinds)}")
