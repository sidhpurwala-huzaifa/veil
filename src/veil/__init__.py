"""veil — PII scrubbing layer for LLM API traffic.

Detect sensitive data in prompts, replace it with reversible session tokens
before it leaves your boundary, and re-hydrate the model's response
(streaming or not) on the way back.
"""

from .detectors import Detector, RegexDetector, default_detectors
from .engine import MessageScrubResult, Scrubber, ScrubResult
from .policy import Policy, Rule
from .session import ScrubSession
from .streaming import StreamRehydrator
from .types import Action, Finding, PIIBlockedError

__version__ = "0.1.0"

__all__ = [
    "Action",
    "Detector",
    "Finding",
    "MessageScrubResult",
    "PIIBlockedError",
    "Policy",
    "RegexDetector",
    "Rule",
    "Scrubber",
    "ScrubResult",
    "ScrubSession",
    "StreamRehydrator",
    "default_detectors",
]
