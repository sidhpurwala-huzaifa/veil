"""The Scrubber: detect -> policy -> transform, plus message-list helpers."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Sequence

from .detectors import Detector, default_detectors
from .policy import Policy
from .session import ScrubSession
from .streaming import StreamRehydrator
from .types import Action, Finding, PIIBlockedError

# Message keys whose string values carry model-visible text in the OpenAI
# and Anthropic wire formats. Everything else (role, type, ids) is left alone.
_TEXT_KEYS = frozenset({"content", "text"})


@dataclass
class ScrubResult:
    text: str
    findings: list[Finding]
    session: ScrubSession


@dataclass
class MessageScrubResult:
    messages: list[Any]
    findings: list[Finding]
    session: ScrubSession


class Scrubber:
    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: Policy | None = None,
    ):
        self.detectors: list[Detector] = list(detectors) if detectors is not None else default_detectors()
        self.policy = policy if policy is not None else Policy.default()

    # -- outbound ----------------------------------------------------------

    def scrub(self, text: str, session: ScrubSession | None = None) -> ScrubResult:
        session = session if session is not None else ScrubSession()
        findings = self._actionable_findings(text)
        scrubbed = self._apply(text, findings, session)
        return ScrubResult(text=scrubbed, findings=findings, session=session)

    def scrub_messages(
        self, messages: Sequence[Any], session: ScrubSession | None = None
    ) -> MessageScrubResult:
        """Scrub an OpenAI/Anthropic-style message list, sharing one session.

        Walks the structure and scrubs string values under 'content'/'text'
        keys (including nested content blocks). The input is not mutated.
        """
        session = session if session is not None else ScrubSession()
        findings: list[Finding] = []
        scrubbed = [self._scrub_value(copy.deepcopy(m), session, findings) for m in messages]
        return MessageScrubResult(messages=scrubbed, findings=findings, session=session)

    # -- inbound -----------------------------------------------------------

    def rehydrate(self, text: str, session: ScrubSession) -> str:
        return session.rehydrate(text)

    def stream_rehydrator(self, session: ScrubSession) -> StreamRehydrator:
        return StreamRehydrator(session)

    # -- internals ---------------------------------------------------------

    def _actionable_findings(self, text: str) -> list[Finding]:
        raw = [f for d in self.detectors for f in d.detect(text)]
        passed = []
        for f in raw:
            rule = self.policy.rule_for(f.entity_type)
            if rule.action is Action.ALLOW or f.confidence < rule.min_confidence:
                continue
            passed.append(f)
        # Fail closed: a BLOCK finding blocks even if an overlapping finding
        # would have won overlap resolution.
        blocked = [f for f in passed if self.policy.rule_for(f.entity_type).action is Action.BLOCK]
        if blocked:
            raise PIIBlockedError(blocked)
        return _resolve_overlaps(passed)

    def _apply(self, text: str, findings: list[Finding], session: ScrubSession) -> str:
        # Replace right-to-left so earlier offsets stay valid.
        for f in sorted(findings, key=lambda f: f.start, reverse=True):
            action = self.policy.rule_for(f.entity_type).action
            if action is Action.TOKENIZE:
                replacement = session.tokenize(f.entity_type, f.text)
            else:  # MASK
                replacement = f"[REDACTED_{f.entity_type}]"
            text = text[: f.start] + replacement + text[f.end :]
        return text

    def _scrub_value(self, value: Any, session: ScrubSession, findings: list[Finding]) -> Any:
        if isinstance(value, dict):
            for k, v in value.items():
                if k in _TEXT_KEYS and isinstance(v, str):
                    result = self.scrub(v, session)
                    findings.extend(result.findings)
                    value[k] = result.text
                else:
                    value[k] = self._scrub_value(v, session, findings)
            return value
        if isinstance(value, list):
            return [self._scrub_value(v, session, findings) for v in value]
        return value


def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Keep the strongest finding per region: confidence, then span length."""
    ordered = sorted(findings, key=lambda f: (-f.confidence, f.start - f.end, f.start))
    kept: list[Finding] = []
    for f in ordered:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)
