"""Per-entity-class policy: what to do with each kind of finding.

A Policy maps entity types to Rules. Unknown types fall through to the
default rule, so new detectors are covered the moment they're registered —
fail-closed by default rather than silently allowing a new entity class.
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import Action


@dataclass(frozen=True)
class Rule:
    action: Action = Action.TOKENIZE
    min_confidence: float = 0.5


class Policy:
    def __init__(self, rules: dict[str, Rule] | None = None, default: Rule | None = None):
        self._rules = dict(rules or {})
        self._default = default if default is not None else Rule()

    @classmethod
    def default(cls) -> "Policy":
        """Tokenize everything at >=0.5 confidence. Safe and reversible."""
        return cls()

    def rule_for(self, entity_type: str) -> Rule:
        return self._rules.get(entity_type, self._default)

    def with_rule(self, entity_type: str, rule: Rule) -> "Policy":
        """Return a copy with one rule added/replaced (policies are immutable-ish)."""
        rules = dict(self._rules)
        rules[entity_type] = rule
        return Policy(rules, self._default)
