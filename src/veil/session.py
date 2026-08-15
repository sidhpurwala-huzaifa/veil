"""Session-scoped reversible tokenization.

A ScrubSession owns the token<->value mapping for one conversation.
Tokenization is deterministic within a session — the same value always maps
to the same token — so the model sees a coherent entity across turns
("[PERSON_1] emailed [PERSON_2]" stays consistent) and re-hydration is a
plain dictionary lookup.

Tokens are short, readable, bracketed uppercase strings ([EMAIL_1],
[CREDIT_CARD_2]): frontier models reliably echo this shape verbatim, which
is what makes re-hydration work at all.

Sessions serialize with to_dict()/from_dict(); persistence (redis, a vault
service, a DB row per conversation) is the caller's choice and a later
extension point.
"""

from __future__ import annotations

import re

# [TYPE_N] where TYPE is uppercase (underscores allowed) and N is the
# per-type ordinal. Kept in one place: the streaming re-hydrator matches
# against this exact shape.
TOKEN_RE = re.compile(r"\[([A-Z][A-Z0-9_]*)_(\d+)\]")

_TYPE_SANITIZE_RE = re.compile(r"[^A-Z0-9]+")


def _normalize_type(entity_type: str) -> str:
    norm = _TYPE_SANITIZE_RE.sub("_", entity_type.upper()).strip("_")
    if not norm or not norm[0].isalpha():
        norm = "PII" + ("_" + norm if norm else "")
    return norm


class ScrubSession:
    def __init__(self) -> None:
        self._by_value: dict[tuple[str, str], str] = {}
        self._by_token: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def tokenize(self, entity_type: str, value: str) -> str:
        etype = _normalize_type(entity_type)
        key = (etype, value)
        token = self._by_value.get(key)
        if token is not None:
            return token
        n = self._counters.get(etype, 0) + 1
        self._counters[etype] = n
        token = f"[{etype}_{n}]"
        self._by_value[key] = token
        self._by_token[token] = value
        return token

    def lookup(self, token: str) -> str | None:
        return self._by_token.get(token)

    def rehydrate(self, text: str) -> str:
        """Replace every known token with its original value.

        Unknown token-shaped strings pass through untouched — the model may
        legitimately produce bracketed uppercase text of its own.
        """
        return TOKEN_RE.sub(lambda m: self._by_token.get(m.group(0), m.group(0)), text)

    def __len__(self) -> int:
        return len(self._by_token)

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict:
        return {"tokens": dict(self._by_token), "counters": dict(self._counters)}

    @classmethod
    def from_dict(cls, data: dict) -> "ScrubSession":
        session = cls()
        session._by_token = dict(data["tokens"])
        session._counters = dict(data["counters"])
        for token, value in session._by_token.items():
            m = TOKEN_RE.fullmatch(token)
            if m is None:
                raise ValueError(f"malformed token in session data: {token!r}")
            session._by_value[(m.group(1), value)] = token
        return session
