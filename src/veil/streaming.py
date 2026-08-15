"""Streaming re-hydration with chunk-boundary holdback.

Providers stream responses in arbitrary chunk sizes, so a token can arrive
split across chunks ("...[EMA" + "IL_1]..."). The re-hydrator emits
everything it can prove is not part of a token and holds back only a
trailing run that is still a viable token prefix. Worst-case added latency
is one chunk; worst-case holdback is `max_token_len` characters.

Usage:

    rh = session.stream_rehydrator()
    for chunk in model_stream:
        out = rh.feed(chunk)
        if out:
            yield out
    tail = rh.flush()
    if tail:
        yield tail
"""

from __future__ import annotations

import re

from .session import TOKEN_RE, ScrubSession

# A trailing run that could still grow into a full token: '[' followed only
# by token-body characters, no closing ']' yet.
_PARTIAL_RE = re.compile(r"\[[A-Z0-9_]*\Z")


class StreamRehydrator:
    def __init__(self, session: ScrubSession, max_token_len: int = 64):
        self.session = session
        self.max_token_len = max_token_len
        self._buf = ""

    def feed(self, chunk: str) -> str:
        self._buf += chunk
        return self._drain(final=False)

    def flush(self) -> str:
        """Emit whatever is still held back. Call once, after the stream ends."""
        return self._drain(final=True)

    def _drain(self, final: bool) -> str:
        buf = self._buf
        out: list[str] = []
        pos = 0
        while pos < len(buf):
            i = buf.find("[", pos)
            if i == -1:
                out.append(buf[pos:])
                pos = len(buf)
                break
            out.append(buf[pos:i])
            m = TOKEN_RE.match(buf, i)
            if m is not None:
                token = m.group(0)
                out.append(self.session.lookup(token) or token)
                pos = m.end()
                continue
            rest = buf[i:]
            if not final and len(rest) <= self.max_token_len and _PARTIAL_RE.fullmatch(rest):
                # Still a viable token prefix — hold it for the next chunk.
                pos = i
                break
            out.append("[")
            pos = i + 1
        self._buf = buf[pos:]
        return "".join(out)
