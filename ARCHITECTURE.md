# veil — Architecture

This document records why the library is shaped the way it is, the invariants
future code must preserve, and the roadmap from embeddable SDK to enterprise
gateway. Read it before adding a detector tier, a persistence backend, or a
deployment mode.

## 1. Problem statement

Enterprises sending traffic to frontier LLM APIs (Anthropic, OpenAI, …) leak
PII in prompts. The goal is a layer that:

1. detects sensitive data in outbound text,
2. removes it **before it crosses the enterprise boundary**,
3. lets the model still produce a useful answer, and
4. restores the real values in the response on the way back — including
   streaming responses.

(3) and (4) are what separate this from classic DLP redaction: irreversible
masking breaks the product ("email {NAME} about {EMAIL}" is a useless answer).
Reversibility is therefore a core design constraint, not a feature.

## 2. Lessons taken from the field (survey, Aug 2026)

The design deliberately borrows the best pattern from each shipping system
and avoids their verified failure modes:

| System | Pattern adopted | Failure mode avoided |
|---|---|---|
| LiteLLM + Presidio | per-entity action + confidence-threshold policy; token echo re-hydration | streaming unmask assumed normalized response objects; on Anthropic's native SSE path chunks passed through as raw bytes and **unmasking silently never ran** (issue #22821) — users received `<PERSON>` placeholders |
| Skyflow LLM Privacy Vault | deterministic, reversible tokenization; detokenization as a separately-permissioned operation | vendor cloud dependency — veil's core is self-contained |
| AWS Bedrock Guardrails | policy evaluation decoupled from any one call path (reusable in RAG/batch) | irreversible `{NAME}` masking; **its own logs retained unmodified input** — an audit layer must never see raw PII |
| Cloudflare AI Security | parallel detectors under a hard latency budget with graceful fallback (planned, tier 2/3) | block-or-log only, prompts only — no redaction, no response handling |

Benchmark evidence that shaped the detection design: on multilingual,
PII-specific data (REDACT, 2026), default rule-based detection scores
micro-F1 ≈ 0.2 and — critically — recall ≈ 0.07 on GDPR Article 9 categories
(health, religion, sexual orientation, ethnicity, union membership), while
zero-shot frontier-LLM detectors score 0.6+ with 0.74–0.77 recall on the same
tier. On well-covered English structured entities, regex+checksum and tuned
lightweight models are competitive. Conclusion baked into the architecture:

- **Tier 1 (shipped):** regex + checksum validators. Deterministic, auditable,
  fast, zero dependencies. The floor, never the ceiling.
- **Tier 2 (planned plugin):** NER span models for names/addresses/orgs.
- **Tier 3 (planned plugin):** LLM classifier for semantic and Article 9
  categories. Non-deterministic, so it must be *additive* detection — never
  the sole mechanism on a compliance-critical path, and its findings carry
  its own confidence so policy thresholds stay meaningful.

All three tiers implement the same `Detector` protocol; the engine does not
know or care which tier a finding came from.

## 3. Component map

```
                       ┌────────────────────────────────────────────┐
 text / messages ────► │ Scrubber (engine.py)                       │
                       │   1. run every Detector        detectors/  │
                       │   2. apply Policy per finding  policy.py   │
                       │      ├─ ALLOW / below threshold → drop     │
                       │      ├─ BLOCK → raise PIIBlockedError      │
                       │      └─ TOKENIZE / MASK → transform        │
                       │   3. resolve overlapping spans             │
                       │   4. replace right-to-left                 │
                       └───────────────┬────────────────────────────┘
                                       │ tokenize(value) ⇄ lookup(token)
                       ┌───────────────▼────────────────────────────┐
                       │ ScrubSession (session.py)                  │
                       │   deterministic token map, per-type        │
                       │   counters, to_dict()/from_dict()          │
                       └───────────────┬────────────────────────────┘
                                       │
 LLM response ───────► StreamRehydrator (streaming.py) ───► clean text
 (chunks, any split)     bounded holdback buffer
```

### types.py — data model
`Finding(entity_type, start, end, text, confidence, detector)` is the single
currency between detectors, policy, and engine. Offsets index the exact text
handed to the detector; `text` carries the value so nothing downstream
re-slices. `Action` and `PIIBlockedError` live here so no layer imports
another just for an enum.

### detectors/ — detection tier(s)
`Detector` is a runtime-checkable Protocol: `name` + `detect(text) ->
list[Finding]`. That is the *entire* plugin surface.

`RegexDetector` is the reusable declarative form: pattern + optional
validator + fixed confidence. The validator **gates** rather than down-scores
— a match that fails Luhn is dropped, not emitted at lower confidence — so a
stated confidence is always trustworthy.

Built-in confidence values encode evidence strength: checksum-validated
matches (card, IBAN) are 0.99; format-only matches (email) 0.9–0.95;
ambiguous shapes (phone) 0.65 and rely on the policy floor.

Two composable wrappers sit on top of `Detector`:

- **`ContextBooster`** (context.py) — adjusts confidence based on keyword
  proximity. Context-gated detectors (DOB, passport) use a low base
  confidence that drops below the policy threshold without a keyword, and a
  boost that lifts it past the threshold when context confirms the finding.
- **`FilteredDetector`** (filters.py) — drops findings matching an allowlist
  (exact values or regex patterns). Integrated into `Scrubber` via the
  `allowlist` / `allowlist_patterns` constructor parameters.

The 20 built-in detectors now span structured PII (EMAIL, SSN, ITIN,
CREDIT_CARD, PHONE, IBAN), infrastructure identifiers (IP_ADDRESS,
IPV6_ADDRESS, MAC_ADDRESS, URL), and secrets/credentials (AWS_ACCESS_KEY,
API_KEY, PRIVATE_KEY, JWT, SLACK_TOKEN, GCP_API_KEY, GENERIC_SECRET), plus
two context-gated personal identifiers (DATE_OF_BIRTH, PASSPORT_US).

Locale-specific detectors (UK_NINO, CA_SIN, AADHAAR, EU_VAT) live in
`detectors/locale.py` and are opt-in via `locale_detectors("GB")`.

False-positive hardening: EMAIL rejects matches inside URLs (`://…@…`);
IP_ADDRESS excludes RFC 5737 documentation ranges and broadcast addresses;
PHONE excludes version-string patterns; US_SSN rejects ITIN ranges.

### policy.py — decision layer
`Policy` maps entity type → `Rule(action, min_confidence)`. Unknown types hit
the default rule (TOKENIZE @ 0.5), so registering a new detector is
fail-closed: its findings get scrubbed even before anyone writes a rule.

### session.py — reversibility
Tokens are `[TYPE_N]` — short, readable, uppercase-bracketed. That exact
shape is load-bearing: frontier models echo it verbatim, tokenizers keep it
intact, and `TOKEN_RE` (defined once, here) is shared with the streaming
layer. Determinism (same value → same token within a session) is what keeps
multi-turn conversations coherent and makes re-hydration a dict lookup.

Persistence is deliberately *not* in the core: `to_dict()/from_dict()` is
the contract, and redis/DB/vault backends are the caller's (later, a
`SessionStore` interface's) concern.

### streaming.py — the hard correctness problem
A token can be split anywhere by response chunking. The re-hydrator emits
everything provably outside a token and holds back only a trailing run that
is still a viable token prefix (`[` + token-body chars, no `]` yet), capped
at `max_token_len`. Properties:

- worst-case added latency: one chunk;
- worst-case holdback: `max_token_len` chars;
- text before a held-back partial is emitted immediately (tested);
- unknown token-shaped strings pass through untouched — the model may write
  its own bracketed text.

### engine.py — orchestration
Order of operations in `_actionable_findings` is deliberate:

1. detect (all detectors, all findings);
2. filter by rule action/threshold;
3. **BLOCK check before overlap resolution** — fail closed: a blockable
   finding blocks the request even if an overlapping higher-confidence
   finding would have won the span;
4. overlap resolution: highest confidence, then longest span, greedy;
5. replacements applied right-to-left so offsets stay valid.

`scrub_messages` walks OpenAI/Anthropic message shapes and scrubs string
values under `content`/`text` keys only (deep-copied, never mutating input),
sharing one session across the whole list.

## 4. Invariants (do not break)

1. **Raw PII never appears in anything designed to persist or leave the
   boundary**: scrubbed text, tokens, `PIIBlockedError` messages (entity
   types only — the findings list carries values for the caller to handle),
   future audit records. The Bedrock CloudWatch gap is the anti-pattern.
2. **Determinism within a session**: same (entity_type, value) → same token,
   including after `from_dict` restore.
3. **Validators gate, never down-score.**
4. **Fail closed**: unknown entity types get the default rule; BLOCK wins
   over overlap resolution; a detector exception should abort the request,
   not skip the detector (currently exceptions propagate — keep it that way).
5. **Streaming re-hydration must be tested against adversarial chunking**
   (char-by-char, split inside `[`, unterminated partials, oversized bracket
   runs). Every new provider adapter re-runs this class of tests against its
   real wire format.
6. **Token shape changes require touching exactly one place** (`TOKEN_RE` in
   session.py) and re-running the streaming suite.
7. **Zero runtime dependencies in the core package.** Model-backed detectors
   live in extras (`veil-pii[ner]`, `veil-pii[llm]`), never in core.

## 5. Extension seams

| Seam | Interface | Status |
|---|---|---|
| Detection | `Detector` protocol | shipped (20 built-ins); NER/LLM tiers plug in here |
| Context scoring | `ContextBooster` wrapper | shipped; keyword-proximity confidence adjustment |
| Allowlisting | `FilteredDetector` wrapper / `Scrubber(allowlist=…)` | shipped; exact values and regex patterns |
| Locale packs | `locale_detectors(locale)` | shipped (GB, CA, IN, EU); add packs by registering in `locale.py` |
| Policy | `Policy`/`Rule` objects | shipped; YAML/policy-pack loader planned |
| Session persistence | `to_dict()/from_dict()` | shipped; `SessionStore` protocol planned (redis, DB, vault service) |
| Transform | `Action` enum | shipped; candidate addition: `SYNTHESIZE` (realistic fake values) for workloads where token shapes confuse the model |
| Providers | none yet | planned: thin adapters wrapping official SDKs (see roadmap) |

## 6. Roadmap

Phased so each stage ships something deployable:

1. **v0.1 (this)** — core SDK: deterministic detectors, policy, reversible
   sessions, streaming re-hydration, message-list helpers.
2. **Provider adapters** — drop-in wrappers for the OpenAI and Anthropic
   Python SDKs (`veil.wrap(client, policy=...)`) so integration is one line;
   per-provider streaming tests against real SSE shapes (the LiteLLM lesson:
   re-hydration must be validated per wire format, not per abstraction).
3. **Detection tier 2/3** — NER plugin (extras dependency) and LLM-classifier
   plugin with a hard latency budget and parallel execution (Cloudflare
   pattern: fire detectors concurrently, hard cap, fall back to completed
   results — configurable fail-open/fail-closed per entity class).
4. **SessionStore + audit** — pluggable persistence; structured audit events
   (detections, policy decisions, detokenizations — never values) with a
   stable schema for SIEM ingestion.
5. **Gateway** — reverse proxy speaking the OpenAI/Anthropic wire formats,
   built on this engine, for zero-app-change org-wide enforcement. Egress to
   provider APIs firewalled to the gateway only. Multi-tenant: per-tenant
   policy packs and session keyspaces.
6. **Detokenization RBAC** — Skyflow's key insight: re-identification is a
   *privilege*, distinct from scrubbing. When the gateway lands, `rehydrate`
   for a given entity class becomes a permission, and every detokenization
   is an audit event.

## 7. Known limitations (v0.1)

- No free-text name/address/health detection — tier 1 is structured PII only.
  Do not deploy this alone against GDPR Article 9 exposure.
- Locale packs (GB, CA, IN, EU) cover the most common identifiers per locale
  but are not exhaustive. Comprehensive locale coverage belongs in tier 2
  planning alongside NER models that handle free-form addresses and names.
- `MASK` output (`[REDACTED_TYPE]`) matches the token character class; it can
  never collide (no trailing `_N`), but a model might echo it — re-hydration
  correctly leaves it untouched.
- Session token maps hold raw values in memory by design (that's what makes
  re-hydration possible). Protecting the session at rest is the persistence
  backend's job — document this loudly in any `SessionStore` implementation.
- No thread-safety guarantees on a shared session yet; one session per
  conversation is the supported pattern.
- Context-gated detectors (`DATE_OF_BIRTH`, `PASSPORT_US`) rely on keyword
  proximity heuristics — they will miss values that appear far from any
  keyword or in unexpected phrasing. Tier 2/3 detectors are needed for
  robust coverage of these categories.
