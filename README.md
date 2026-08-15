# veil

**PII scrubbing layer for LLM API traffic.** Detect sensitive data in prompts,
replace it with reversible session tokens *before* it leaves your boundary, and
re-hydrate the model's response — streaming or not — on the way back.

> Working title. Rename the package before publishing; nothing in the code
> depends on the name.

```
your app ──► veil.scrub() ──► [EMAIL_1], [CREDIT_CARD_1] ──► frontier LLM
your app ◄── veil.rehydrate() ◄── response with tokens ◄─────────┘
```

The model never sees the real values. Your users never see the tokens.

- **Zero runtime dependencies.** Pure Python 3.10+, stdlib only. The core
  detection tier is regex + checksum validators (Luhn, IBAN mod-97) —
  deterministic and auditable, which is what a compliance-critical path needs
  as its floor.
- **Reversible by default.** Tokenization is session-scoped and deterministic:
  the same value always maps to the same token within a session, so the model
  reasons coherently across turns and re-hydration is a dictionary lookup.
- **Streaming-safe.** The stream re-hydrator handles tokens split across
  response chunks with bounded holdback — the failure mode that has bitten
  production gateways.
- **Extensible.** Detectors, policies, and session persistence are all small
  interfaces. NER models, LLM classifiers, and org-specific matchers plug into
  the same pipeline as the built-ins.

## Install

```bash
pip install -e ".[dev]"   # from a checkout
pytest                     # 36 tests, <1s
```

## Quickstart

```python
from veil import Scrubber

scrubber = Scrubber()

result = scrubber.scrub("Email jane@acme.com about card 4111 1111 1111 1111.")
result.text
# 'Email [EMAIL_1] about card [CREDIT_CARD_1].'

# ... send result.text to the LLM ...
response = 'Drafted the note to [EMAIL_1].'

scrubber.rehydrate(response, result.session)
# 'Drafted the note to jane@acme.com.'
```

### Scrubbing full message lists (OpenAI / Anthropic shapes)

```python
messages = [
    {"role": "system", "content": "You are a support agent."},
    {"role": "user", "content": "Customer jane@acme.com reports SSN 219-09-9999 leaked."},
]
result = scrubber.scrub_messages(messages)
result.messages[1]["content"]
# 'Customer [EMAIL_1] reports SSN [US_SSN_1] leaked.'
```

Anthropic-style content blocks (`content: [{"type": "text", "text": ...}]`)
are handled by the same call. The input list is never mutated.

### Streaming responses

```python
rh = scrubber.stream_rehydrator(result.session)
for chunk in llm_stream:            # chunks may split a token anywhere
    out = rh.feed(chunk)
    if out:
        yield out
tail = rh.flush()                   # always call once at end-of-stream
if tail:
    yield tail
```

### Multi-turn conversations

Reuse one session per conversation so tokens stay stable across turns:

```python
from veil import ScrubSession

session = ScrubSession()
r1 = scrubber.scrub(turn_1_text, session)
r2 = scrubber.scrub(turn_2_text, session)   # same email -> same [EMAIL_1]

# persist between requests however you like
saved = session.to_dict()
session = ScrubSession.from_dict(saved)
```

## Policy

Every entity class gets a rule: an action plus a confidence floor. Unknown
entity types fall through to the default rule, so a newly added detector is
covered the moment it's registered.

| Action | Effect | Reversible |
|---|---|---|
| `TOKENIZE` | replace with `[TYPE_N]` session token | yes |
| `MASK` | replace with `[REDACTED_TYPE]` | no |
| `BLOCK` | raise `PIIBlockedError`, request must not be sent | — |
| `ALLOW` | pass through | — |

```python
from veil import Action, Policy, Rule, Scrubber, PIIBlockedError

policy = Policy(
    rules={
        "CREDIT_CARD":    Rule(Action.BLOCK),           # never leaves, even tokenized
        "AWS_ACCESS_KEY": Rule(Action.BLOCK),
        "EMAIL":          Rule(Action.TOKENIZE),
        "PHONE":          Rule(Action.TOKENIZE, min_confidence=0.6),
        "IP_ADDRESS":     Rule(Action.ALLOW),           # fine for this workload
    },
    default=Rule(Action.TOKENIZE, min_confidence=0.5),  # everything else
)

scrubber = Scrubber(policy=policy)
try:
    scrubber.scrub("charge 4111 1111 1111 1111")
except PIIBlockedError as e:
    audit_log(e.findings)   # entity types + spans, never send the request
```

## Built-in detectors

Deterministic tier only — every built-in is a regex gated by a structural or
checksum validator where one exists. Confidence reflects how much a match
alone proves.

| Entity | Validator | Confidence |
|---|---|---|
| `CREDIT_CARD` | Luhn mod-10 | 0.99 |
| `IBAN` | ISO 13616 mod-97 | 0.99 |
| `AWS_ACCESS_KEY` | AKIA/ASIA prefix format | 0.99 |
| `API_KEY` | `sk-…`, `ghp_…` formats | 0.95 |
| `EMAIL` | — | 0.95 |
| `IP_ADDRESS` | octet range check | 0.90 |
| `US_SSN` | dashed form, area-number rules | 0.85 |
| `PHONE` | 10–15 digit count | 0.65 |

Overlaps (a card number that also looks phone-shaped) are resolved in favor
of higher confidence, then longer span.

## Writing a custom detector

A detector is anything with a `name` and `detect(text) -> list[Finding]`.

```python
from veil import Finding, RegexDetector, Scrubber, default_detectors

# 1. declarative: regex + optional validator
employee_id = RegexDetector(
    "EMPLOYEE_ID", r"\bEMP-\d{6}\b", confidence=0.95,
)

# 2. anything else: implement the protocol (NER model, LLM call, dictionary…)
class NameDetector:
    name = "ner:person"
    def detect(self, text):
        return [
            Finding("PERSON", s.start, s.end, s.text, s.score, self.name)
            for s in my_ner_model(text)
        ]

scrubber = Scrubber(detectors=default_detectors() + [employee_id, NameDetector()])
```

The policy covers new entity types automatically via the default rule; add an
explicit rule when they need different handling.

## Integrating with an existing harness

The pattern is always the same three lines around your provider call:

```python
def guarded_completion(client, messages, session):
    scrubbed = scrubber.scrub_messages(messages, session)          # outbound
    response = client.chat.completions.create(model=MODEL,
                                              messages=scrubbed.messages)
    return scrubber.rehydrate(response.choices[0].message.content,  # inbound
                              session)
```

## What this is not (yet)

- **Not an NER/LLM detection tier** — the built-ins won't catch free-text
  names, addresses, or GDPR Article 9 categories (health, religion, sexual
  orientation…). The `Detector` protocol is the seam where those land.
  Rule-based detection alone benchmarks very poorly on that data; see
  ARCHITECTURE.md.
- **Not a network gateway** — this is the embeddable core. The reverse-proxy
  deployment (zero app changes, org-wide enforcement) is a planned layer on
  top of this same engine.
- **Not a guarantee** — no detector reaches 100% recall. veil is risk
  reduction and policy enforcement, one layer of a defense-in-depth story.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

Layout:

```
src/veil/
  types.py        Finding, Action, PIIBlockedError
  policy.py       Rule, Policy
  detectors/      Detector protocol, RegexDetector, validators, built-ins
  session.py      ScrubSession — reversible token map, serialization
  streaming.py    StreamRehydrator — chunk-boundary-safe re-hydration
  engine.py       Scrubber — detect → policy → transform, message helpers
tests/
```

See **ARCHITECTURE.md** for the design rationale, invariants, and roadmap.

## License

Apache-2.0
