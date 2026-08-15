# Usage Guide

This guide walks through veil's features in order of complexity. Start with
[Basic usage](#basic-usage) and read as far as you need.

## Basic usage

Scrub a string, send the cleaned version to your LLM, then re-hydrate the
response:

```python
from veil import Scrubber

scrubber = Scrubber()

result = scrubber.scrub("Email jane@acme.com about card 4111 1111 1111 1111.")
result.text
# 'Email [EMAIL_1] about card [CREDIT_CARD_1].'

# ... send result.text to the LLM ...
response = "Drafted the note to [EMAIL_1]."

scrubber.rehydrate(response, result.session)
# 'Drafted the note to jane@acme.com.'
```

## Message lists (OpenAI / Anthropic)

Pass full conversation arrays directly — both OpenAI and Anthropic content
block shapes are handled. The input list is never mutated.

```python
messages = [
    {"role": "system", "content": "You are a support agent."},
    {"role": "user", "content": "Customer jane@acme.com reports SSN 219-09-9999 leaked."},
]
result = scrubber.scrub_messages(messages)
result.messages[1]["content"]
# 'Customer [EMAIL_1] reports SSN [US_SSN_1] leaked.'
```

## Streaming responses

The stream re-hydrator handles tokens split across chunks:

```python
rh = scrubber.stream_rehydrator(result.session)
for chunk in llm_stream:
    out = rh.feed(chunk)
    if out:
        yield out
tail = rh.flush()       # always call once at end-of-stream
if tail:
    yield tail
```

## Multi-turn sessions

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

Every entity type gets a rule: an action plus a confidence floor. Unknown
types fall through to the default rule automatically.

| Action | Effect | Reversible |
|---|---|---|
| `TOKENIZE` | replace with `[TYPE_N]` session token | yes |
| `MASK` | replace with `[REDACTED_TYPE]` | no |
| `BLOCK` | raise `PIIBlockedError` | — |
| `ALLOW` | pass through unchanged | — |

```python
from veil import Action, Policy, Rule, Scrubber, PIIBlockedError

policy = Policy(
    rules={
        "CREDIT_CARD":    Rule(Action.BLOCK),
        "AWS_ACCESS_KEY": Rule(Action.BLOCK),
        "EMAIL":          Rule(Action.TOKENIZE),
        "PHONE":          Rule(Action.TOKENIZE, min_confidence=0.6),
        "IP_ADDRESS":     Rule(Action.ALLOW),
    },
    default=Rule(Action.TOKENIZE, min_confidence=0.5),
)

scrubber = Scrubber(policy=policy)
try:
    scrubber.scrub("charge 4111 1111 1111 1111")
except PIIBlockedError as e:
    audit_log(e.findings)
```

## Allowlisting

Skip known-safe values so they don't produce findings:

```python
import re
from veil import Scrubber

scrubber = Scrubber(
    allowlist={"test@example.com"},
    allowlist_patterns=[re.compile(r".*@mycompany\.com")],
)
```

## NER detection (Tier 2)

The built-in detectors handle structured PII (emails, cards, phones, etc.).
For free-text names, organizations, and locations, add NER:

```bash
pip install -e ".[ner]"
python -m spacy download en_core_web_sm
```

```python
from veil import Scrubber, default_detectors
from veil.detectors.ner import ner_detectors

scrubber = Scrubber(detectors=default_detectors() + ner_detectors())
```

NER detectors implement the same `Detector` protocol — the engine treats
their findings identically to regex findings.

For model selection (multilingual, transformer, performance trade-offs),
see the **[NER Models Reference](ner-models.md)**.

## Locale packs

Opt-in packs that add locale-specific regex detectors and/or translated
context keywords for `DATE_OF_BIRTH` and `PASSPORT`:

```python
from veil import Scrubber, default_detectors
from veil.detectors.locale import locale_detectors

# Single locale
scrubber = Scrubber(detectors=default_detectors() + locale_detectors("DE"))

# Stack multiple
scrubber = Scrubber(
    detectors=default_detectors()
              + locale_detectors("DE")
              + locale_detectors("FR")
)
```

Locale packs compose with NER — add both:

```python
from veil.detectors.ner import ner_detectors

scrubber = Scrubber(
    detectors=default_detectors()
              + ner_detectors(model="de_core_news_sm")
              + locale_detectors("DE")
)
```

For the full list of available locales and what each provides, see the
**[Detector Reference](detectors.md#locale-packs)**.

## Custom detectors

A detector is anything with a `name` and `detect(text) -> list[Finding]`.

```python
from veil import ContextBooster, Finding, RegexDetector, Scrubber, default_detectors

# Option 1: declarative regex + optional validator
employee_id = RegexDetector("EMPLOYEE_ID", r"\bEMP-\d{6}\b", confidence=0.95)

# Option 2: any class implementing the protocol
class NameDetector:
    name = "ner:person"
    def detect(self, text):
        return [
            Finding("PERSON", s.start, s.end, s.text, s.score, self.name)
            for s in my_ner_model(text)
        ]

# Option 3: context-gated (fires only near keywords)
mrn = ContextBooster(
    RegexDetector("MRN", r"\b\d{7}\b", confidence=0.4),
    keywords=["medical record", "mrn", "patient id"],
    boost=0.45,
    window=60,
)

scrubber = Scrubber(detectors=default_detectors() + [employee_id, mrn])
```

The policy covers new entity types automatically via the default rule; add
an explicit rule when they need different handling.

## Integration pattern

The pattern is always the same three lines around your provider call:

```python
def guarded_completion(client, messages, session):
    scrubbed = scrubber.scrub_messages(messages, session)
    response = client.chat.completions.create(
        model=MODEL, messages=scrubbed.messages
    )
    return scrubber.rehydrate(
        response.choices[0].message.content, session
    )
```

## What veil does not cover (yet)

- **GDPR Article 9 categories** (health, religion, sexual orientation) need
  semantic classifiers. Tier 3 LLM-based detection is planned.
- **Network gateway** mode (zero-app-change, org-wide enforcement) is a
  planned layer on top of this engine.
- No detector reaches 100% recall — veil is risk reduction and policy
  enforcement, one layer of a defense-in-depth story.
