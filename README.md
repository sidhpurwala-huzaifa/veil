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
pip install -e ".[dev]"       # core + test dependencies
pip install -e ".[ner,dev]"   # include Tier 2 NER (spaCy)
pytest                         # 146 tests, <3s
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
| `PRIVATE_KEY` | PEM block delimiters | 0.99 |
| `SLACK_TOKEN` | `xox[bpras]-…` prefix | 0.99 |
| `JWT` | base64url structure check | 0.95 |
| `GCP_API_KEY` | `AIza…` prefix | 0.95 |
| `API_KEY` | `sk-…`, `sk-ant-…`, `sk_live_…`, `ghp_…` | 0.95 |
| `EMAIL` | URL-context exclusion | 0.95 |
| `IP_ADDRESS` | octet range, RFC 5737 exclusion | 0.90 |
| `IPV6_ADDRESS` | structural validation | 0.90 |
| `US_SSN` | dashed form, area-number rules, ITIN exclusion | 0.85 |
| `US_ITIN` | IRS range rules | 0.85 |
| `MAC_ADDRESS` | — | 0.85 |
| `URL` | `https?://…` | 0.70 |
| `GENERIC_SECRET` | `password=…`, `secret:…` key-value patterns | 0.70 |
| `PHONE` | 10–15 digit count, version-string exclusion | 0.65 |
| `DATE_OF_BIRTH` | calendar date + keyword context required | context-gated |
| `PASSPORT` | 6–9 digits (optional letter prefix) + keyword context | context-gated |

Overlaps (a card number that also looks phone-shaped) are resolved in favor
of higher confidence, then longer span.

### Context-gated detectors

Some patterns (dates, passport numbers) are too noisy without context.
`DATE_OF_BIRTH` and `PASSPORT` only fire when a keyword like "dob",
"birthday", or "passport" appears nearby. Locale packs add translated
keywords (e.g. `locale_detectors("DE")` adds "Geburtsdatum", "Reisepass").
Under the hood these use `ContextBooster`, which you can also apply to your
own detectors:

```python
from veil import ContextBooster, RegexDetector

my_detector = ContextBooster(
    RegexDetector("MRN", r"\b\d{7}\b", confidence=0.4),
    keywords=["medical record", "mrn", "patient id"],
    boost=0.45,
    window=60,
)
```

### Allowlisting

Skip known-safe values so they don't produce findings:

```python
import re
from veil import Scrubber

scrubber = Scrubber(
    allowlist={"test@example.com"},
    allowlist_patterns=[re.compile(r".*@mycompany\.com")],
)
```

### Locale packs

Opt-in packs that add locale-specific regex detectors **and/or** translated
context keywords for `DATE_OF_BIRTH` and `PASSPORT`. Stack as many as you
need — overlap resolution handles the rest.

```python
from veil import Scrubber, default_detectors
from veil.detectors.locale import locale_detectors, available_locales

# Single locale
scrubber = Scrubber(detectors=default_detectors() + locale_detectors("GB"))

# Multiple locales
scrubber = Scrubber(
    detectors=default_detectors()
              + locale_detectors("DE")
              + locale_detectors("FR")
)

# See what's available
print(available_locales())
```

| Locale | Regex detectors | Context keywords |
|---|---|---|
| `GB` | `UK_NINO` (National Insurance Number) | — |
| `CA` | `CA_SIN` (Social Insurance Number, Luhn-validated) | — |
| `IN` | `AADHAAR` (Verhoeff checksum) | DOB, PASSPORT (Hindi) |
| `EU` | `EU_VAT` (VAT identification numbers) | — |
| `DE` | — | DOB ("Geburtsdatum", "geboren"), PASSPORT ("Reisepass", "Passnummer") |
| `FR` | — | DOB ("date de naissance", "né le"), PASSPORT ("passeport") |
| `ES` | — | DOB ("fecha de nacimiento"), PASSPORT ("pasaporte") |
| `PT` | — | DOB ("data de nascimento"), PASSPORT ("passaporte") |
| `IT` | — | DOB ("data di nascita"), PASSPORT ("passaporto") |
| `RU` | — | DOB ("дата рождения"), PASSPORT ("паспорт") |
| `ZH` | — | DOB ("出生日期", "生日"), PASSPORT ("护照") |
| `JA` | — | DOB ("生年月日"), PASSPORT ("パスポート", "旅券番号") |
| `KO` | — | DOB ("생년월일"), PASSPORT ("여권") |
| `AR` | — | DOB ("تاريخ الميلاد"), PASSPORT ("جواز سفر") |
| `HE` | — | DOB ("תאריך לידה"), PASSPORT ("דרכון") |
| `TH` | — | DOB ("วันเกิด"), PASSPORT ("หนังสือเดินทาง") |

Adding a new locale is a single `_register()` call in `locale.py` — see the
existing packs for the pattern.

## Writing a custom detector

A detector is anything with a `name` and `detect(text) -> list[Finding]`.

```python
from veil import ContextBooster, Finding, RegexDetector, Scrubber, default_detectors

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

## Tier 2: NER detection (optional)

The built-in Tier 1 detectors handle structured PII. For free-text names,
organizations, and locations, enable Tier 2 NER via the `[ner]` extra:

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
their findings identically to regex findings. See [`docs/ner-models.md`](docs/ner-models.md)
for available spaCy models, multilingual setup, and performance data.

## What this is not (yet)

- **Not an LLM detection tier** — GDPR Article 9 categories (health,
  religion, sexual orientation…) need semantic classifiers. Tier 2 NER
  covers names/orgs/locations; Tier 3 LLM classifiers are the planned next
  step. The `Detector` protocol is the seam where those land.
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
  types.py           Finding, Action, PIIBlockedError
  policy.py          Rule, Policy
  detectors/
    base.py          Detector protocol, RegexDetector
    builtin.py       20 built-in detectors (default_detectors())
    validators.py    Luhn, IBAN, Verhoeff, IPv4/6, date, JWT, NINO, etc.
    context.py       ContextBooster — keyword-proximity confidence scoring
    filters.py       FilteredDetector — allowlist/denylist wrapper
    locale.py        Opt-in locale packs (17 locales) + context keywords
    ner.py           Tier 2 NER via spaCy (requires [ner] extra)
  session.py         ScrubSession — reversible token map, serialization
  streaming.py       StreamRehydrator — chunk-boundary-safe re-hydration
  engine.py          Scrubber — detect → policy → transform, message helpers
tests/
docs/
  ner-models.md      spaCy model reference (languages, sizes, performance)
```

See **ARCHITECTURE.md** for the design rationale, invariants, and roadmap.

## License

Apache-2.0
