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

- **Zero runtime dependencies.** Pure Python 3.10+, stdlib only for the core.
- **Reversible by default.** Same value always maps to the same token within a
  session — multi-turn coherence and re-hydration are dictionary lookups.
- **Streaming-safe.** Handles tokens split across response chunks.
- **Extensible.** NER models, LLM classifiers, and org-specific matchers plug
  into the same pipeline as the 20 built-in regex detectors.

## Install

```bash
pip install -e ".[dev]"          # core + test deps
pip install -e ".[ner,dev]"      # add Tier 2 NER (spaCy)
pytest                            # 146 tests, <3s
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

## Documentation

| Doc | What it covers |
|---|---|
| **[Usage Guide](docs/guide.md)** | Messages, streaming, multi-turn sessions, policy, NER, locale packs, custom detectors, integration patterns |
| **[Detector Reference](docs/detectors.md)** | All 20 built-in entity types, validators, confidence scores, locale packs |
| **[NER Models](docs/ner-models.md)** | spaCy model catalog — languages, sizes, label mapping, performance |
| **[Architecture](ARCHITECTURE.md)** | Design rationale, invariants, component map, roadmap |

## Project layout

```
src/veil/
  engine.py          Scrubber — detect → policy → transform
  types.py           Finding, Action, PIIBlockedError
  policy.py          Rule, Policy
  session.py         ScrubSession — reversible token map
  streaming.py       StreamRehydrator — chunk-boundary-safe
  detectors/
    base.py          Detector protocol, RegexDetector
    builtin.py       20 built-in detectors
    validators.py    Luhn, IBAN, Verhoeff, date, etc.
    context.py       ContextBooster
    filters.py       FilteredDetector (allowlist/denylist)
    locale.py        17 locale packs
    ner.py           Tier 2 NER via spaCy (requires [ner] extra)
tests/
docs/
```

## License

Apache-2.0
