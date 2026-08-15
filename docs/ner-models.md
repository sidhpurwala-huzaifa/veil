# NER Models Reference

veil's Tier 2 NER detection uses [spaCy](https://spacy.io/) trained
pipelines. You choose which model(s) to load — only the models you need
are downloaded and run.

For setup and basic usage, see the [Usage Guide](guide.md#ner-detection-tier-2).

## Model sizes

Each language offers up to four model sizes:

| Size | Suffix | Vectors | Typical size | Use case |
|---|---|---|---|---|
| Small | `sm` | none | 10–15 MB | Fast, good enough for most NER |
| Medium | `md` | 20k keys | 40–50 MB | Better accuracy, word vectors |
| Large | `lg` | 500k keys | 350–600 MB | Best accuracy without GPU |
| Transformer | `trf` | none | 350–500 MB | Highest accuracy, GPU recommended |

For NER-only workloads, `sm` is usually sufficient. Use `trf` when
accuracy matters more than throughput.

## Available models by language

Every model below includes a NER component. Install with
`python -m spacy download <model name>`.

| Language | Code | Model names | NER labels |
|---|---|---|---|
| **Catalan** | `ca` | `ca_core_news_sm` / `md` / `lg` / `trf` | PER, ORG, LOC, MISC |
| **Chinese** | `zh` | `zh_core_web_sm` / `md` / `lg` / `trf` | PERSON, ORG, GPE, LOC, FAC, DATE, NORP + others |
| **Croatian** | `hr` | `hr_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Danish** | `da` | `da_core_news_sm` / `md` / `lg` / `trf` | PER, ORG, LOC, MISC |
| **Dutch** | `nl` | `nl_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **English** | `en` | `en_core_web_sm` / `md` / `lg` / `trf` | PERSON, ORG, GPE, LOC, FAC, DATE, NORP + others |
| **Finnish** | `fi` | `fi_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **French** | `fr` | `fr_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **German** | `de` | `de_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Greek** | `el` | `el_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Italian** | `it` | `it_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Japanese** | `ja` | `ja_core_news_sm` / `md` / `lg` / `trf` | PERSON, ORG, GPE, LOC, FAC, DATE, NORP + others |
| **Korean** | `ko` | `ko_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Lithuanian** | `lt` | `lt_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Macedonian** | `mk` | `mk_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Multi-language** | `xx` | `xx_ent_wiki_sm` | PER, ORG, LOC, MISC |
| **Norwegian** | `nb` | `nb_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Polish** | `pl` | `pl_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Portuguese** | `pt` | `pt_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Romanian** | `ro` | `ro_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Russian** | `ru` | `ru_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Slovenian** | `sl` | `sl_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Spanish** | `es` | `es_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Swedish** | `sv` | `sv_core_news_sm` / `md` / `lg` | PER, ORG, LOC, MISC |
| **Ukrainian** | `uk` | `uk_core_news_sm` / `md` / `trf` | PER, ORG, LOC, MISC |

## NER label → veil entity type mapping

veil maps spaCy labels to veil entity types automatically. Both naming
conventions (English-style and multilingual-style) are handled by the
default entity map — you don't need to configure anything when switching
models.

| spaCy label | Used by | veil entity type |
|---|---|---|
| `PERSON` | English, Chinese, Japanese | `PERSON_NAME` |
| `PER` | All other languages, multi-language | `PERSON_NAME` |
| `ORG` | All models | `ORGANIZATION` |
| `GPE` | English, Chinese, Japanese | `LOCATION` |
| `LOC` | All models | `LOCATION` |
| `FAC` | English, Chinese, Japanese | `LOCATION` |
| `DATE` | English, Chinese, Japanese | `DATE_TIME` |
| `NORP` | English, Chinese, Japanese | `NORP_GROUP` |
| `MISC` | Most non-English models | *(unmapped — ignored)* |

## Choosing models for your data

### Single-language data

Use the language-specific model. It will be more accurate than the
multi-language model for that language.

```python
# German customer data
ner_detectors(model="de_core_news_sm")

# Japanese logs
ner_detectors(model="ja_core_news_sm")
```

### Multilingual data (known languages)

Pass one model per language you expect. Each model runs one pass over
the text; the engine deduplicates overlapping findings automatically.

```python
# Customer support in English, French, and Spanish
ner_detectors(model=["en_core_web_sm", "fr_core_news_sm", "es_core_news_sm"])
```

### Multilingual data (unknown or many languages)

Use the multi-language model (`xx_ent_wiki_sm`) alongside your primary
language model. The `xx` model covers 176 languages at lower accuracy.

```python
# English-primary with multilingual fallback
ner_detectors(model=["en_core_web_sm", "xx_ent_wiki_sm"])
```

### Maximum accuracy (English)

Use the transformer model. Requires more memory and benefits from a GPU,
but produces significantly better NER results.

```python
# High-accuracy English NER
ner_detectors(model="en_core_web_trf")
```

## Performance characteristics

Measured on 1,000 REDACT benchmark records (mixed PII text, ~200 words
average).

| Model | Time (1k records) | Memory | Download |
|---|---|---|---|
| `en_core_web_sm` | ~2s | ~50 MB | 13 MB |
| `en_core_web_lg` | ~3s | ~600 MB | 560 MB |
| `en_core_web_trf` | ~310s (CPU) | ~1.5 GB | 400 MB |
| `xx_ent_wiki_sm` | ~3s | ~50 MB | 15 MB |

Transformer models are 50–100× faster on GPU.

## Custom entity map

Override the label-to-type mapping if you need different behavior:

```python
NerDetector(
    model="en_core_web_sm",
    entity_map={
        "PERSON": "FULL_NAME",     # use a custom type name
        "ORG": "ORGANIZATION",
        "GPE": "LOCATION",
        # omit DATE to ignore date entities
    },
)
```
