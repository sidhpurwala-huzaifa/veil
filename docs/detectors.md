# Detector Reference

All built-in detectors, their validators, and locale-specific extensions.

## Built-in detectors (Tier 1)

Every built-in is a regex gated by a structural or checksum validator where
one exists. Confidence reflects how much a match alone proves. Overlaps are
resolved in favor of higher confidence, then longer span.

### Structured PII

| Entity | Validator | Confidence |
|---|---|---|
| `EMAIL` | URL-context exclusion | 0.95 |
| `CREDIT_CARD` | Luhn mod-10 | 0.99 |
| `US_SSN` | dashed form, area-number rules, ITIN exclusion | 0.85 |
| `US_ITIN` | IRS range rules | 0.85 |
| `PHONE` | 10-15 digit count, international formats, version exclusion | 0.65 |
| `IBAN` | ISO 13616 mod-97 | 0.99 |
| `DATE_OF_BIRTH` | calendar date + keyword context required | context-gated |
| `PASSPORT` | 6-9 digits (optional letter prefix) + keyword context | context-gated |

### Infrastructure identifiers

| Entity | Validator | Confidence |
|---|---|---|
| `IP_ADDRESS` | octet range, RFC 5737 exclusion | 0.90 |
| `IPV6_ADDRESS` | structural validation | 0.90 |
| `MAC_ADDRESS` | -- | 0.85 |
| `URL` | `https?://...` | 0.70 |

### Secrets and credentials

| Entity | Validator | Confidence |
|---|---|---|
| `AWS_ACCESS_KEY` | AKIA/ASIA prefix format | 0.99 |
| `PRIVATE_KEY` | PEM block delimiters | 0.99 |
| `SLACK_TOKEN` | `xox[bpras]-...` prefix | 0.99 |
| `JWT` | base64url structure check | 0.95 |
| `GCP_API_KEY` | `AIza...` prefix | 0.95 |
| `API_KEY` | `sk-...`, `sk-ant-...`, `sk_live_...`, `ghp_...` | 0.95 |
| `GENERIC_SECRET` | `password=...`, `secret:...` key-value patterns | 0.70 |

### Context-gated detectors

`DATE_OF_BIRTH` and `PASSPORT` are too noisy without context. They only fire
when a keyword appears within 80 characters of the match:

- **DATE_OF_BIRTH** keywords (English): "dob", "born", "birthday",
  "date of birth", "birth date", "birthdate"
- **PASSPORT** keywords (English): "passport", "passport number",
  "passport no", "passport#"

Locale packs add translated keywords (see below). You can also create your
own context-gated detector with `ContextBooster` — see the
[Usage Guide](guide.md#custom-detectors).

## NER detectors (Tier 2)

Detects `PERSON_NAME`, `ORGANIZATION`, `LOCATION`, `DATE_TIME`, and
`NORP_GROUP` from free text using spaCy models. Requires the `[ner]` extra.

For the full model catalog, language support, and performance data, see the
**[NER Models Reference](ner-models.md)**.

## Locale packs

Opt-in packs activated via `locale_detectors("XX")`. Each pack can provide
regex detectors, translated context keywords, or both.

### Packs with regex detectors

| Locale | Entity | Validator |
|---|---|---|
| `GB` | `UK_NINO` (National Insurance Number) | NINO prefix rules |
| `CA` | `CA_SIN` (Social Insurance Number) | Luhn mod-10 (9-digit) |
| `IN` | `AADHAAR` (Unique ID) | Verhoeff checksum |
| `EU` | `EU_VAT` (VAT identification number) | structural |

### Packs with context keywords

These packs add translated keywords so `DATE_OF_BIRTH` and `PASSPORT`
fire on non-English text:

| Locale | DOB keywords | PASSPORT keywords |
|---|---|---|
| `DE` | Geburtsdatum, geboren, geb. | Reisepass, Passnummer, Ausweisnummer |
| `FR` | date de naissance, ne le, nee le | passeport, numero de passeport |
| `ES` | fecha de nacimiento, nacido el | pasaporte, numero de pasaporte |
| `PT` | data de nascimento, nascido em | passaporte, numero do passaporte |
| `IT` | data di nascita, nato il | passaporto, numero di passaporto |
| `RU` | дата рождения | паспорт, номер паспорта |
| `ZH` | 出生日期, 生日 | 护照, 护照号码 |
| `JA` | 生年月日 | パスポート, 旅券番号 |
| `KO` | 생년월일 | 여권, 여권번호 |
| `AR` | تاريخ الميلاد, تاريخ الولادة | جواز سفر, رقم جواز السفر |
| `HE` | תאריך לידה | דרכון, מספר דרכון |
| `TH` | วันเกิด, วันเดือนปีเกิด | หนังสือเดินทาง |
| `IN` | जन्म तिथि, जन्म दिनांक | पासपोर्ट |

### Adding a new locale

A single `_register()` call in `locale.py`:

```python
_register("XX", [],                              # no regex detectors
    dob_keywords=["keyword1", "keyword2"],
    passport_keywords=["keyword3"],
)
```

Or with regex detectors:

```python
_register("XX", [
    RegexDetector("XX_ID", r"\b\d{10}\b", confidence=0.90),
],
    dob_keywords=["keyword1"],
)
```
