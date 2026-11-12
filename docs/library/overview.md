# The VecShield detection library — overview

The `vecshield` library is a **local PII safety gate** for AI data pipelines. It
detects and redacts sensitive data before it is embedded into a vector store or
trained into a model.

## What it does

| Capability | CLI | SDK |
|---|---|---|
| Classify a string/file | `vecshield detect` | `check_text()` |
| Gate chunks before embedding | `vecshield ingest-check` | `check_chunks()` |
| Scan a training dataset | `vecshield training-check` | `check_dataset()` |
| Preview redaction | `vecshield redact-preview` | `redact_text()` |

## What it detects

- **PII (personal identifiers)**
  - US: SSN, phone, date of birth, street address, ZIP code, driver's license,
    passport, EIN/tax ID, ITIN
  - UK: National Insurance number, UTR (Unique Taxpayer Reference)
  - Canada: Social Insurance Number (SIN)
  - India: PAN card, Aadhaar number
  - Brazil: CPF (Cadastro de Pessoas Físicas, checksum-validated)
  - China: Resident Identity Card (18-digit, checksum-validated)
  - Singapore: NRIC / FIN (checksum-validated)
  - Italy: Codice fiscale
  - Mexico: CURP
  - Netherlands: BSN (Burgerservicenummer, elfproef-validated)
  - South Africa: National ID (Luhn-validated)
  - Australia: Tax File Number (checksum-validated)
  - General: email, IPv4/IPv6, MAC address, metadata identifiers
- **PHI (health information)**
  - US: Medical record numbers, Medicare MBI, NPI, DEA number (checksum-validated)
  - UK: NHS number (mod-11 validated)
  - Clinical: ICD-9/ICD-10 diagnosis codes
- **PCI (payment card data)**
  - Credit/debit card numbers (Luhn-validated), IBAN (structure-validated),
    SWIFT/BIC codes, CVV/CVC, card expiry date
- **Secrets / credentials**
  - Cloud & infra: AWS access keys, private key blocks, JWTs, bearer tokens
  - AI/ML platforms: OpenAI, Anthropic, Hugging Face, Google API keys
  - Dev & CI: GitHub tokens, npm tokens, SendGrid, Slack tokens
  - Database connection strings with embedded credentials
  - HTTP Basic auth headers, generic secret context patterns
  - Stripe API keys

Detection is a high-precision regex layer, optionally combined with a
higher-recall NLP layer (Presidio + spaCy) when you install `vecshield[nlp]`.

## Design principles

- **Local-only.** No service, no account, no telemetry.
- **CI-friendly.** Every command emits `--json` and exits `2` on a policy
  failure.
- **Dependency-light core.** Heavy detectors and dataset formats are optional
  extras behind lazy imports.
