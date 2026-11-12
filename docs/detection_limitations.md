# Detection limitations, by regulation

What the detector engine recognises, measured against what the frameworks in
the criterion pack actually define as protected data — and what it therefore
cannot see.

**Read this as analysis, not regulatory advice.** It has not been reviewed by a
qualified practitioner. It follows the same rule as the criterion pack: where
something is uncertain it is marked uncertain rather than stated, and
confidence is flagged per item. Detection is not legal compliance, and nothing
here establishes it.

The gap analysis in §2 onwards was written against an earlier state of the
engine. Several of the gaps it names have since been closed; §0 says which,
and §1 records the baseline it was written against. The analysis is kept intact
because it states *why* each gap matters and where the evidence is thin.

---

## 0. Which of these gaps are closed

The engine went from **75 detectors to 130**, and from **15 validators to 33**.
Measured by importing the engine: 58 `pii`, 33 `secret`, 14 `phi`, 14 `pci`,
10 `special_category`, 1 `criminal_offence`.

| # | Gap (ranked in §10) | State |
|---|---|---|
| 1 | Label taxonomy: `special_category`, `criminal_offence`, `minor` qualifier | **closed** |
| 2 | PCI track data, PIN blocks | **closed** — 5 detectors |
| 3 | Art. 9 lexicons, Art. 10 criminal offence | **closed** — 6 detectors |
| 4 | Clinical vocabularies | **closed** — 8 detectors, and wired into `PHI_CONTEXT` |
| 5 | European national identifiers | **closed** — 12 detectors, all check-digited |
| 6 | Validators for existing detectors | **closed** — IMEI and VIN; see the correction below |
| 7 | Credential expansion | **closed** — 16 detectors |
| 8 | Biometric and genetic references | **closed** — 6 detectors |
| 9 | Non-English NER | **open, with an interim measure** — language is detected and reported in the coverage statement; the model itself is still English-only |

Three corrections to the analysis below, found while implementing it:

- **The SSN claim in §9 was wrong.** The SSN detectors already encode the
  unissuable ranges in-pattern (`(?!000|666|9\d\d)`, `(?!00)`, `(?!0000)`),
  and there is a deliberate companion detector for exactly those ranges. No
  validator was needed and none was added.
- **Two long-standing test fixtures were not valid identifiers.** The IMEI and
  VIN fixtures failed their own check digits the moment the validators were
  attached, which is what a check digit is for. Replaced with published
  values that validate.
- **A real false positive surfaced: every valid IMEI was being reported as
  payment card data.** IMEIs carry a Luhn check digit by design, so they
  satisfied the `credit_card` validator — a device inventory produced PCI
  findings. Fixed by requiring the Amex prefix at fifteen digits, which is the
  only length where payment cards and IMEIs collide.

Safe Harbor category **(P) biometric identifiers moved from "not detectable"
to partial**, because references are text even though templates are not. The
manifest now reports 16 of 18 detectable, 2 undetectable.

---

## 1. The baseline this analysis was written against

Measured by importing the engine, not by reading it. For the current counts,
see §0.

| Layer | Count then | Notes |
|---|---|---|
| Regex detectors | **75** | 44 `pii`, 16 `secret`, 9 `pci`, 6 `phi` |
| Regex detectors with a validator | **15 of 75** | checksum or range validation |
| Presidio/NER entity types consumed | **16** | English only |
| Sensitivity labels | **6** | `pii`, `phi`, `pci`, `secret`, `source_code`, `none` |

NER runs with `supported_languages=["en"]`; the entity-type count is unchanged.

---

## 2. The structural gap: the label taxonomy cannot express the regulated categories

*Closed in part. `special_category`, `criminal_offence` and the `minor`
qualifier now exist; CPRA SPI still has no label of its own, and the
co-occurrence rules in §6 are still missing.*

This was the finding that mattered most, because every other gap inherited
from it. The engine had five positive labels. The frameworks in the pack
define at least five further categories that carry **materially different legal
obligations**, and all of them collapsed into `pii`:

| Category | Regime | Why a separate label matters |
|---|---|---|
| Special categories | GDPR Art. 9(1) | Processing is *prohibited* unless an Art. 9(2) condition applies. A different lawful-basis analysis entirely, not a more severe flavour of Art. 6. |
| Criminal convictions and offences | GDPR Art. 10 | Requires official authority or specific Member State law. Not an Art. 9 category — its own regime. |
| Sensitive personal information | CPRA §1798.140(ae) | Triggers the **right to limit use and disclosure** (§1798.121), a right that does not exist for ordinary personal information. |
| Children's data | GDPR Art. 8; COPPA; CPRA §1798.120(c) | Consent age 13–16 (GDPR), under-13 (COPPA), opt-**in** for sale/share under 16 (CPRA). |
| Biometric / genetic | GDPR Art. 9; BIPA; CUBI; My Health My Data | Private right of action under BIPA. Statutory damages per violation. |

**Consequence at the time:** a store holding trade-union membership, sexual
orientation, or a genetic variant was labelled exactly the same as a store
holding a work email address. The PIA module (`compliance/pia.py`) and the
Art. 35 DPIA question could not be answered from the classification output,
because the signal that drives "is a DPIA likely required" — large-scale
processing of Art. 9 data — was not a thing the engine could emit.

The recommendation (highest value, lowest detector work) was to add
`special_category`, `criminal_offence`, and a `minor` qualifier to the label
model before adding any new patterns, since detectors that already existed
(`NRP`, health context) would immediately produce more useful output. All
three now exist.

---

## 3. GDPR

### 3.1 Article 9 special categories — largely absent

*Closed: six lexicon detectors now carry the `special_category` label (trade-union
membership, sexual orientation, political opinion, religious belief, racial or
ethnic origin) and one carries `criminal_offence`. The table below is the state
that prompted them.*

Art. 9(1) enumerates eight categories. Coverage at the time:

| Art. 9 category | Status | Note |
|---|---|---|
| Racial or ethnic origin | **partial** | `NRP` fires on nationality/ethnic adjectives; precision floor 0.60 and it is mapped to plain `pii` |
| Political opinions | **absent** | no detector, no lexicon |
| Religious or philosophical beliefs | **partial** | `NRP` only, incidentally |
| **Trade union membership** | **absent** | confirmed: no pattern, no lexicon |
| **Genetic data** (Art. 4(13)) | **absent** | see §4.3 |
| **Biometric data for unique identification** (Art. 4(14)) | **absent** | see §3.2 |
| Data concerning health (Art. 4(15)) | **partial** | see §3.3 |
| **Sex life or sexual orientation** | **absent** | confirmed: no pattern, no lexicon |

Four of eight categories have no signal of any kind.

### 3.2 Biometric data — absent everywhere it is named

*Closed at the reference level only: `biometric_reference` detects the words,
not templates. Raw biometric templates remain undetectable.*

Not detected in any form, and it is named by GDPR Art. 9, HIPAA Safe Harbor
(P), CPRA SPI, Illinois BIPA, Texas CUBI and Washington's My Health My Data
Act. Raw templates are genuinely hard; **references are not**, and references
are what appears in a retrieval corpus: "faceprint", "voiceprint", "iris
scan", "fingerprint template", "gait signature", `.tpl`/`.dat` template
filenames, and base64 blobs appearing beside those words. A reference-level
detector would be high precision and would move four frameworks at once.

### 3.3 "Data concerning health" is broader than the identifier detectors

The six `phi` detectors are all **identifier-shaped**: MRN, ICD code, NPI,
DEA, NHS number, Medicare MBI. GDPR Art. 4(15) is about *content*: any data
revealing health status, including inference. A sentence such as "the customer
mentioned she is being treated for bipolar disorder" is special-category data
under GDPR with no identifier present, and today produces no health signal at
all unless a `PERSON` happens to be nearby.

This is a recall gap specific to GDPR. Under HIPAA the identifier-shaped
approach is closer to correct, because the Safe Harbor test is itself an
identifier test — so the two regimes need different logic, and the engine
currently has only one.

### 3.4 National identifiers — the EU is thinly covered

*Closed for the EU list below: twelve check-digited detectors were added. The
non-EU absences at the end of the section are still open.*

Present: US (SSN, ITIN), UK (NINO, UTR, NHS), Canada, Australia, India
(Aadhaar, PAN), Brazil, Mexico, Italy, Netherlands, Singapore, South Africa,
China.

For an engine used against GDPR criteria, the notable absences are EU/EEA:

| Missing | Country | Structure |
|---|---|---|
| **NIR / INSEE** | France | 13 digits + 2-digit check key; first digit encodes sex, and it embeds birth year, month and *département* — arguably special-category-adjacent |
| **PESEL** | Poland | 11 digits, embeds DOB and sex, check digit |
| **Steuer-ID** | Germany | 11 digits, check digit |
| **DNI / NIE** | Spain | 8 digits + check letter (mod-23) |
| **Personnummer / fødselsnummer / CPR / HETU** | SE / NO / DK / FI | all embed DOB, all check-digited, all ubiquitous in Nordic text |
| **Rijksregisternummer** | Belgium | 11 digits, embeds DOB, check digit |
| **PPSN** | Ireland | 7 digits + check letter |
| **NIF** | Portugal | 9 digits, check digit |
| **AMKA** | Greece | 11 digits, embeds DOB |
| **AHV/AVS** | Switzerland | 13 digits, EAN-13 check |

Also absent outside the EU: Japan My Number, South Korea RRN, Turkey TC
Kimlik, Israel Teudat Zehut, Russia SNILS/INN, Argentina CUIL, Chile RUT,
Colombia cédula, Indonesia NIK, Philippines PhilSys, Nigeria NIN.

Most of these are check-digited, which means they can be added at the same
precision bar the existing detectors hold.

### 3.5 Language coverage — the largest practical GDPR gap

NER is English-only.

**Correction (2026-09-23).** An earlier version of this section said a German
or French corpus gets "no `PERSON`, `LOCATION` or `ORGANIZATION` detection
whatsoever". That is **wrong**, and it was measured rather than reasoned:
running the English `en_core_web_lg` over German clinical prose does find the
patient's name. It also invents a spurious `ORGANIZATION` the German model does
not. So the English model partially generalises, and the honest statement is
that non-English text is detected **worse and more noisily**, not that it is
invisible.

That matters because the original claim was used to rank this as the largest
practical GDPR gap. It is still a real gap — degraded recall and extra false
positives across every European language, with no way for the engine to know
which — but its size is now an open question rather than a stated fact, and
`benchmarks/regulatory_coverage/` is where it should be settled.
Regex detectors are language-independent throughout, so structured identifiers
were never affected.

For a store of EU data this is arguably more consequential than any
single missing pattern, and the coverage statement does not currently say it.
A store of German-language tickets can pass `data_classification` with
`complete` coverage while every name in it goes unseen.

**This is also an honesty problem, not only a recall problem.** The engine
does not know what language it is reading, so it cannot warn.

### 3.6 Pseudonymous and online identifiers

Recital 26 and the CCPA definition of a unique identifier both cover
identifiers that are not names. `prefixed_id`, `metadata_identifier`,
`ipv4/ipv6`, `mac_address`, `user_agent_string` and `username_handle` exist.
Absent: **advertising identifiers** (IDFA, AAID/GAID), cookie IDs, **hashed
email addresses** (the dominant adtech join key — a bare SHA-256 is
indistinguishable from any other hash, but `sha256(email)` in an adtech
context is highly detectable), device-fingerprint hashes, and the identity
graph IDs (UID2, RampID).

### 3.7 Children's data

*Closed in part: a `minor` qualifier and two detectors (`minor_age_context`,
`minor_school_context`) now exist. CPRA's opt-in rule is still not modelled as
a rule.*

`age_context` exists. There is no concept of a **minor**: no detection of an
age below 13/16, no school/grade/guardian lexicon, no `minor` qualifier on a
finding. Under CPRA §1798.120(c) the sale or sharing of a known under-16's
data requires opt-in, which is the opposite default from everything else in
the statute — a distinction the engine cannot currently express.

---

## 4. HIPAA

### 4.1 Safe Harbor residuals

`compliance/hipaa.py` already reports (P) biometric, (Q) full-face images and
(R) "any other unique identifying characteristic" as undetectable, and marks
seven more as partial. That honesty is right. What the partials hide:

- **(I) health plan beneficiary numbers** — Medicare MBI is covered. Medicaid
  state IDs, TRICARE/DoD Benefits Number, commercial member and group numbers
  are not.
- **(K) certificate/licence numbers** — `MEDICAL_LICENSE` (NER) and DEA are
  covered. State professional licences and **ClinicalTrials.gov NCT numbers**
  are not.
- **(M) device identifiers** — the **FDA Unique Device Identifier** has a
  defined, parseable structure (DI + PI, GS1/HIBCC/ICCBBA issuing agencies).
  Not detected. Implant serials likewise.
- **Accession numbers and specimen IDs** — a routine identifier in pathology
  and radiology, and a classic re-identification vector. Not detected.

### 4.2 Clinical vocabularies — only ICD is present

*Closed: eight vocabulary detectors were added and wired into `PHI_CONTEXT`.*

`icd_code_context` exists. Absent: **CPT/HCPCS** procedure codes, **LOINC**
lab codes, **SNOMED CT** concept IDs, **RxNorm** and **NDC** drug codes
(NDC's 10/11-digit segmented format is highly detectable), and **DRG**.

These matter twice over. They are identifiers in their own right, and they are
the strongest available **health-context signal** — which is what drives the
`DATE_TIME` → PHI upgrade and the `PERSON` → PHI upgrade. Adding them would
improve PHI recall well beyond the codes themselves.

### 4.3 Genetic information — absent, and it is explicitly regulated

*Closed: `genetic_variant_hgvs`, `genetic_rsid`, `genetic_sequence_run` and
`genetic_testing_context` now carry the `special_category` label.*

GINA and the HIPAA Privacy Rule both treat genetic information as protected,
and GDPR Art. 4(13)/Art. 9 treat it as special category. Detectable forms:
**HGVS variant nomenclature** (`NM_000059.3:c.1234del`, `c.76A>T`), **dbSNP
rsIDs** (`rs334`), gene symbol + variant pairs, FASTA/VCF fragments, and
sequence runs. None are detected. For a tool whose flagship demo is a
clinical retrieval corpus, this is a conspicuous hole.

### 4.4 Regimes stricter than HIPAA that the pack does not model

- **42 CFR Part 2** — substance use disorder treatment records. A separate
  federal regime with consent rules stricter than HIPAA. Not in the framework
  list and no context detector.
- **Reproductive health care** — subject to a 2024 HHS rulemaking whose
  current status I have not verified and which has been litigated. Flagging as
  a watch item only; confirm before relying on it.
- Mental and behavioural health context generally — no signal.

---

## 5. PCI DSS

*Closed: five detectors for track data and PIN blocks were added.*

The PAN side is well covered: `credit_card` (Luhn-validated), `card_like_number`,
`credit_card_issuer`, expiry and CVV context, IBAN, SWIFT/BIC.

**Sensitive Authentication Data is not covered at all**, and Requirement 3.3.1
and its sub-requirements prohibit retaining it after authorisation. This is the
single most clear-cut compliance failure the engine could detect and does not:

| SAD element | Status | Detectability |
|---|---|---|
| **Full track data** (Track 1 / Track 2 equivalent) | **absent** | Very high. Track 1 `%B<PAN>^<NAME>^<YYMM><service code>…?` and Track 2 `;<PAN>=<YYMM><service code>…?` are rigid, distinctive formats — near-zero false positive rate |
| **PIN / PIN block** | **absent** | Moderate; context-dependent, but ISO 9564 PIN blocks in hex beside PAN context are tractable |
| **Card verification code** | context only | Correct as-is — a bare 3 digits is not detectable and should not be |
| **Service code** | **absent** | Only meaningful inside track data |

A track-data detector is, in my judgement, the highest-precision single
addition available anywhere on this list, and it detects a prohibited storage
condition rather than merely sensitive content.

Since settled: a **truncated or masked PAN** (permitted) is no longer labelled
PCI. The masked alternative was removed from `card_like_number`, so
`411111******1111` reads as truncated rather than as stored card data. See
[Crypto posture](crypto_posture.md) for how `pan_representation` uses that.

---

## 6. CPRA sensitive personal information

§1798.140(ae) defines SPI as a closed list, and §1798.121 attaches a distinct
consumer right to it. Mapped against the engine:

| SPI element | Status |
|---|---|
| SSN, driver's licence, state ID, passport | covered |
| Account log-in **+ password/credentials** | **absent as a pair** — `username_handle` and `generic_secret_context` exist independently, with no co-occurrence rule |
| Financial account **+ access code/PIN** | **absent as a pair** |
| Precise geolocation | partial — `gps_coordinate` exists; no precision threshold (the statutory test is ~1,850 feet) |
| Racial/ethnic origin, religion, union membership | **absent** (§3.1) |
| **Contents of mail, email and text messages** not directed to the business | **absent** — structurally detectable via header blocks and transcript formatting |
| Genetic data | **absent** |
| Biometric for unique identification | **absent** |
| Health information | partial |
| Sex life / sexual orientation | **absent** |

The two "combination" elements are worth noting as a design point: they are
not entity detections at all, they are **co-occurrence rules**. The engine has
no mechanism for "A within N characters of B raises the label", which is the
shape several statutory definitions actually take.

---

## 7. SOC 2 / credential coverage

*Closed: sixteen further credential detectors were added, taking the secret
layer to 33. The list below is the state that prompted them; check the current
detector list before assuming an item is still missing.*

Sixteen secret detectors, covering AWS access key IDs, GitHub, Google, OpenAI,
Anthropic, HuggingFace, npm, SendGrid, Slack, Stripe, JWT, private key blocks,
basic auth, bearer tokens and DB URLs.

Absent, roughly in order of how often they appear in a runbook corpus:

- **Azure**: storage connection strings (`DefaultEndpointsProtocol=…;AccountKey=`),
  SAS tokens, AD client secrets
- **GCP service account JSON** (`"type": "service_account"` + `private_key_id`)
- **AWS secret access key** (the 40-char secret, distinct from the `AKIA`
  access key ID already covered) and session tokens
- **HashiCorp Vault** tokens (`hvs.`, `s.`), **kubeconfig** files and
  Kubernetes service-account tokens
- **Twilio** (`AC…`, `SK…`), Mailgun, Postmark
- **Datadog**, New Relic, PagerDuty, Snowflake, Databricks, Cloudflare
- **Atlassian/Jira**, Notion, Linear, Figma
- **PGP private key blocks**; PKCS#12 bundles
- OAuth `client_secret` and refresh tokens
- `.npmrc` / `.pypirc` / Docker registry auth blocks
- Shopify, Square, PayPal, Plaid

This list is the cheapest to extend — each is a literal-prefixed pattern that
the existing `gate` optimisation handles well.

---

## 8. EU AI Act

Art. 10 data governance is represented in the pack. Two things the engine
cannot currently support:

- **Art. 5 prohibited practices.** A retrieval corpus containing scraped
  facial images, emotion-inference outputs from a workplace or education
  setting, or biometric categorisation by sensitive attribute is an Art. 5
  question, not an Art. 10 one. No detector speaks to any of it, and the
  biometric gap (§3.2) is the blocker.
- **Art. 10(5)** permits processing special categories specifically to detect
  and correct bias in high-risk systems. Answering "is this corpus relying on
  Art. 10(5)?" requires special-category labelling that does not exist.

---

## 9. Precision gaps: most detectors have no validator

*Open, with two exceptions. Of the nine below, only `imei_number` and
`vehicle_vin` gained a validator; `us_ssn` turned out not to need one (see the
correction in §0). 33 of 130 detectors now validate, against 15 of 75 then.*

Separate from coverage. Several existing detectors match identifiers that
carry a **published check digit that is not being verified**, which is free
precision:

| Detector | Available check |
|---|---|
| `imei_number` | **Luhn** — directly analogous to the card validator already in the codebase |
| `vehicle_vin` | ISO 3779 check digit, position 9 |
| `india_aadhaar_context` | Verhoeff |
| `italy_fiscal_code` | check character |
| `mexico_curp` | check digit |
| `us_ssn` | no checksum, but invalid ranges are well defined (area 000/666/900–999, group 00, serial 0000) |
| `us_itin` | defined range constraints |
| `uk_nino_context` | prefix/suffix format rules |
| `swift_bic_code` | structural validation |

Every one of these currently contributes to findings at `uncertain`
confidence. Validators are exactly what moves a detector off that class, which
in turn is what the Actions page needs before it will propose an irreversible
remediation — so this work unblocks VecShield's own refusal logic.

---

## 10. The ranking the work followed

Ranked by regulatory weight per unit of effort, not by effort alone. Items 1-8
are implemented and item 9 only in part; §0 is the current state. This is a
prioritisation of the analysis above, not a roadmap.

1. **Label taxonomy** — `special_category`, `criminal_offence`, `minor`.
   Unblocks GDPR Art. 9/10, CPRA SPI and the DPIA question. Little detector
   work; mostly model and reporting.
2. **PCI track data and PIN blocks.** Highest precision available, and detects
   a prohibited *condition* rather than sensitive content.
3. **Art. 9 lexicons** — union membership, sexual orientation, political
   opinion, religion. Lexicon plus context, landing on the new label.
4. **Clinical vocabularies** — NDC, CPT/HCPCS, LOINC, SNOMED, RxNorm. Improves
   PHI recall well beyond the codes themselves via the context upgrade.
5. **EU national identifiers** — FR, DE, ES, PL, Nordics first. Check-digited,
   so they meet the existing precision bar.
6. **Validators for the nine detectors above.** Free precision; unblocks
   irreversible remediation.
7. **Secret-detector expansion** — Azure, GCP SA JSON, Vault, kubeconfig.
   Cheapest items on the list.
8. **Biometric and genetic reference detectors.** Moves four frameworks.
9. **Non-English NER.** Largest EU recall gap, largest effort. Until then, the
   engine should at minimum **detect the language and say so in the coverage
   statement** — a store it cannot read should not report the same coverage as
   one it can.

Item 9's interim measure is the one that matters most for VecShield's own
honesty claims, and it is far cheaper than the full fix.
