# Crypto posture

Crypto posture assesses cryptographic protection **at the vector-database data
plane**: what VecShield can verify through the configured connector about
transport encryption, database-native encryption at rest, field-level
protection, and what an authenticated retrieval client can still read. It then
turns those observations into evidence for the six frameworks VecShield
carries: CCPA/CPRA, GDPR, HIPAA, PCI-DSS, SOC 2 and the EU AI Act.

It is deliberately not a cloud-KMS, disk-encryption, HSM or CSPM scanner.
Anything the database interface does not expose — AWS KMS, Key Vault, EBS or
LUKS volume encryption, cloud IAM, snapshot settings — is reported as
**not observable**, never as a failure.

This page describes what the engine does today. Where a claim rests on a fake
SDK rather than a live server, or on a secondary source rather than the primary
text, it says so.

## How it fits the rest of the engine

Crypto posture is an extension of engines that already exist, not a new scanner
beside them. VecShield already carried:

| Need | Where it lives |
|---|---|
| TLS in transit (VCR-01) | `posture/encryption.py`, check `transport_encryption` |
| "Unobservable is not a fail" | `coverage.py` outcomes `unsupported` / `inconclusive`; criteria map them to `evidence_needed` |
| Regulatory mapping | `Criterion.technical_checks` in `compliance/packs.py`, reduced by name in `criteria.py:_technical` |
| Addressable HIPAA specs | `Criterion.specification` + the `addressable_determination` evidence key |
| Manual artifacts | `evidence.py` (`EvidenceArtifact`, `EvidenceReview`, `accepted_requirements`) |
| History for drift | Immutable audit snapshots with `check_outcomes`; stable finding fingerprints |
| PAN detection | Luhn-validated `credit_card` and track-data detectors in `regex_classifier.py` |
| "Embeddings are not encryption" | `score/inversion.py`, `score/sensitivity.py` |
| Per-span surface (text vs metadata) | `classify/surfaces.py` stamps `span["surface"]` |

Crypto obligations largely map onto criteria that already existed
(`HIPAA-164-312-A2IV-ENCRYPTION-01`, `HIPAA-164-312-E1-TRANSMISSION-01`,
`GDPR-SECURITY-32-01`, `PCI-DSS-3-STORAGE-01`). A parallel `*-CRYPTO-01`
criterion set would put two answers to the same obligation on screen, so the
existing criteria are extended and new ones added only where no criterion
exists.

## Design principles

- **Measure once, map many.** A check records one `check_outcome`. Criteria
  cite check names. No framework gets its own scanner.
- **Layers stay separate.** Transport, storage encryption, field/data-level
  protection and retrieval-time exposure are separate rows. They are never
  collapsed into one "Encryption ✓".
- **Not observable is not a fail.** It leads to `evidence_needed` and a
  request for a manual artifact.
- **Readable is not unencrypted.** Plaintext returned to an authenticated
  client says nothing about the disk; the wording must say so.
- **No crypto score.** Coverage is reported property by property, as counts.
- **High entropy is not encryption.** VecShield names a representation
  (opaque, token, hash candidate), never an algorithm, unless database-visible
  configuration states the algorithm.
- **The regulatory basis below is the ceiling.** No criterion may claim a
  stronger relationship than the framework row supports.

---

## Regulatory basis

This table is the basis for every mapping described here. It is authoritative
for what VecShield may claim.

| Framework | At-rest support | In-transit support | Correct VecShield interpretation |
|---|---|---|---|
| **CCPA/CPRA** | Explicit in 2026 regulations | Explicit in 2026 regulations | Direct automated control for businesses subject to cybersecurity audits |
| **GDPR** | Explicitly contemplated, risk-based | Explicitly contemplated, risk-based | Appropriate according to risk, not universally mandatory |
| **HIPAA** | Explicit, but currently "addressable" | Explicit, but currently "addressable" | Encrypt if reasonable/appropriate; otherwise document alternative |
| **PCI-DSS** | Stored PAN must be unreadable; encryption is one permitted mechanism | Strong cryptography explicitly required for PAN over open/public networks | Very strong if PAN is in vector DB |
| **SOC 2** | AICPA point of focus explicitly discusses encryption of data at rest based on risk | AICPA point of focus explicitly discusses encryption/secure channels | Excellent audit-evidence mapping, but SOC 2 is not a statute |
| **EU AI Act** | No explicit at-rest encryption requirement | No explicit transit-encryption requirement | Supporting cybersecurity/privacy control only; don't claim direct mandate |

### What each row means in the engine

Each row becomes a **relationship** (display) and an **evaluation semantic**
(what a failed check does to a criterion).

| Framework | Relationship label | Evaluation semantic | Applicability gate |
|---|---|---|---|
| CCPA/CPRA | Direct — cybersecurity audit | `standard`: a failed check is `gap_identified` | Business subject to CCPA **and** subject to the CPPA cybersecurity-audit requirement |
| GDPR | Risk-based | `risk_based`: a failure is a gap unless an accepted `risk_determination` documents why the measure is not appropriate to the risk | Processes personal data of EU data subjects |
| HIPAA | Addressable | `addressable`: a failure is a gap unless an accepted `addressable_determination` documents the decision and any equivalent measure (45 CFR 164.306(d)(3)) | Covered entity or business associate; system handles ePHI |
| PCI-DSS | Direct when PAN is present | `standard` | Stores, processes or transmits account data; for transit, over open/public networks |
| SOC 2 | Control evidence (not a statute) | `risk_based`: points of focus are considerations, not requirements; the entity's own control design governs | Criterion in audit scope; system in service boundary |
| EU AI Act | Supporting evidence only | **No criterion.** Crypto observations appear as supporting Art. 15 cybersecurity context and never produce a status | High-risk AI system (display only) |

The EU AI Act row is enforced by test: no EU AI Act criterion may cite a
crypto check. Adding one would turn "supporting" into a mandate the Act does
not state.

### Source records (`compliance/sources.py`)

Every record is held as `lifecycle="draft"`. Licensed texts (PCI DSS, AICPA
TSC) are referenced by locator and link only, following the module's existing
rules.

| Id | Framework | Locator | Notes |
|---|---|---|---|
| `ccpa-cppa-cyberaudit` | CCPA/CPRA | Cal. Code Regs. tit. 11, § 7123(c)(2) (Art. 9, §§ 7120-7124) | Encryption of personal information at rest and in transit is an audit component, assessed "if applicable". Thresholds are in § 7120(b). The first report is due April 1 of 2028, 2029 or 2030, depending on revenue (§ 7121). Verified 2026-09-24. |
| `ccpa-1798-150` | CCPA/CPRA | Cal. Civ. Code § 1798.150 | Private right of action for breaches of nonencrypted and nonredacted personal information. Supporting context only. |
| `gdpr-art-32-1-a` | GDPR | Art. 32(1)(a) | Pseudonymisation and encryption, as appropriate to the risk. |
| `hipaa-164-312-e-2-ii` | HIPAA | 45 CFR 164.312(e)(2)(ii) | Cited by its own addressable criterion. |
| `pci-dss-req-3-5-1` | PCI-DSS | Requirement 3.5.1 | Stored PAN is rendered unreadable. The mechanisms are one-way hashes of the entire PAN (keyed, per 3.5.1.1), truncation, index tokens, and strong cryptography. |
| `pci-dss-req-3-5-1-2` | PCI-DSS | Requirement 3.5.1.2 | Disk/partition-level encryption alone does not satisfy 3.5.1 on non-removable media. |
| `pci-dss-req-4-2-1` | PCI-DSS | Requirement 4.2.1 | Strong cryptography for PAN over open, public networks. |
| `tsc-cc6-7` | SOC 2 | CC6.7 | Transmission; point of focus on encryption or secure channels. |

`tsc-cc6-1`'s encryption point of focus is referenced in `notes`, not quoted.

Watch item: HHS has proposed Security Rule amendments that would remove the
addressable/required distinction for encryption (90 FR 898, 2025-01-06). As of
2026-09-24 there is no final rule; the Unified Agenda projects final action for
July 2027. The table above says "currently". If the proposal is finalised, the
change is data only: flip `specification` on the two HIPAA encryption criteria
and bump the pack version.

---

## Architecture

```
            Connector (+ optional crypto methods)
                              │
   ┌──────────────────────────┼───────────────────────────┐
   │                          │                           │
posture engine          scan_store observer          opt-in active checks
transport_encryption    data_representation          transport_tls_enforcement
at_rest_encryption      pan_representation           retrieval_exposure
field_encryption                                     direct_identifier_exposure
   │                          │                           │
   └──────────── check_outcome records in the audit snapshot ┘
                              │
             ┌────────────────┼──────────────────┐
             │                                   │
   criteria (technical_checks)         Crypto posture read model
   evaluate_pack — unchanged API       GET /stores/{id}/crypto-posture
             │                                   │
   Frameworks / Criteria / Policies        Crypto tab
```

The only extra store reads are the connector crypto methods and the opt-in
probes. Data representation piggybacks on the classification pass that already
iterates every chunk, through `scan_store`'s existing `observer` hook.

### Evidence states

Six evidence states travel as `crypto_state` inside a check outcome's
`coverage` details. `coverage.OUTCOMES` is unchanged, so coverage summaries and
criterion evaluation keep working unmodified.

| `crypto_state` | Check outcome | Criterion effect |
|---|---|---|
| `verified` | `passed` | passed |
| `protected_representation` | `passed` | passed |
| `observed_exposure` — full PAN, or a protection mechanism applied inconsistently | `failed` | `gap_identified` (or excused by a determination where the semantic allows) |
| `observed_exposure` — sensitive data consistently plaintext, no mechanism observed | `inconclusive` | `evidence_needed`: the exposure is a fact; whether it breaches depends on risk |
| `not_verified` | `inconclusive` | `evidence_needed` |
| `not_observable` | `unsupported` | `not_run` → `evidence_needed` (fallback evidence requested) |
| `not_applicable` (e.g. no PAN found) | `passed`, with `crypto_state: not_applicable` | passed. `skipped` is not used: next to a `passed` sibling, `_technical` would downgrade the criterion to inconclusive. |

### Controls and the checks that carry them

| Control | Check | Why this shape |
|---|---|---|
| VCR-01 secure transport | `transport_encryption`, extended with session evidence where the client exposes it: Postgres `pg_stat_ssl` for the backend PID, pymongo TLS options, Redis `SSLConnection`, HTTP client scheme | No second TLS check |
| VCR-02 plaintext rejection | `transport_tls_enforcement`. Passive where the DB exposes it (e.g. Postgres `pg_hba_file_rules` with `hostssl`, when readable); otherwise an opt-in probe | Enforcement is a different property from "VecShield used TLS" |
| VCR-03/04/05, VCR-09 | `data_representation`, per collection. Reports text and metadata surfaces separately, and record structure (embedding, chunk and metadata present or absent). Carries the inversion-risk score as context | One pass; embeddings are explicitly not protection |
| VCR-06 PAN | `pan_representation`: full / truncated / tokenized / hash candidate / opaque / none | PCI cites it directly |
| VCR-07 direct identifiers | `direct_identifier_exposure`: a direct identifier sits next to a pseudonymous one | Reuses `_SENSITIVE_KEY_PARTS` from `surfaces.py` |
| VCR-08 consistency | Within one scan: mixed protected and plaintext values in one field make `data_representation` `failed`. Across runs: the drift comparison | Single-scan drift is cheap |
| VCR-10 field encryption | `field_encryption`, connector-specific (MongoDB `encryptedFields` / `$jsonSchema` `encrypt`) | Not forced into a lowest common denominator |
| VCR-11 at rest | `at_rest_encryption` | The separate checker `encryption.py` already anticipated it |
| VCR-12 | **Not a scanner.** `data_representation` restricted to sensitive fields, shown next to VCR-11 | It would duplicate VCR-05 |
| VCR-13 coverage | **Not a scanner.** A rollup in the read model: verified encrypted / verified unencrypted / unknown per collection | Same idea as `summarize_coverage` |
| VCR-14 at-rest drift | A generic snapshot comparison over check outcomes and fingerprints | Also answers "what changed since the last scan" |
| Active retrieval probe | `retrieval_exposure`, opt-in. Replays stored vectors like `probe_isolation` does; no embedding model needed | Reuses a proven probe pattern |

### How `data_representation` classifies a value

A pure module classifies the representation of sensitive values:

- **From classifier spans:** a detected value is `plaintext`, `masked`
  (`****1234`) or `truncated` (first six / last four).
- **From field shape**, for metadata keys that `_SENSITIVE_KEY_PARTS` marks as
  sensitive but where no detector fired:
  - UUID-shaped → `pseudonymous` candidate;
  - 32/40/64 hex → `hash_candidate`;
  - high-entropy base64 → `opaque`;
  - format-preserving digits that fail Luhn under a card-like key → `tokenized`
    candidate;
  - otherwise `unknown`.
- Output: per collection and per field path, counts per class. Evidence stores
  counts and masked previews only (existing `_redact`), never raw values.

It lives in `vecshield_platform`, so the `vecshield` classifier contract does
not change.

A masked PAN (`411111******1111`) is not labelled PCI: the masked alternative
was removed from `card_like_number` in the library's classifier so that a
truncated value reads as `truncated`, not as stored card data. That change took
the regulatory-coverage hard negatives from 10/12 to 11/12 clean, with no
regression on the detector benchmark.

---

## Criteria (pack `vecshield-vector-store-draft-3`)

Every row cites only checks the engine actually emits. A test enforces this by
running the real engines, not a hand-written list.

### Existing criteria, rewired

| Criterion | Semantic | `technical_checks` | Evidence |
|---|---|---|---|
| `HIPAA-164-308-A4-ACCESS-MGMT-01` | addressable | `tenant_isolation`, `authentication`, `network_exposure` | unchanged |
| `HIPAA-164-308-A8-EVALUATION-01` | standard | `data_classification`, `rag_integrity`, `tenant_isolation`, `network_exposure`, `transport_encryption`, `authentication`, `cve` | unchanged |
| `HIPAA-164-308-B1-BAA-01` | standard | **manual-evidence-only.** It is an inference from connector kind, not a posture result; `business_associate_exposure` stays as displayed context | unchanged |
| `HIPAA-164-312-A1-ACCESS-CONTROL-01` | standard | `tenant_isolation`, `authentication`, `network_exposure` | unchanged |
| `HIPAA-164-312-A2IV-ENCRYPTION-01` | addressable | `at_rest_encryption` | `encryption_at_rest_statement` is **fallback evidence** |
| `HIPAA-164-312-D-AUTHN-01` | standard | `authentication` | unchanged |
| `HIPAA-164-312-E1-TRANSMISSION-01` | standard | `network_exposure`. The encryption specification sits in its own addressable criterion (below), so a plaintext endpoint on a private network is decided under the addressable rule, not auto-gapped under the standard | `transport_security_statement` is fallback evidence |
| `GDPR-SECURITY-32-01` | — | `tenant_isolation`, `authentication`, `network_exposure` (access, as its paraphrase says) | unchanged |
| `PCI-DSS-3-STORAGE-01` | standard | `data_classification`, `pan_representation`. **Deliberately not `at_rest_encryption`**: under 3.5.1.2, storage encryption cannot be the sole mechanism, and an unobservable at-rest state must not blur the PAN result. | cites `pci-dss-req-3-5-1`, `-3-5-1-2` |

### Crypto criteria

Each exists only where no criterion covered the obligation already.

| Criterion | Framework | Semantic | `technical_checks` | Fallback evidence | Applicability |
|---|---|---|---|---|---|
| `HIPAA-164-312-E2II-ENCRYPTION-01` | HIPAA | addressable | `transport_encryption`, `transport_tls_enforcement` | `transport_security_statement` | `_EPHI_APPLICABILITY` |
| `GDPR-32-1A-ENCRYPTION-01` | GDPR | risk_based | `transport_encryption`, `at_rest_encryption`, `data_representation` | `encryption_risk_assessment` | `processes_personal_data_of_eu_subjects` |
| `PCI-DSS-4-2-1-TRANSMISSION-01` | PCI-DSS | standard | `transport_encryption`, `transport_tls_enforcement` | `pan_transmission_statement` | account data questions + `account_data_transmitted_over_open_public_networks` |
| `SOC2-CC6.1-ENCRYPTION-01` | SOC 2 | risk_based | `at_rest_encryption` | `encryption_policy` | SOC 2 questions |
| `SOC2-CC6.7-TRANSMISSION-01` | SOC 2 | risk_based | `transport_encryption`, `transport_tls_enforcement` | `transmission_security_policy` | SOC 2 questions |
| `CCPA-CYBERAUDIT-ENCRYPTION-01` | CCPA/CPRA | standard | `transport_encryption`, `transport_tls_enforcement`, `at_rest_encryption` | `encryption_program_description` | `business_subject_to_ccpa` + `subject_to_cppa_cybersecurity_audit` |
| — | EU AI Act | — | none, by design | — | — |

Interpretation notes carry the basis table's wording:
- CCPA notes § 1798.150's "nonencrypted and nonredacted" as supporting
  context.
- SOC 2 notes that the conclusion is the auditor's opinion.
- PCI notes that the storage-encryption row is shown beside the criterion but
  never satisfies it.

**Transit criteria without the enforcement probe.** When the opt-in probe is
off and nothing passive is available, `transport_tls_enforcement` records
`skipped`. With `transport_encryption` passed, `_technical` reads
`inconclusive`, so the criterion asks for fallback evidence. This is
intentional: VecShield using TLS does not show that other clients must.

### Criteria-engine behaviour (`compliance/criteria.py`)

Both rules are pure and leave non-crypto criteria evaluating as before.

1. **`Criterion.fallback_evidence: list[str]`.** These keys are required only
   when the technical result is `not_run` or `inconclusive`. They are merged
   into the evidence reduction at that point.
   - `manual_evidence` stays unconditional.
   - A manual-evidence-only criterion may not declare fallback evidence, since
     it has no technical result to fall back from.
   - Once the store exposes the property, the artifact stops being demanded:
     for example, HIPAA drops from 3 manual items to 2.
2. **`risk_based` in `SPECIFICATION_KINDS`.** It evaluates like `addressable`,
   but reads the evidence key `risk_determination`, and the UI labels it
   "Risk-based". `addressable` keeps its HIPAA-specific wording and basis.
3. **Accepted fallback evidence moves a criterion to `under_review`.** Without
   this, a store that cannot show a property could never get past
   `evidence_needed`. It never concludes the criterion; a reviewer does.

`PACK_VERSION` is `vecshield-vector-store-draft-3`. Snapshots saved before the
crypto checks existed evaluate honestly against it: checks they never ran read
`not_run`, so the criterion shows `evidence_needed`.

---

## Connector capabilities

Optional methods on `Connector`. The defaults raise `UnsupportedCapability`, so
a connector that does not implement one reports not observable.

| Method | Capability string | Returns |
|---|---|---|
| `transport_session_info()` | `transport_introspection` | `{tls: bool, version, cipher, source}` |
| `at_rest_encryption_state(collection=None)` | `at_rest_introspection` | `AtRestObservation(state ∈ enabled/disabled/not_observable/unsupported/error, scope, source, evidence, observed_at)` |
| `field_encryption_config(collection)` | `field_encryption_introspection` | per-field configuration, where exposed |
| `tls_enforcement_info()` | `tls_enforcement_introspection` | passive enforcement source, where one exists (pgvector reads `pg_hba_file_rules`) |

The strings are in `CAPABILITY_METHODS` in `actions.py`, so
`capability_verdict()` rejects a connector that advertises a capability without
implementing it. The per-connector capability matrix in the docs and the
console is generated from this, not hand-written.

TLS facts found by connectors go into `VectorStore.metadata["transport"]`.
Endpoint strings do not change: `transport_encryption` fingerprints are keyed
on the endpoint, and changing it would orphan cases and suppressions.
MongoDB's endpoint stays stripped, because the full URI can carry credentials.

Implemented sources. Everything not listed reports "not supported"; the
per-database table further down is the authoritative account of why.

| Connector | Transport session | Passive enforcement | At rest | Field encryption |
|---|---|---|---|---|
| pgvector | `pg_stat_ssl` | `pg_hba_file_rules` | EDB TDE, Percona `pg_tde` | — |
| MongoDB | client TLS context | — | `serverStatus.encryptionAtRest` | `encryptedFields`, `$jsonSchema encrypt` |
| Redis | `SSLConnection` | — | — | — |
| Azure AI Search | — | — | `SearchIndex.encryption_key` | — |
| Vertex AI | — | — | `encryption_spec.kms_key_name` | — |
| Bedrock KB | — | — | managed KB's own `kmsKeyArn` (data-source keys cover ingestion only) | — |

**These were built and tested against SDK fakes, not live servers.** The spike
against real deployments is still owed before any is called verified in the
field.

`pgcrypto` being installed is **not** evidence of encryption at rest, and is
never read as such.

---

## Active checks (opt-in, off by default)

`transport_tls_enforcement` (when no passive source exists) and
`retrieval_exposure` are opt-in: `--tls-probe` and `--retrieval-probe` on the
CLI, `tls_probe` / `retrieval_probe` on `POST /stores/{id}/audit`, and
checkboxes on the Run screen. The settings path is `AuditRequest` →
`resolve_audit_settings` scope → `run_full_audit` kwarg. Both are recorded in
the audit scope and the audit log.

`direct_identifier_exposure` (VCR-07) is **passive and always on.** It comes
out of the same classification pass as `data_representation`, so it is not a
probe.

Safety rules:

- **The TLS enforcement probe never sends credentials over a plaintext
  connection.**
  - Postgres: connect with `sslmode=disable` and a throwaway user, then read
    the `pg_hba` rejection ("no encryption"). The probe never uses libpq, which
    would read `PGPASSWORD`, `.pgpass` and service files; it writes a startup
    message for a throwaway role on a raw socket instead.
  - HTTP stores: one unauthenticated `GET` to the `http://` twin of an
    `https://` endpoint, with no auth header.
- The retrieval probe replays stored vectors (read-only). Its evidence holds
  counts and masked previews. Raw content is available only through the
  existing audited reveal flow.

**An unrequested probe does not make a run partial.** It is recorded as
`skipped` with `coverage.opt_in = true`, so criteria still read it and ask for
fallback evidence, and `coverage.summarize_coverage` leaves it out of
completeness (`checks_not_requested`). A check the run configuration
*excluded* is still a gap.

---

## Console

Crypto posture appears in its own tab **and** inside the regulation and policy
views where it belongs:

- **Store drill-down → Crypto tab.** It leads with the coverage statement,
  shows one layer's rows at a time (Transport → Storage encryption →
  Field/data-level → Retrieval exposure), groups identical rows across
  collections, and shows the estate matrix when no store is chosen. Coverage is
  counts ("38 verified · 0 unencrypted · 4 unknown"), never "100%". An explicit
  "Embeddings are not treated as cryptographic protection" line, and
  "Infrastructure disk / cloud KMS: outside connector scope."
- **Compliance → Frameworks.** Each framework card has a *Cryptographic
  protection* block: at-rest and in-transit rows labelled with the relationship
  from the regulatory basis table (Direct / Risk-based / Addressable / Control
  evidence / Supporting only), linking to the Crypto tab. The EU AI Act block
  reads "Supporting cybersecurity evidence (Art. 15) — no encryption mandate".
- **Compliance → Criteria.** Crypto check outcomes render their `crypto_state`
  as a chip. Not observable is visually distinct from failed. PCI shows two
  rows, "Storage encryption" and "PAN data-level protection", and never merges
  them. Fallback-evidence requests say *why*: "required because the store does
  not expose this property".
- **Compliance → Policies / Templates.** Posture policies appear with their
  triggering crypto state (below). The templates `pci-pan` and
  `hipaa-transmission-plaintext` carry the crypto categories rather than
  duplicating into new templates.
- **Compliance → Evidence.** Fallback-evidence requirements are listed beside
  manual ones, marked conditional.

The shipped console is `api/dashboard/dist/`; `parity.test.mjs` holds the tab
to the parity checklist.

Read-model endpoints:

- `GET /stores/{store_id}/crypto-posture?audit_id=` assembles the read model
  from a saved snapshot. It never scans.
- `GET /admin/crypto-estate` lists the coverage statement and a gate preview
  (not audit-logged) for every registered store; a store never assessed says so.

The regulatory basis table is served from a single data module
(`compliance/crypto_basis.py`) that the Frameworks view, the read model and
this page all follow.

The read model's `coverage.statement` says, per layer, how many rows were
observed (verified, exposure seen, not applicable), only declared
(configuration or vendor documentation), unknown or not observable, and not
checked. A layer's headline is its worst bucket, so it reads "verified" only
when every row is verified or not applicable.

`crypto_context` on the criteria response carries the audit's
`at_rest_encryption` outcomes. The console uses it to draw PCI's "Storage
encryption" row, which no PCI criterion cites.

### Policies (`posture/policy.py`)

| Policy | When | Severity |
|---|---|---|
| `pan-rendered-unreadable` | `pan_representation` finds full PAN | critical |
| `protection-applied-consistently` | `data_representation` finds a field with mixed protected and plaintext values | high |
| `at-rest-encryption-not-disabled` | `at_rest_encryption` state is **disabled** (never on not observable) | high |
| `tls-enforced` | `transport_tls_enforcement` shows plaintext accepted | high |
| `verify-tls-certificates` | TLS without certificate verification | medium |

A policy's `when.category` may be a list, so `hipaa-transmission-plaintext`
also fires on "store accepts plaintext", and `pci-pan` cites Requirement 3.5.1.

---

## The crypto gate

VecShield's only approvals are for action plans and risk exceptions (separation
of duties), so crypto enforcement is not an approval hook. It is a gate a
pipeline asks before promoting a store:

- `vecshield_platform/crypto/gate.py` evaluates a saved audit against rules
  that combine facts, which a single-finding policy cannot do, for example
  "PHI present **and** encryption at rest not verified".
- Served at `GET /stores/{id}/crypto-gate`, with the rules at
  `GET /compliance/crypto-gate/rules`.
- The `crypto-gate` CLI exits 2 on block, 1 when evidence is needed, and 0 on
  pass or warn (`--fail-on-warn` makes a warning exit 1).
- Every API decision is audit-logged.

| Rule | Decision | Cleared by evidence? |
|---|---|---|
| Full PAN readable | block | no — fix it |
| Database reports encryption at rest off | block | no |
| Sensitive data over a connection without TLS | block | no |
| Store with sensitive data accepts plaintext | block | no |
| PHI where encryption at rest is not verified | block | yes: accepted `encryption_at_rest_statement` or addressable determination (HIPAA A2IV) |
| Policy requires at-rest encryption (`requires_at_rest_encryption`) and it is not verified | request evidence | yes: SOC 2 CC6.1, GDPR 32(1)(a) or HIPAA A2IV evidence |
| Protection applied inconsistently | warn | no |
| PHI or card data returned in plaintext by retrieval | warn | no |

Evidence clears only gaps. A database that cannot report encryption at rest is
not blocked forever once its statement is accepted. An observed failure is
never cleared by a document. The gate never creates evidence records; it names
the evidence that would clear each rule.

---

## Transport details

- `sslmode=prefer` reads as unverified, like an unset sslmode, which behaves
  the same way.
- `mongodb+srv` with `tls=false` reads as plaintext.
- Weaviate's `secure=True` on the host/port path connects over TLS.
- pgvector takes an `sslmode` connector option (`--sslmode` on the CLI).
- Endpoint strings, and therefore finding fingerprints, are unchanged.
- **TLS without certificate verification** raises a MEDIUM finding (category
  `tls_certificate_verification`, policy `verify-tls-certificates`). Sources:
  OpenSearch `verify_certs=False`; MongoDB `tlsInsecure` and
  `tlsAllowInvalidCertificates`; Redis `ssl_cert_reqs=none`; Postgres
  `sslmode=require` or `prefer`. Only `verify-ca` and `verify-full` verify.
  The `transport_encryption` result stays verified: the channel is encrypted,
  and the finding records that the server is not authenticated.

## Drift

A generic snapshot comparison over check outcomes and fingerprints reports what
changed since the last audit. A finding that disappears counts as `resolved`
only if the newer audit actually re-ran a check that could report it again;
otherwise it is `not_retested`. Findings from sampled checks show as "not
re-tested", never "resolved".

## Compatibility

- The `vecshield` library's `ScanJob`, `Finding`, `Chunk` and `Classification`
  contracts are unchanged. Crypto data goes in `stats`, `evidence` and coverage
  details.
- `coverage.OUTCOMES`, `CRITERION_STATUSES` and `evaluate_pack`'s signature are
  unchanged.
- Connector crypto methods default to `UnsupportedCapability`.
- Endpoint strings, and therefore fingerprints, are unchanged.
- Active checks are opt-in.

## Out of scope

AWS KMS, Azure Key Vault, GCP Cloud KMS, EBS/disk/LUKS, HSMs, cloud IAM,
snapshot settings, and external certificate managers — unless the database
itself exposes them. FHE, TEEs and encrypted ANN. A numeric crypto score.

Also not built:

- A Chroma Cloud connection path for its customer-managed keys.
- Live-server checks of Milvus encryption zones and `pg_tde`. The Milvus cipher
  plugin is not public.

## Encryption at rest, database by database

Research date 2026-09-24. This asks one question per database: can the
connector see encryption at rest through the client it already holds? The
answers come from vendor documentation, API references and SDK source.
`vecshield_platform/posture/at_rest_support.py` is the canonical copy. A test
holds it to what the connectors actually advertise.

Every row whose "Supported" column says **no** reports "Not supported by
&lt;database&gt;". It gives the reason and names the evidence to supply instead.
It does not mark the run partial. Criteria still ask for their fallback evidence.

| Database | Supported | What is visible, and how | What the connector cannot see |
|---|---|---|---|
| PostgreSQL: EDB Postgres Advanced/Extended 15+ | yes | `pg_control_init().data_encryption_version`; `0` means TDE is off, so the check can show *disabled* | disk and volume layer |
| PostgreSQL: Percona `pg_tde` | yes | `pg_tde_is_encrypted()` per relation, run on the heap, every partition, the vector indexes and TOAST; plus `pg_tde.wal_encrypt` | temp files and statistics (not covered by pg_tde) |
| PostgreSQL: community, RDS/Aurora, Azure, Cloud SQL, AlloyDB, Supabase, Neon | no | the provider is identified through settings only, to name the right evidence | storage encryption is a control-plane attribute (`StorageEncrypted`, `dataEncryption`, `diskEncryptionConfiguration`) or a vendor statement |
| MongoDB Enterprise / Percona Server for MongoDB | yes, per node | `serverStatus().encryptionAtRest` (`encryptionEnabled`, `encryptionCipherMode`, `encryptionKeyId`). Field names come from Percona; MongoDB does not document them | other replica-set members; vector indexes held by `mongot` |
| MongoDB Community Edition, Atlas (volume layer), Atlas Free/Flex | no | — | Atlas encrypts volumes by default; customer-managed-key settings live in Atlas |
| OpenSearch with the storage-encryption plugin | yes, per index | `index.store.type: cryptofs` and `index.store.crypto.*` in the index settings | disk and domain encryption underneath |
| Amazon OpenSearch Service (domain), OpenSearch Serverless | no | — | `EncryptionAtRestOptions` and the encryption policies are AWS control-plane settings |
| Pinecone (serverless, API 2026-07) | yes, customer-managed key only | `cmek_id` on the index model | Pinecone's default provider-managed encryption |
| Milvus 2.6.0+ with a cipher plugin | yes, *enabled* only | `cipher.ezID` and `cipher.key` on the database and collection properties. Built from source code; needs a live check | object storage, disks, message queue, local cache |
| Milvus below 2.6.0, Milvus Lite, Zilliz default | no | — | encryption is in object storage or on disk |
| Azure AI Search | yes, customer-managed key only | `SearchIndex.encryption_key` | Microsoft-managed AES-256, which is always on (documented) |
| Vertex AI Vector Search | yes, customer-managed key only | `encryption_spec.kms_key_name` on the index, and on the endpoint when one is configured | Google default encryption, which is always on (documented) |
| Bedrock managed knowledge base | yes, customer-managed key only | the knowledge base's own `serverSideEncryptionConfiguration.kmsKeyArn`, under `knowledgeBaseConfiguration` | the AWS default key |
| Bedrock custom knowledge base | no | data-source keys cover **transient ingestion storage only** and never count as at-rest evidence | the backing vector store; scan it with its own connector |
| Qdrant (OSS, Cloud, Hybrid) | no | no API field | Qdrant Cloud encrypts volumes by default (documented) |
| Weaviate (OSS, Cloud) | no | no API field | the storage layer or Weaviate Cloud infrastructure |
| Chroma (local, self-hosted) | no | no API field. Chroma Cloud has per-collection GCP CMEK (`Schema.cmek`), but this connector has no Cloud path | host disk encryption |
| Redis (OSS, Enterprise, Cloud, ElastiCache, MemoryDB, Azure) | no | no command reports it | disk and snapshot encryption, or the provider's control plane |
| OpenAI vector stores | no | no API field. EKM status needs an organisation admin key | OpenAI documents AES-256 at rest |

Vendor-documented always-on encryption is shown as context, as "Vendor
documentation: …", with the source. It is never shown as a pass: it is a
statement about the service, not an observation of this store.

Not yet confirmed against real deployments:
- Milvus `cipher.*` on a server with the plugin loaded, and on Zilliz.
- `serverStatus` on an Atlas cluster with customer-managed keys.
- Amazon OpenSearch index-level encryption.
- Azure's service-level default customer-managed key.
- Whether Pinecone BYOC indexes carry `cmek_id`.

Main sources:
- [Percona pg_tde functions](https://docs.percona.com/pg-tde/functions.html)
- [EDB TDE verification](https://www.enterprisedb.com/docs/tde/latest/enabling/verifying_tde/)
- [Percona MongoDB encryption](https://docs.percona.com/percona-server-for-mongodb/8.0/data-at-rest-encryption.html)
- [OpenSearch storage encryption](https://github.com/opensearch-project/opensearch-storage-encryption)
- [Pinecone describe_index 2026-07](https://docs.pinecone.io/reference/api/2026-07/control-plane/describe_index)
- [Milvus cipher.go](https://github.com/milvus-io/milvus/blob/v2.6.24/internal/util/hookutil/cipher.go)
- [Azure AI Search encryption](https://learn.microsoft.com/azure/search/search-security-built-in)
- [Vertex AI CMEK](https://docs.cloud.google.com/vertex-ai/docs/general/cmek)
- [Bedrock KB encryption](https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html)
- [Qdrant Cloud encryption](https://qdrant.tech/documentation/cloud/encryption/)
- [Weaviate forum on encryption](https://forum.weaviate.io/t/how-does-encryption-work-on-weaviate/5832)
- [Redis encryption FAQ](https://redis.io/faq/doc/2j6kk4yf86/does-redis-support-encryption-at-rest-and-in-transit)
- [OpenAI: your data](https://developers.openai.com/api/docs/guides/your-data)

## How far the sources were checked

Every URL and vendor claim in `at_rest_support.py`, the connectors,
`sources.py` and this document was fetched and checked against the sentence it
supports on 2026-09-24. What that pass corrected:

- **California audit regulation.** Pinned to Cal. Code Regs. tit. 11,
  § 7123(c)(2), with thresholds (§ 7120(b)), due dates (§ 7121) and the
  "if applicable" caveat.
- **EU AI Act dates.** Regulation (EU) 2026/1744 (Digital Omnibus on AI, OJ
  24.7.2026) moved the high-risk obligations, Art. 15 among them, to 2027-12-02
  (Annex III) and 2028-08-02 (Annex I). The Act still states no encryption
  requirement, so the "supporting only" basis is unchanged.
- **HIPAA.** Encryption is still addressable. The proposed rule is not final.
- **PCI 3.5.1.** Mechanism list corrected: hashes must be of the entire PAN,
  and are keyed per 3.5.1.1.
- **SOC 2.** The URL points to the TSC points-of-focus document rather than a
  general SOC page. The CC6.1 encryption point of focus is recorded in the
  source's notes.
- **Vendor-default claims** cite pages that actually say them: Vertex (no
  AES-256 claim without the default-encryption page), each Bedrock backing
  store, Azure PostgreSQL, Cloud SQL and AlloyDB separately, Pinecone, Weaviate,
  Redis, Chroma and OpenAI.

Still resting on secondary or search-index sources:
- The PCI DSS v4.0.1 and AICPA TSC texts, which are licence-gated; paraphrased
  from sources that quote them.
- OpenAI's AES-256 statement; the page refuses automated fetches.
- Weaviate's trust portal.
- Milvus encryption zones, which have no official Milvus documentation and were
  read from tagged source code.

### Open before the criteria leave draft

No crypto criterion is above `draft` lifecycle, and none will be until a
qualified reviewer signs off a `ContentReview`. These are the items that pass
has to confirm, with citations recorded in `sources.py`:

- the CPPA cybersecurity-audit subsection naming encryption at rest and in
  transit, the audit applicability thresholds, and the audit due dates;
- PCI DSS v4.0.1 3.5.1, 3.5.1.2 and 4.2.1 locators;
- the TSC CC6.1 and CC6.7 point-of-focus wording (paraphrased, not quoted);
- the status of the HHS Security Rule proposal;
- that EU AI Act Art. 15 and its recitals contain no explicit encryption
  requirement.
