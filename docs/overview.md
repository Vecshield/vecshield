# VecShield: a technical overview

Apache-2.0 · criterion pack `vecshield-vector-store-draft-4`

VecShield is an open-source scanner for the data that lives inside vector
databases and the pipelines that fill them. It reads the store directly — the
chunks, the metadata, the tenant filters, the configuration the server will
admit to — and reports what it found and, just as carefully, **what it could
not see**. It runs entirely on infrastructure you control.

## The problem

Retrieval-augmented generation has become the ordinary way to put an
organisation's own documents in front of a language model. The pattern is
simple enough to build in an afternoon: take the text you already have, cut it
into passages, convert each passage into a vector, keep the vectors somewhere,
and at question time fetch whichever passages sit closest to the question and
hand them to the model as context. It works well, it is cheap, and it has
spread through most engineering organisations faster than anyone governed it.

What the pattern quietly does is make a second copy of an organisation's most
sensitive text and put it somewhere new. The copy is not a backup and it is not
a cache. The original record lived in a system that knew things about it: who
was allowed to read it, how long it could be kept, which jurisdiction it had to
stay in, who to tell when it was touched. The chunk that ends up in the vector
store inherits none of that. It has an identifier, an array of floating-point
numbers, and whatever metadata the ingestion script happened to attach on the
day it ran.

The tools that would normally notice are looking elsewhere. Data-loss
prevention watches email and endpoints. Posture management reads cloud control
planes. Database scanners understand tables and columns. A vector store is none
of those shapes: its payload is an opaque numeric array with a text blob and a
loose metadata dictionary beside it, reachable through an SDK rather than a
query language. So the tier that now holds the clinical correspondence, the
support transcripts, the contracts and the incident runbooks is, in most
estates, the one tier nobody is scanning.

### Where the gaps are

**Chunks lose their ACLs.** A chunk is a copy. The row-level security,
retention clock and residency rule that governed the source row do not travel
with it. One collection routinely holds data from tenants, jurisdictions and
sensitivity classes that were never meant to sit together.

**Tenant filters are a convention.** Isolation usually depends on every query
carrying the right metadata filter. Nothing in the store proves that holds —
and a filter that is silently ignored looks identical to one that works, until
someone else's data comes back in a result set.

**Retrieval is an injection path.** Text that reaches a model through retrieval
is instruction-shaped input. A poisoned chunk needs no network access and no
credentials; it only needs to be indexed once and then retrieved.

## What the software actually is

VecShield is two Python packages that ship from one distribution. The first,
`vecshield`, is the detection library. It holds the classifier ensemble, the
ingest gate and the dataset scanner, and it has no dependency on anything else
in the project — you can import it inside an ingestion job and never run a
server at all. The second, `vecshield_platform`, is the control plane built on
top of it: connectors for thirteen vector stores, the assessment engines, the
REST API, and a web console. The dependency runs one way only — the platform
imports the library, never the reverse — so the detector stays usable alone.

That split matters because the two halves answer different questions. The
library answers *should this text be embedded at all?*, and is designed to sit
in the path of an ingestion pipeline, where catching something costs almost
nothing. The platform answers *what is already in the store, and what can I
prove about it?* — the harder question, asked after the data has landed.

### Three ways it is used

**As a library.** A few lines in an ingestion job classify each chunk before it
is embedded, and block, redact or tag it. There are worked examples for
LangChain, LlamaIndex, Airflow, Dagster and Prefect, because this is where the
cheapest intervention lives: a secret that never gets embedded never has to be
found and deleted later.

**As a command-line tool.** `audit` runs a full assessment against a configured
store and exits with a code a pipeline can act on. Teams run it against staging
collections on every change, and on a schedule against production.

**As a server.** The same engines behind a REST API and a console, with
assessment history, finding cases, approval workflow, evidence bundles and a
hash-chained audit log — for when the question stops being technical and starts
being organisational.

### What it is not

**Not a model firewall.** It does not sit between a user and a model filtering
prompts and completions. It works on the retrieval tier: what went into the
store, what is in it now, and what comes back out of it.

**Not a cloud posture scanner.** It reads what the database itself exposes. It
does not authenticate to AWS, Azure or GCP management APIs, so anything only
visible there is reported as not observable rather than guessed at.

**Not a compliance certification.** It produces technical evidence a reviewer
can use. It never concludes that an obligation has been met — a deliberate
architectural constraint, not a disclaimer bolted on afterwards.

## What a full audit runs

| Engine | Observes |
|---|---|
| **scan** | Sensitive-data classification per chunk; biometric templates; embedding/dimension consistency; retention horizon against declared schedule |
| **integrity** | Prompt injection in indexed text; duplication and supersession; ingestion anomalies; hubness; provenance against a source manifest |
| **access** | Exhaustive tenant-isolation probe; RBAC diff; API-key audit |
| **posture** | Network exposure; authentication; TLS and plaintext refusal; encryption at rest and field level; CVEs; version support; hardening |
| **compliance** | Criterion evaluation, evidence sufficiency, policy, allow-listing and time-boxed suppression |

The **access** engine is the one most tools approximate and VecShield does
exhaustively. Where a collection carries a tenant field it does not sample: it
enumerates every chunk, then replays each chunk's own vector under every tenant
filter that should *not* return it. Because a vector is at distance zero from
itself, it ranks first among whatever a filter admits — so if the filter would
ever leak that chunk, this query finds it.

| Step | What it does |
|---|---|
| Enumerate | Every chunk id, tenant value, vector digest |
| Canary | Query a tenant value that cannot exist — any hit means the filter is ignored (critical) |
| Full view | One filtered query per tenant; a short result means a lossy index, reported partial |
| Cross sweep | Every (chunk, foreign tenant) pair — a returned chunk is a bleed (critical) |
| Unfiltered | What is reachable with no filter at all (high) |

It is bounded by a query budget, 10,000 per collection by default. Over budget
it queries a deterministic subset and downgrades itself to `sampled` with
partial coverage — it does not quietly claim a proof it did not obtain.

## Three commitments that shape the design

**An unknown is never a pass.** This drove most of the architecture. Every
check reports its own outcome, and the vocabulary distinguishes a check that
passed from one that was inconclusive, one the store could not support, one
that was skipped and one that errored. Those states survive all the way out to
the API, the console and the shell exit code.

| Exit | Meaning |
|---|---|
| `0` | No high or critical finding, **and** the store was read in full |
| `1` | Could not run — bad input, store unreachable |
| `2` | A high or critical finding |
| `3` | Clean, *but* part of the store went unread: a cap was hit, or rows were hidden by row-level security. **Not a pass.** |

Exit `3` exists because a scan that hit a limit, or was quietly denied rows, is
not the same as a clean one and must not be allowed to look like one in a
dashboard.

**Observation is separated from judgement.** Compliance assessment keeps four
things in four distinct fields: whether the obligation applies to this system
at all, what the technical checks observed, whether the supporting evidence was
supplied and accepted, and what a named human reviewer concluded. VecShield
fills in the second. It can prompt on the first and track the third. It never
writes the fourth. A passing check is not a satisfied obligation, and a failing
one may be perfectly well answered by a compensating control the scanner cannot
see — so collapsing these into one red-or-green verdict would make the tool
actively misleading in exactly the setting where it matters most.

**Claims about the detectors are measured.** It is easy to assert that a
classifier is accurate. VecShield ships a labelled corpus in the repository,
scores itself against it, and publishes precision and recall with confidence
intervals — declining to report a rate at all where there are too few
observations to support one. CI fails if precision regresses.

## Detection

Classifiers run independently and merge: the most sensitive label wins, ties
break on confidence, and spans and detector names are unioned so every finding
is traceable to the rule that fired. PII found in clinical context is promoted
to PHI.

| Label | Detectors | Examples |
|---|---|---|
| `pii` | 58 | SSN, national IDs, passport, address |
| `secret` | 33 | cloud keys, tokens, private keys |
| `phi` | 14 | MRN, NPI, MBI, DEA, clinical codes |
| `pci` | 14 | PAN, track data, IBAN, SWIFT |
| `special_category` | 10 | GDPR Art. 9 including genetic |
| `criminal_offence` | 1 | conviction context |

**Checksums cut false positives.** 33 detectors validate structure rather than
shape alone — Luhn for cards and IMEI, ABA weights for routing numbers, mod-97
for IBAN and the French NIR, mod-11 for the Dutch BSN and Portuguese NIF,
ISO 7064 for the German tax ID.

### Measured, not asserted

A labelled corpus of 112 items ships in [`benchmark/corpus/`](../benchmark/corpus/).
`benchmark run` scores the detectors, `calibrate` derives confidence classes
from the lower bound of each interval, and `compare` fails CI when precision
drops beyond tolerance.

| Family | n | Precision | Recall | 95% CI (precision) |
|---|---|---|---|---|
| injection | 55 | 1.00 | 1.00 | 0.86–1.00 |
| secrets | 31 | 0.94 | 1.00 | 0.74–0.99 |
| pii, regex only | 10 | not measured | 0.50 | — |
| pci / phi / clean | 16 | too few observations — reported as not measured | | |

The corpus is small and was written by the detector authors; the intervals are
wide and the content classifier is English-only. The project publishes these
caveats alongside the numbers rather than quoting a headline score. The fuller
account of what the detectors cannot see is in
[detection limitations](detection_limitations.md).

### What poisoning looks like

Injection scoring decodes before it matches — base64, hex and URL encoding are
unwrapped, and text is NFKC-normalised — so evasion does not buy a clean score.
A directive that only becomes visible after decoding is flagged as a hidden
directive. The classes covered: instruction override, system and role
impersonation, policy-bypass requests, exfiltration via rendered images, tool
and function abuse, fake conversation delimiters, retrieval-ranking
manipulation, homoglyphs and zero-width and soft-hyphen tricks, Unicode tag
smuggling, and CSS- or comment-hidden text.

Mapped to **OWASP LLM01 / LLM04 / LLM08** and **MITRE ATLAS AML.T0070,
AML.T0071**.

## The regulatory model

| Framework | Criteria |
|---|---|
| HIPAA 45 CFR 164 Subpart C | 18 |
| GDPR | 4 |
| SOC 2 | 4 |
| CCPA / CPRA | 3 |
| PCI-DSS | 2 |
| EU AI Act | 2 |
| **Total** | **33** |

Backed by **75 source records** carrying issuer, section, URL, edition,
effective and compliance dates, legal status, retrieval timestamp and content
hash. Licensed standards are marked non-redistributable and linked rather than
quoted.

**Versioned on purpose.** When the pack changes, a reviewer decision carries
forward only if that criterion's digest is unchanged; otherwise it goes stale
and must be made again against the current wording. A decision cannot silently
come to describe a criterion that has since been rewritten. See the
[pack migration record](compliance/pack-draft-4-migration.md).

## Where it runs, and who holds the data

VecShield runs inside your environment — a VPC, a Kubernetes cluster, a laptop,
or an air-gapped datacentre. Chunks, vectors, findings, audit logs and reports
stay in infrastructure you control. There is no vendor backend to phone home
to, and telemetry is off by default. The NLP model wheels are hash-pinned and
installed at build time, so a scanning run needs no network access at all.

Access is role-aware: a viewer reads results, an operator runs assessments, a
compliance role handles privacy requests and evidence, an admin manages the
system. Destructive remediation is staged and approved separately from
execution, enforced server-side, so the person who approves a deletion plan
cannot also be the person who runs it. Sensitive values are masked by default,
and unmasking one is itself a gated action that lands in the audit log.

| Control | What it means |
|---|---|
| Masking by default | Chunk values are masked; revealing one is gated and audit-logged |
| Hash-chained log | Append-only `audit.jsonl`; tampering breaks the chain |
| Allow-list and suppression | Known-good findings are suppressed with an expiry, not deleted |
| Capability honesty | A connector that cannot delete raises rather than reporting success |

## Where teams use it

| Setting | How |
|---|---|
| Pre-production gate | Run `audit` in CI against a staging collection; exit `2` blocks the release on a high finding, exit `3` blocks on incomplete coverage |
| Ingestion firewall | Call the gate from a LangChain, LlamaIndex, Airflow, Dagster or Prefect step to block or redact chunks *before* they are embedded and become expensive to remove |
| Multi-tenant SaaS | Prove per chunk that one customer's filter cannot surface another's data, and keep the proof as evidence rather than an assertion |
| Privacy requests | Locate a subject across every registered store, execute erasure, then verify it three ways — re-enumeration, direct id re-read, and retrieval replay using the deleted chunk's own vector, which is what catches a soft delete |
| Audit preparation | Produce evidence bundles with a hash-chained audit log, where unmasking a value is itself a gated, logged action |

## Try it

A synthetic estate — six registered stores, fourteen collections and fifteen
regulation-specific scenarios — seeds into a local Chroma directory. No API
keys, no network, nothing external.

```bash
cd demo
docker compose up --build
```

The console is then at `127.0.0.1:8088`, signed in as `admin` /
`vecshield-demo`, with every finding, case and evidence record already
populated. A test in CI asserts that every scenario still fires, so the demo
cannot quietly rot. See [`demo/README.md`](../demo/README.md).

## Deployment

Self-hosted Docker (full or slim image), Kubernetes via the Helm chart, or an
IaC scaffold. The chart refuses to render without auth configured and pins a
single writer. NLP model wheels are SHA-256 pinned and installed at build time,
so scanning runs fully offline.

| | |
|---|---|
| Library | `pip install vecshield` — embed the detector directly |
| Extras | One per connector; install only what you deploy |
| Python | 3.10+ |

Full detail in [deployment](deployment.md).

## The state of the project

VecShield is open source under Apache-2.0, with no paid tier, no feature gating
and no licence key: the detection engine, the connectors, the console and the
compliance layer are all in the repository. It carries roughly 3,500 tests, a
console test suite that renders the shipped interface in a sandboxed DOM, and a
benchmark gate on the detectors.
