<p align="center">
  <img src="docs/brand/vecshield-logo-lockup.png"
       alt="VecShield"
       width="520">
</p>

<h1 align="center">VecShield</h1>

<p align="center">
  <strong>Open-source security and compliance scanning for vector databases and RAG pipelines.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
</p>

<p align="center">
  <a href="demo/README.md">Demo</a> ·
  <a href="docs/overview.md">Technical overview</a> ·
  <a href="docs/README.md">Docs</a> ·
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

Your RAG stack probably has a vector store nobody audits. It holds chunks of
whatever got embedded — support tickets, clinical notes, source code, Slack
exports — and it usually has weaker access control than the systems that data
came from. VecShield looks at what is actually in there.

**Two things, one install:**

- **A detection library** (`vecshield`) you call from your own code to keep
  sensitive data out of a pipeline before it is embedded.
- **A server with a web console** (`vecshield_platform`) that connects to your
  vector stores and assesses what already landed in them.

```
vecshield_platform  ──imports──▶  vecshield
```

The library never imports the server, so you can use it on its own.

## Try it

A seeded estate and the full console, with synthetic data, in one command:

```bash
git clone https://github.com/vecshield/vecshield
cd vecshield/demo
docker compose up --build
```

Then open <http://127.0.0.1:8088> and sign in as `admin` / `vecshield-demo`.
The data is synthetic and the console is published on loopback only. Details
and a guided walkthrough: [`demo/README.md`](demo/README.md).

## Install

```bash
pip install vecshield                     # the library and CLI
pip install "vecshield[chroma]"           # plus a vector-store connector
pip install "vecshield[chroma,nlp]"       # plus NER for names and addresses
```

Connector extras: `chroma`, `pgvector`, `qdrant`, `weaviate`, `milvus`,
`pinecone`, `redis`, `opensearch`, `mongodb`, `openai`, `azure`, `bedrock`,
`vertex`. Install only what you actually connect to.

## Use the library

Gate an ingestion pipeline so sensitive chunks never reach the embedder:

```python
from vecshield import check_text

result = check_text("Contact Jane at jane.doe@example.org, SSN 219-09-9999")

result.has_pii      # True
result.label        # 'pii'
result.confidence   # 0.95

for span in result.spans:
    print(span["detector"], span["label"], span["preview"])
    # us_ssn pii 21*******99
    # email  pii ja****************rg
```

Previews are masked by default. A tool that finds secrets should not be the
thing that then copies them into your logs.

```bash
vecshield detect ./notes.txt            # classify a file
vecshield ingest-check ./chunks.jsonl   # gate chunks before embedding
vecshield training-check ./dataset.jsonl
vecshield redact-preview ./notes.txt
```

See the [SDK reference](docs/library/sdk_reference.md) and
[ingestion integration](docs/library/ingestion_integration.md) for LangChain,
LlamaIndex, Airflow, Dagster and Prefect.

## Run the server

```bash
vecshield-platform audit --connector chroma --path ./chroma_data --report out.html
vecshield-platform serve --config ./vecshield.json --state-dir ./state --port 8088
```

An assessment runs five engines over a store:

| Engine | What it looks for |
|---|---|
| **Scan** | PII, PHI, payment data and credentials in the stored chunks |
| **Posture** | Network exposure, TLS, encryption at rest, known CVEs |
| **Integrity** | Prompt injection, poisoning, duplication, embedding anomalies |
| **Access** | RBAC drift, API-key hygiene, exhaustive tenant-isolation probing |
| **Compliance** | Policy evaluation, allow-listing, evidence and obligation tracing |

Exit codes are built for CI:

| Code | Meaning |
| --- | --- |
| `0` | No high or critical finding, **and** the store was read in full. |
| `1` | The command could not run: bad input, store unreachable. |
| `2` | A high or critical finding. |
| `3` | No high or critical finding, but part of the store went unread. **Not a pass.** |

That last one is the point. A scan that could not read everything is not a
clean scan, and VecShield will not report it as one.

## What this does not do

Worth saying plainly, because security tools are usually sold the other way:

- **Detection is not compliance.** VecShield maps findings to criteria from
  GDPR, HIPAA, PCI-DSS, SOC 2, CCPA/CPRA and the EU AI Act, but a technical
  result, whether it applies, whether its evidence suffices, and a reviewer's
  conclusion are four separate fields. Only the first is automated. Nothing
  here establishes legal compliance.
- **A clean result is not proof of absence.** The detectors miss things, and
  [`docs/detection_limitations.md`](docs/detection_limitations.md) says which
  things, by regulation.
- **Unobservable is not a pass.** When a connector cannot report something —
  disk encryption, cloud KMS, IAM — VecShield says *not observable* rather than
  guessing. Missing capability is reported as unknown coverage, never as a pass.
- **It is not a cloud posture scanner.** It sees what the vector database's own
  interface exposes. For KMS, volume encryption or cloud IAM, use a CSPM.

## Your data stays yours

The server runs in your environment. Chunks, embeddings, findings, audit logs
and reports stay in infrastructure you control. There is no managed backend,
telemetry is off by default, and the only outbound request any engine makes is
to a vulnerability feed, which you can disable.

## Project layout

```
vecshield/            detection library: classifiers, ingest gate, dataset scan
vecshield_platform/   server, console, connectors, assessment engines
  api/                FastAPI app + the console served from api/dashboard/dist/
  connectors/         13 vector-store connectors behind one ABC
  scan/ posture/ integrity/ access/ compliance/      the five engines
demo/                 the seeded demo estate and its Docker Compose stack
benchmark/corpus/     labelled corpus the detectors are scored against
benchmarks/           harnesses for public research datasets
docs/                 documentation
tests/                ~3500 tests
```

## Contributing

Issues and pull requests are welcome. [`CONTRIBUTING.md`](CONTRIBUTING.md) has
the development setup and the gates a change has to pass; detector changes also
have to clear the benchmark gates. Security reports:
[`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
