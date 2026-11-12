# The VecShield demo

A seeded vector-store estate and the web console, in one command. Everything
is synthetic and everything runs locally: no API keys, no telemetry, no
external vector database, no network calls.

## Run it

```bash
cd demo
docker compose up --build
```

First run takes a few minutes: it builds the image, seeds the estate, and runs
a full assessment against every store. When it is ready the container prints a
banner with a generated admin password:

```
  VecShield demo console
  ----------------------
  URL       http://127.0.0.1:8088
  Username  admin
  Password  <generated on first boot>
```

Open <http://127.0.0.1:8088> and sign in. **You will be asked to change the
password immediately** — the bootstrap account is forced to rotate on first
sign-in, and the demo does not make an exception for itself.

Lost the banner? `docker compose exec vecshield cat /data/admin-password`.

| Command | Effect |
|---|---|
| `docker compose up` | Start. Re-seeding is skipped if an estate already exists, so triage you did survives a restart. |
| `docker compose down` | Stop, keeping the estate. |
| `docker compose down -v` | Stop and discard the estate, so the next start seeds afresh. |

The console is published on `127.0.0.1` only. It is an admin interface that can
delete vectors; do not bind it to a public address without real authentication
in front of it. See [deployment](../docs/deployment.md) for a real install.

## Run it without Docker

```bash
pip install -e ".[chroma]"
python demo/seed.py --state ./demo-state --strict
VECSHIELD_INITIAL_ADMIN_PASSWORD="$(python -c 'import secrets;print(secrets.token_urlsafe(18))')" \
  vecshield-platform serve --config ./demo-state/vecshield.json \
    --state-dir ./demo-state/state --port 8088
```

Bound to `127.0.0.1`, sign-in is not required.

## What gets seeded

Six registered stores, fourteen collections, 171 chunks and 111 findings,
carrying planted issues across six regulatory frameworks:

| Store | What it stands in for |
|---|---|
| `clinical-rag` | Clinical guidance with patient correspondence mixed in (HIPAA) |
| `customer-360` | Multi-tenant support and marketing data (GDPR, CCPA/CPRA) |
| `payments-ops` | Chargeback notes and gateway runbooks (PCI-DSS) |
| `platform-runbooks` | Deploy runbooks and incident timelines (SOC 2) |
| `ai-corpus` | A training corpus with contributed content (EU AI Act) |
| `legal-archive` | Registered and connected, but **deliberately never assessed** |

That last one matters. A store nobody has scanned is not a clean store, and the
console says so rather than leaving it out of the totals: it appears as *never
assessed* on the overview and in the crypto estate view.

Fifteen scenarios are planted. Fourteen produce a specific finding; the
fifteenth is an estate-wide view with no single signal. Each one also carries a
**hard negative** — something that looks sensitive but is not — so the demo
shows the detectors declining to fire as well as firing.

One collection, `payments-ops/merchant_disputes`, has a **real cross-tenant
leak**: a tenant filter that fails because a numeric tenant id loses precision
as a float and collides with another tenant's. The isolation prober finds it.

[WALKTHROUGH.md](WALKTHROUGH.md) takes each regulation through the full
lifecycle: inventory, scan, triage, action, close.

## The demo checks itself

`seed.py --strict` does not just load data; it verifies that every scenario it
advertises actually fires, and fails rather than serving a demo that quietly
stopped working. A planted cross-tenant leak that goes undetected fails the
seeder whether or not `--strict` was passed.

`tests/test_demo.py` runs the same check in CI, so a detector change that
breaks a scenario breaks the build:

```bash
python -m pytest tests/test_demo.py -q
```

## Honest limits of this demo

- **The data is synthetic.** Personal details, card numbers and credentials are
  invented, or are test values published by their issuers for this purpose. The
  detectors' behaviour on real data will differ.
- **Detection is not compliance.** The console maps findings to framework
  criteria, but a technical result, its applicability, the sufficiency of its
  evidence and a reviewer's conclusion are four separate things, and only the
  first is automated. See [detection limitations](../docs/detection_limitations.md).
- **Regex detectors only.** The demo image skips the NLP extra to stay small
  and offline, so recall on names, addresses and locations is lower than a full
  install. See [NLP models](../docs/nlp_models.md).
- **Chroma only.** Posture checks that need a real server — TLS, network
  exposure, CVEs, encryption at rest — report *not observable* against a local
  Chroma directory. That is the correct answer, not a pass. To exercise them,
  register a real store.

## Extending the demo to pgvector

`seed.py` can additionally seed two PostgreSQL + pgvector stores, which makes
the posture and encryption checks meaningful:

```bash
docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=secret pgvector/pgvector:pg16
VECSHIELD_STORE_DEMO_PG_PASSWORD=secret python demo/seed.py \
  --state ./demo-state --strict \
  --pgvector-dsn postgresql://postgres@localhost:55432/postgres
```

The password is read from the environment and never written to the config file.
