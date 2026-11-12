# Customer Support And Email Demo

Demo title:

> Your support copilot indexed every customer email. VecShield shows what it accidentally embedded.

This demo uses a synthetic AcmeDesk support corpus. Do not seed real customer
emails, tickets, CRM notes, or billing records into the default demo.

## Files

Run the generator to create the data files in this folder:

```bash
python3 examples/customer_support_email_demo/generate_support_email_demo.py
```

Generated files:

- `qdrant_points.jsonl`: Qdrant point records with `collection`, `id`, `vector`, and `payload`.
- `stores.qdrant.json`: VecShield Enterprise config that registers the local Qdrant store and demo policies.
- `sample_customers.json`: synthetic customers, including the Maya Brooks deletion-request subject.
- `injected_risks_manifest.json`: every injected risk case, expected VecShield result, and affected point IDs.
- `runtime_events.jsonl`: runtime query-abuse replay records for `/runtime/events`.
- `ingest_firewall_samples.json`: three chunks for the ingest-firewall step.
- `demo_summary.json`: counts by collection and injected risk tag.

## Data Model

Qdrant collections:

- `support_ticket_rag`
- `inbound_email_rag`
- `billing_disputes_rag`
- `crm_account_notes_rag`
- `internal_runbooks_rag`
- `help_center_public_kb`

Every point payload includes the raw chunk text in `content` because the
VecShield Qdrant connector reads `content`, `text`, `document`, `chunk`, `body`,
or `page_content`. The demo also sets:

- `tenant_id`
- `customer_id`
- `account_id`
- `ticket_id`
- `thread_id`
- `source_system`
- `channel`
- `access_scope`
- `retention_class`
- `contains_attachment_text`
- `generated_from`
- `risk_tags`

Embeddings are deterministic 384-dimensional hash vectors. They are not meant to
model semantic quality; they make the Qdrant demo repeatable without an external
embedding service. The cross-tenant canary points intentionally share a vector
seed so tenant-filter failures are easy to explain.

## Start Qdrant

Install the Qdrant connector dependency in the same Python environment that
runs `vecshield-platform`:

```bash
python -m pip install qdrant-client
```

```bash
docker run --rm -p 6333:6333 -p 6334:6334 \
  -v "$(pwd)/.demo/support_email_qdrant:/qdrant/storage" \
  qdrant/qdrant
```

Seed the database:

```bash
python3 examples/customer_support_email_demo/qdrant_seed.py \
  --url http://localhost:6333
```

The seeder creates payload indexes for `tenant_id`, `customer_id`,
`account_id`, `source_system`, `access_scope`, `retention_class`, and
`risk_tags`.

## Start VecShield Enterprise

```bash
vecshield-platform serve \
  --config examples/customer_support_email_demo/stores.qdrant.json \
  --state-dir .demo/support_email_state \
  --host 127.0.0.1 \
  --port 8088
```

Open `http://127.0.0.1:8088/`.

## Dashboard Walkthrough

1. Open **Stores** and test `support-email-qdrant`.
2. Open **Compliance → Policies → Templates** and show that each template exposes attribution, action, and rule JSON.
3. Open **Policies** and show the demo policies instantiated from CCPA/CPRA, PCI-DSS, SOC 2, GDPR, and General security templates.
4. Open **Assessments → New assessment**, choose `support-email-qdrant`, and run a full audit.
5. Run the integrity scan on `inbound_email_rag` to find the stored prompt-injection email.
6. Run the isolation probe on `support_ticket_rag` with tenant field `tenant_id`.
7. Open **Operations → Ingest** and paste the samples from `ingest_firewall_samples.json`.
8. Open **Compliance → Personal data requests** and create a request for `maya.brooks@example-customer.test`.
9. Open **Operations → Runtime** after replaying `runtime_events.jsonl`.
10. Close with **System → Audit log** and **Assessments → History** to show the evidence trail.

## Runtime Replay

Replay events with curl:

```bash
while read -r event; do
  curl -sS -X POST http://127.0.0.1:8088/runtime/events \
    -H 'Content-Type: application/json' \
    -d "$event" >/dev/null
done < examples/customer_support_email_demo/runtime_events.jsonl
```

Then refresh **Runtime Alerts**. Expected alerts include bulk retrieval,
collection sweep, and enumeration-style behavior.

## Talk Track

Opening:

> Support data is the messiest data in the company. Customers paste card
> numbers, passwords, addresses, reset links, logs, and confidential business
> context. VecShield audits the retrieval layer where that mess becomes
> searchable.

Data point:

> The demo is synthetic, but the structure mirrors support systems: ticket body,
> inbound email body, billing note, CRM note, runbook, public KB, and payload
> metadata. VecShield sees both chunk text and metadata that can identify a
> customer or tenant.

Close:

> VecShield runs where the support data already lives. Raw tickets, emails,
> embeddings, findings, and reports stay customer-controlled by default.

## Optional Base Dataset

The generator currently creates synthetic seed records. A future variant can
load a local Bitext support CSV export, map `instruction` to customer message,
map `response` to agent reply, and then keep the same injected-risk manifest.
Do not make demos depend on downloading a dataset at presentation time.
