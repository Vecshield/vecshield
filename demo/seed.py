#!/usr/bin/env python
"""Seed a self-contained VecShield console demo.

Builds five local Chroma stores from `scenarios.py`, registers them, attaches
the policies for the regulations that reach each one, runs real assessments, and
populates the surfaces the console has gained — findings with cases, evidence,
reviews, exceptions, runtime alerts and job history.

The last step is the one that matters: **it verifies each scenario actually
fired** and prints what did not. A demo that claims fifteen scenarios and
silently shows nine is the exact failure this product exists to prevent, so the
seeder reports the gap and can exit non-zero on it.

    python demo/seed.py --state ./demo-state

Everything is synthetic. See the module docstring in `scenarios.py`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import shutil
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

# demo/seed.py -> the repository root, so an uninstalled checkout works.
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scenarios import (  # noqa: E402
    PG_MARKER_TABLE,
    PG_SCENARIOS,
    PG_STORES,
    SCENARIOS,
    STORES,
    CollectionSpec,
    Scenario,
    StoreSpec,
)

#: Which policy templates each store gets. A store carries the policies for the
#: regulations that actually reach it, rather than all of them everywhere, so
#: the Policies screen reads like a deployment rather than a catalogue.
STORE_POLICIES = {
    "clinical-rag": ["hipaa-phi", "hipaa-phi-invertible", "sec-high-catchall"],
    "customer-360": ["gdpr-pii-collection", "gdpr-pii-invertible",
                     "gdpr-cross-tenant", "ccpa-personal-info"],
    "payments-ops": ["pci-pan", "pci-secrets", "sec-secrets"],
    "platform-runbooks": ["soc2-secrets", "soc2-injection", "soc2-anomaly",
                          "sec-secrets"],
    "ai-corpus": ["aiact-data-governance", "aiact-robustness", "sec-high-catchall"],
    # The pgvector stores carry the policies for what actually reaches them:
    # clinical correspondence, and a collection two tenants share.
    "pgvector-clinical": ["hipaa-phi", "sec-high-catchall"],
    "pgvector-support": ["gdpr-cross-tenant", "sec-secrets"],
}

#: `expects` entries checked against classification labels. Anything else is
#: checked against check names and finding categories instead.
LABEL_EXPECTATIONS = {"pii", "phi", "pci", "secret"}


def build_store(root: Path, spec: StoreSpec, rng: random.Random,
                pg: "PgTarget | None" = None) -> str:
    """Create one store with its collections and their metadata.

    Dispatches on `spec.kind` so there is one place that knows how a demo store
    is built, rather than one per backend scattered through the seeder.
    """
    if spec.kind == "pgvector":
        if pg is None:
            raise ValueError(
                f"{spec.store_id} is a pgvector store but no database was given")
        return build_pgvector_store(pg, spec, rng)
    return build_chroma_store(root, spec, rng)


def build_chroma_store(root: Path, spec: StoreSpec, rng: random.Random) -> str:
    """Create one Chroma store with its collections and their metadata."""
    import chromadb

    path = root / spec.store_id
    if path.exists():
        shutil.rmtree(path)
    client = chromadb.PersistentClient(path=str(path))

    for collection in spec.collections:
        metadata = {"description": collection.description}
        if collection.embedding_model:
            # The connector reads this and the inversion scorer needs it: with
            # no model name it falls back to 0.55, below every threshold that
            # asks whether the vectors themselves are recoverable.
            metadata["embedding_model"] = collection.embedding_model
        handle = client.create_collection(collection.name, metadata=metadata)
        docs = collection.docs
        metadatas = []
        for i in range(len(docs)):
            row = {"ingested_at": "2026-09-01"}
            # A document declared untagged carries no tenant key at all, so the
            # isolation check has real untagged chunks to find and sweep.
            if i not in collection.untagged:
                row["tenant_id"] = collection.tenants[i % len(collection.tenants)]
            # A document whose provenance was "never recorded" must actually
            # lack a source key. Stamping one on everything would make the
            # provenance scenarios describe a problem the store does not have.
            if i not in collection.unsourced:
                row["source"] = collection.rare_sources.get(
                    i, f"{collection.name}-{collection.source}")
            row.update(collection.extra.get(i, {}))
            metadatas.append(row)
        # Real embeddings of one corpus cluster; independent Gaussians do not,
        # so an "outlier" among them is meaningless. Each collection gets a base
        # direction with per-document noise, and a declared outlier gets its own.
        base = [rng.gauss(0, 1) for _ in range(collection.dimension)]
        embeddings = []
        for i in range(len(docs)):
            if i in collection.outliers:
                embeddings.append([rng.gauss(0, 1) for _ in range(collection.dimension)])
            else:
                embeddings.append([b + rng.gauss(0, 0.25) for b in base])
        handle.add(
            ids=[f"{collection.name}-{i:03}" for i in range(len(docs))],
            documents=docs,
            embeddings=embeddings,
            metadatas=metadatas,
        )
    return str(path)


#: Environment variable the demo config references for the Postgres password.
#: `VECSHIELD_STORE_` is the default allowed prefix for a secret reference
#: (ADR 0003), so this resolves with no allowlist configuration, and the
#: password itself never reaches `vecshield.json`.
PG_PASSWORD_ENV = "VECSHIELD_STORE_DEMO_PG_PASSWORD"


@dataclass(frozen=True)
class PgTarget:
    """The Postgres the demo's pgvector stores are built in."""

    dsn: str
    host: str
    port: int
    dbname: str
    user: str
    password: str

    @classmethod
    def from_dsn(cls, dsn: str) -> "PgTarget":
        parts = urllib.parse.urlparse(dsn)
        if parts.scheme not in ("postgres", "postgresql"):
            raise ValueError(f"not a Postgres DSN: {parts.scheme or dsn!r}")
        if not parts.hostname:
            raise ValueError("DSN has no host")
        return cls(dsn=dsn, host=parts.hostname, port=parts.port or 5432,
                   dbname=(parts.path or "/postgres").lstrip("/") or "postgres",
                   user=urllib.parse.unquote(parts.username or "postgres"),
                   password=urllib.parse.unquote(parts.password or ""))

    def connect(self):
        import psycopg
        return psycopg.connect(self.dsn, autocommit=True)

    def stored_conn(self, spec: StoreSpec) -> dict:
        """What is written to `vecshield.json` for this store.

        Never the DSN and never the password: `_check_secrets` treats both as
        plaintext secrets, so the password is referenced indirectly and
        resolved at connect time by `ConfigStore.build_registry`.
        """
        return {"host": self.host, "port": self.port, "dbname": self.dbname,
                "user": self.user, "schema": spec.schema,
                "password_env": PG_PASSWORD_ENV}

    def runtime_conn(self, spec: StoreSpec) -> dict:
        """Connector kwargs for the seeder's own audit run."""
        conn = self.stored_conn(spec)
        conn.pop("password_env")
        conn["password"] = self.password
        return conn


def pg_vector_literal(values) -> str:
    """A pgvector input literal. The text form is `[a,b,c]`, no spaces."""
    return "[" + ",".join(repr(float(v)) for v in values) + "]"


def check_pg_schemas(pg: "PgTarget", specs: list[StoreSpec]) -> None:
    """Refuse the whole run if any target schema is not demo-owned.

    Checked for every store before the first one is built, so a collision on
    the second schema cannot be discovered only after the first has already
    been dropped.
    """
    with pg.connect() as conn:
        for spec in specs:
            exists = conn.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
                (spec.schema,)).fetchone()
            if exists and not pg_schema_is_demo_owned(conn, spec.schema):
                raise SystemExit(refusal_message(spec.schema))


def pg_schema_is_demo_owned(conn, schema: str) -> bool:
    """True when `schema` carries the marker table this seeder writes."""
    return bool(conn.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = %s AND table_name = %s",
        (schema, PG_MARKER_TABLE)).fetchone())


def refusal_message(schema: str) -> str:
    return (f"refusing to touch schema {schema!r}: it exists but carries no "
            f"{PG_MARKER_TABLE} table, so it was not created by this seeder. "
            f"Drop it yourself or point --pgvector-dsn at another database.")


def reset_pg_schema(conn, schema: str) -> None:
    """Drop and recreate a demo-owned schema, refusing to touch anything else.

    The Chroma path removes a directory it created. The equivalent here acts on
    a database the caller supplied, so a schema that exists without the demo
    marker table is left alone and the seeder stops: a name that happens to
    collide with real data must never cost someone their data.
    """
    from psycopg import sql

    exists = conn.execute(
        "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
        (schema,)).fetchone()
    if exists:
        if not pg_schema_is_demo_owned(conn, schema):
            raise SystemExit(refusal_message(schema))
        conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
    conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    conn.execute(sql.SQL("CREATE TABLE {}.{} (seeded_at timestamptz NOT NULL DEFAULT now())")
                 .format(sql.Identifier(schema), sql.Identifier(PG_MARKER_TABLE)))
    conn.execute(sql.SQL("INSERT INTO {}.{} DEFAULT VALUES")
                 .format(sql.Identifier(schema), sql.Identifier(PG_MARKER_TABLE)))


def build_pgvector_store(pg: PgTarget, spec: StoreSpec, rng: random.Random) -> str:
    """Create one pgvector store: one schema, one table per collection.

    The connector discovers collections by catalogue introspection — a table
    with a pgvector column — and picks the text column by name, the id from the
    primary key, and metadata from whatever columns are left. So the table
    layout here is the interface, not an implementation detail.
    """
    from psycopg import sql

    with pg.connect() as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        reset_pg_schema(conn, spec.schema)

        for collection in spec.collections:
            # Metadata columns beyond the three every collection writes. A
            # spec's `extra` can name anything, and a key with no column would
            # be silently dropped, so each one gets a column of its own.
            extra_cols = sorted({key for row in collection.extra.values()
                                 for key in row} - {"tenant_id"})
            table = sql.Identifier(spec.schema, collection.name)
            conn.execute(sql.SQL(
                "CREATE TABLE {} (id bigserial PRIMARY KEY, content text, "
                "tenant_id text, source text, ingested_at date, {} embedding vector({}))"
            ).format(
                table,
                sql.SQL("").join(sql.SQL("{} text, ").format(sql.Identifier(c))
                                 for c in extra_cols),
                sql.Literal(collection.dimension)))

            docs = collection.docs
            # Same construction as the Chroma path: one base direction per
            # collection with per-document noise, and a declared outlier given
            # its own direction, so "sits far from the rest" means something.
            base = [rng.gauss(0, 1) for _ in range(collection.dimension)]
            columns = ["content", "tenant_id", "source", "ingested_at",
                       *extra_cols, "embedding"]
            insert = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                table,
                sql.SQL(", ").join(sql.Identifier(c) for c in columns),
                sql.SQL(", ").join(sql.Placeholder() * len(columns)))
            for i, text in enumerate(docs):
                extra = collection.extra.get(i, {})
                # An untagged document carries no tenant at all. In Postgres
                # that is NULL, which `tenant_id = %s` excludes exactly as
                # Chroma's absent key does, so the isolation probe sees the
                # same untagged chunks to sweep.
                tenant = None
                if i not in collection.untagged:
                    tenant = extra.get("tenant_id") or collection.tenants[
                        i % len(collection.tenants)]
                source = None
                if i not in collection.unsourced:
                    source = collection.rare_sources.get(
                        i, f"{collection.name}-{collection.source}")
                if i in collection.outliers:
                    vector = [rng.gauss(0, 1) for _ in range(collection.dimension)]
                else:
                    vector = [b + rng.gauss(0, 0.25) for b in base]
                conn.execute(insert, [
                    text, tenant, source, "2026-09-01",
                    *[extra.get(c) for c in extra_cols],
                    pg_vector_literal(vector)])

            # `vector_cosine_ops` is required, not a preference: the connector's
            # query path uses the cosine operator `<=>`, and an index built with
            # another operator class would not be used for it at all.
            conn.execute(sql.SQL(
                "CREATE INDEX ON {} USING hnsw (embedding vector_cosine_ops) "
                "WITH (m = 16, ef_construction = 64)").format(table))
    return f"{pg.host}:{pg.port}/{pg.dbname} schema {spec.schema}"


def open_demo_store(spec: StoreSpec, stores_root: Path, pg: "PgTarget | None"):
    """A connector for one demo store, whichever backend it lives on."""
    from vecshield_platform.connectors import build_connector

    if spec.kind == "pgvector":
        if pg is None:
            raise ValueError(f"{spec.store_id} needs a Postgres but none was given")
        return build_connector("pgvector", **pg.runtime_conn(spec))
    return build_connector("chroma", path=str(stores_root / spec.store_id))


def observed_labels(result, collection: str | None = None) -> set[str]:
    """Every classification label a run produced, lower-cased.

    Scoped to one collection when asked. Pooling per store let a scenario
    about `curated_corpus` be confirmed by an injection finding on
    `community_contrib` — a different collection, a different scenario.
    """
    seen: set[str] = set()
    for finding in result.all_findings():
        if collection and finding.collection != collection:
            continue
        evidence = finding.evidence or {}
        seen.update(str(k).lower() for k in (evidence.get("labels") or {}))
        # Detector names too, so a known miss can name the detector that
        # should have fired and be verified as still not firing.
        seen.update(str(k).lower() for k in (evidence.get("detector_counts") or {}))
        for example in evidence.get("examples") or []:
            if isinstance(example, dict) and example.get("label"):
                seen.add(str(example["label"]).lower())
    return seen


def observed_signals(result, collection: str | None = None) -> set[str]:
    """Signals a run actually produced: finding categories and passing checks.

    Deliberately narrow. An earlier version also swept in every *key* of every
    evidence dict and matched on substrings, which confirmed three scenarios
    whose findings did not exist — the verification step was itself making the
    claim it was built to check. A signal counts only when a finding carries
    that category, or a check of that name ran and did not pass.
    """
    seen: set[str] = set()
    for finding in result.all_findings():
        if collection and finding.collection != collection:
            continue
        # An "info" finding saying a check found nothing is not the signal; it
        # is the opposite of the signal.
        if str(finding.severity.value).lower() in ("info", "none"):
            continue
        seen.add(str(finding.category).lower())
        evidence = finding.evidence or {}
        if evidence.get("check"):
            seen.add(str(evidence["check"]).lower())
        # The integrity checks all share one category and differ by title.
        # Naming them lets a scenario expect the specific check it planted for.
        title = finding.title.lower()
        for keyword, signal in (("prompt-injection", "injection"),
                                ("anomalous embeddings", "anomaly"),
                                ("provenance", "provenance")):
            if keyword in title:
                seen.add(signal)
    for job in result.jobs:
        for outcome in (job.stats or {}).get("check_outcomes", []) or []:
            if not isinstance(outcome, dict):
                continue
            if outcome.get("check") and outcome.get("outcome") == "failed":
                seen.add(str(outcome["check"]).lower())
    # Inversion risk is a score on a finding, not a check, so it is read from
    # where it is actually written.
    for finding in result.all_findings():
        if collection and finding.collection != collection:
            continue
        sensitivity = (finding.evidence or {}).get("sensitivity") or {}
        if isinstance(sensitivity, dict) and sensitivity.get("inversion_risk", 0) >= 0.7:
            seen.add("inversion_risk")
    return seen


def check_scenario(scenario: Scenario, by_store: dict) -> tuple[str, str]:
    """Did this scenario's planted problem actually show up?

    Returns ``(state, detail)``. Never guesses: a scenario whose store was not
    assessed is 'not_applicable', not a silent pass.
    """
    if not scenario.expects:
        return "not_applicable", "No specific signal expected; an estate-wide view."
    result = by_store.get(scenario.store)
    if result is None:
        return "not_applicable", f"Store {scenario.store} was not assessed."
    labels = observed_labels(result, scenario.collection or None)
    signals = observed_signals(result, scenario.collection or None)
    found, missing = [], []
    for expected in scenario.expects:
        pool = labels if expected in LABEL_EXPECTATIONS else signals
        # Exact membership. Substring matching turned "provenance" into a hit
        # against an unrelated evidence key and confirmed a scenario that had
        # produced no finding at all.
        (found if expected in pool else missing).append(expected)
    # A known miss that is now caught is a change the walkthrough must learn
    # about, so it is reported as loudly as an expected signal that vanished.
    surprises = [name for name in scenario.known_misses
                 if name in labels or name in signals]
    if surprises:
        return "changed", (f"now observes {', '.join(surprises)}, which the scenario "
                           "documents as a known miss; update the walkthrough")
    if not missing:
        note = (f"; still misses {', '.join(scenario.known_misses)} as documented"
                if scenario.known_misses else "")
        return "confirmed", f"observed {', '.join(found)}{note}"
    if found:
        return "partial", f"observed {', '.join(found)}; did NOT observe {', '.join(missing)}"
    return "not_observed", f"did NOT observe {', '.join(missing)}"


def verify_scenarios(by_store: dict, scenarios: list[Scenario] = None,
                     title: str = "Scenario verification") -> list[dict]:
    """Report, per scenario, whether its planted problem actually appeared."""
    scenarios = SCENARIOS if scenarios is None else scenarios
    print(f"\n{title} — what the assessments actually observed:\n")
    rows = []
    for scenario in scenarios:
        state, detail = check_scenario(scenario, by_store)
        mark = {"confirmed": "ok  ", "partial": "~   ", "changed": "CHG ",
                "not_observed": "MISS", "not_applicable": "--  "}[state]
        print(f"  {mark} {scenario.id}  {scenario.framework:11} "
              f"{scenario.template:22} {detail}")
        rows.append({"id": scenario.id, "framework": scenario.framework,
                     "template": scenario.template, "criterion": scenario.criterion,
                     "store": scenario.store, "collection": scenario.collection,
                     "state": state, "detail": detail})
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["state"]] = counts.get(row["state"], 0) + 1
    print("\n  " + ", ".join(f"{n} {state}" for state, n in sorted(counts.items())))
    return rows


def tenant_values(collection) -> list:
    """The tenant value `build_store` wrote on each tagged document, in order."""
    values = []
    for i in range(len(collection.docs)):
        if i in collection.untagged:
            continue
        override = collection.extra.get(i, {}).get("tenant_id")
        values.append(override if override is not None
                      else collection.tenants[i % len(collection.tenants)])
    return values


def numeric_collisions(values) -> list[tuple]:
    """Pairs of distinct stored tenant values the store will match as one number.

    Chroma compares an integer filter with a float value numerically. Two values
    that differ as stored but are equal as float64 collide, unless they are the
    same integer at or below 2**53 written with two types (1042 and 1042.0),
    which may be one tenant. Computed here from the spec, independently of the
    engine, so the seeder does not take the engine's word for what should leak.
    """
    numbers = sorted({(str(v), v) for v in values
                      if isinstance(v, (int, float)) and not isinstance(v, bool)})
    pairs = []
    for i, (key_a, a) in enumerate(numbers):
        for key_b, b in numbers[i + 1:]:
            if float(a) != float(b):
                continue
            if a == b and abs(a) <= 2 ** 53:
                continue
            pairs.append((key_a, key_b))
    return pairs


def expected_isolation(collection) -> dict:
    """What the exhaustive isolation check must report for one seeded collection.

    Derived from the collection's spec, the same data `build_store` wrote, so
    the check is held to the arithmetic of the corpus rather than to numbers
    copied from an earlier run: every tagged chunk queried under each tenant
    that does not own it, every untagged chunk under every tenant. Tenants are
    counted as the check counts them, by their stored value as text, so a
    merchant id stored once as an integer and once as a float is two tenants.

    A collection whose tenant values collide as numbers must leak: the check
    must fail it with bleeds and the CRITICAL finding naming that cause.
    """
    values = tenant_values(collection)
    tenants = {str(v) for v in values}
    untagged = len(collection.untagged)
    tagged = len(values)
    if len(tenants) == 1 and not untagged:
        return {"method": "not_applicable", "complete": True, "outcome": "passed",
                "tenants": 1, "untagged": 0, "cross_tenant_queries": 0}
    expected = {"method": "exhaustive", "complete": True,
                # Two tenants sharing a collection is convention-only (HIGH)
                # even when the store enforces the filter for every chunk.
                "outcome": "failed" if len(tenants) > 1 else "passed",
                "tenants": len(tenants), "untagged": untagged,
                "cross_tenant_queries": tagged * (len(tenants) - 1)
                + untagged * len(tenants)}
    if numeric_collisions(values):
        # A leak is never a complete, verified result.
        expected.update(complete=False, outcome="failed",
                        leak="numeric_tenant_collision")
    return expected


def leak_finding(result, collection: str):
    """The CRITICAL not-enforced isolation finding on one collection, if any."""
    return next((f for f in result.all_findings()
                 if f.collection == collection and f.category == "isolation"
                 and str(f.severity.value).lower() == "critical"
                 and f.title.startswith("Tenant filter NOT enforced")), None)


def check_leak(result, collection: str, cov: dict, cause: str) -> tuple[list[str], str]:
    """Was the leak the spec plants actually found, with its cause named?

    Returns the problems and, when there are none, a one-line description of
    the finding for the seeder's output.
    """
    finding = leak_finding(result, collection)
    evidence = (finding.evidence or {}) if finding else {}
    problems = []
    if not cov.get("bleeds"):
        problems.append("no bleed observed: the expected cross-tenant leak was NOT detected")
    if finding is None:
        problems.append("no CRITICAL 'Tenant filter NOT enforced' finding")
    elif evidence.get("cause") != cause:
        problems.append(f"finding cause {evidence.get('cause')!r}, expected {cause!r}")
    if problems:
        return problems, ""
    pairs = "; ".join(f"{r['probe_tenant']} ({r['probe_type']}) matched "
                      f"{r['leaked_tenant']} ({r['leaked_type']})"
                      for r in evidence.get("colliding_values", [])[:3])
    return [], f"CRITICAL {finding.title} [{cause}: {pairs}]"


def verify_isolation(by_store: dict, capped=None) -> list[dict]:
    """Check each collection's tenant-isolation outcome against its spec.

    Every full run must verify isolation exhaustively (or find it not
    applicable) with no bleed, except a collection whose tenant values collide
    as numbers: that one must leak, and be reported CRITICAL with its cause.
    The capped run must NOT read complete, because it did not read every chunk.
    """
    print("\nIsolation verification — tenant isolation, per collection:\n")
    specs = {spec.store_id: spec for spec in [*STORES, *PG_STORES]}
    rows = []
    runs = [(store_id, result, False) for store_id, result in by_store.items()]
    if capped is not None:
        runs.append(("customer-360", capped, True))
    for store_id, result, is_capped in runs:
        outcomes = {o.get("collection"): o for o in result.all_check_outcomes()
                    if o.get("check") == "tenant_isolation"}
        for collection in specs[store_id].collections:
            outcome = outcomes.get(collection.name) or {}
            cov = outcome.get("coverage") or {}
            problems = []
            leak, leak_line = None, ""
            if is_capped:
                expected = {"complete": False}
                if cov.get("complete") is not False:
                    problems.append("a capped run read complete")
            else:
                expected = expected_isolation(collection)
                leak = expected.pop("leak", None)
                observed = {"method": cov.get("method"), "complete": cov.get("complete"),
                            "outcome": outcome.get("outcome"),
                            "tenants": cov.get("tenant_count"),
                            "untagged": cov.get("untagged"),
                            "cross_tenant_queries": cov.get("cross_tenant_queries", 0)}
                problems += [f"{key} {observed[key]!r}, expected {value!r}"
                             for key, value in expected.items() if observed[key] != value]
                if leak:
                    leak_problems, leak_line = check_leak(result, collection.name, cov, leak)
                    problems += leak_problems
                elif cov.get("bleeds"):
                    problems.append(f"{cov['bleeds']} bleed(s) observed")
            label = f"{store_id}{' (capped)' if is_capped else ''}/{collection.name}"
            mark = "MISS" if problems else "ok  "
            expected_leak = bool(leak)
            summary = (f"{cov.get('method', '-')}, {cov.get('chunks_examined', 0)} chunks, "
                       f"{cov.get('tenant_count', 0)} tenant(s), "
                       f"{cov.get('cross_tenant_queries', 0)} cross-tenant queries, "
                       f"{cov.get('bleeds', 0)} bleeds, {cov.get('untagged', 0)} untagged; "
                       f"{outcome.get('outcome', 'missing')}, "
                       f"{'complete' if cov.get('complete') else 'partial'}")
            print(f"  {mark} {label:42} {summary}")
            if problems:
                print(f"       {'; '.join(problems)}")
            elif expected_leak:
                print(f"       expected leak detected: {leak_line}")
            rows.append({"store": store_id, "collection": collection.name,
                         "capped": is_capped, "expected_leak": expected_leak,
                         "outcome": outcome.get("outcome"),
                         "coverage": cov.get("status"), "method": cov.get("method"),
                         "cross_tenant_queries": cov.get("cross_tenant_queries", 0),
                         "bleeds": cov.get("bleeds", 0), "untagged": cov.get("untagged", 0),
                         "problems": problems})
    bad = sum(1 for r in rows if r["problems"])
    print(f"\n  {len(rows) - bad} as specified, {bad} not as specified")
    return rows


def seed_workflow(history, findings) -> None:
    """Cases, evidence, reviews, exceptions and job history across the estate."""
    from vecshield_platform.cases import CaseState, transition
    from vecshield_platform.evidence import (
        EvidenceArtifact, EvidenceReview, RiskException, transition_artifact,
        transition_review,
    )

    now = dt.datetime.now(dt.timezone.utc)
    # Cases are attached to *named* findings, matched by collection and title
    # prefix, so the walkthrough document can say which case is in which state
    # and be right. An earlier version assigned states by severity order,
    # which put "false positive — published test number" on whichever finding
    # happened to sort sixth.
    CASES = [
        ("patient_correspondence", "PHI detected",
         ["triaged", "assigned", "in_progress"], {"owner": "priya@example.test"}),
        ("referral_letters", "PHI detected",
         ["triaged", "assigned", "in_progress", "awaiting_verification"],
         {"owner": "priya@example.test"}),
        ("support_tickets", "PII detected",
         ["triaged", "assigned", "in_progress"], {"owner": "dpo@example.test"}),
        ("marketing_profiles", "PII detected",
         ["risk_accepted"],
         {"reason": "Behind a separate access path; re-embedding with a "
                    "lower-inversion model is scheduled for next quarter, and "
                    "the exception exc-profiles covers the interval."}),
        ("partner_shared", "Tenant isolation",
         ["triaged", "assigned"], {"owner": "alex@example.test"}),
        ("chargeback_notes", "PCI detected",
         ["triaged", "assigned"], {"owner": "sam@example.test"}),
        ("gateway_runbooks", "SECRET detected",
         ["triaged"], {}),
        ("deploy_runbooks", "SECRET detected",
         ["triaged", "assigned"], {"owner": "alex@example.test"}),
        ("incident_timeline", "Prompt-injection",
         ["triaged", "assigned", "in_progress"], {"owner": "sam@example.test"}),
        ("vendor_docs", "Incomplete provenance",
         ["triaged"], {}),
        ("community_contrib", "Prompt-injection",
         ["triaged", "assigned"], {"owner": "sam@example.test"}),
    ]
    by_key = {}
    for finding in findings:
        by_key.setdefault((finding.collection, finding.title.split(" in ")[0]), finding)
    for collection, prefix, states, extra in CASES:
        finding = next((f for (col, title), f in by_key.items()
                        if col == collection and title.startswith(prefix)), None)
        if finding is None:
            print(f"  ! no finding to attach a case to: {collection} / {prefix}")
            continue
        case = CaseState(**history.get_case(finding.id))
        for state_name in states:
            case, event = transition(
                case, to_state=state_name, actor="demo@example.test",
                owner=extra.get("owner"), reason=extra.get("reason", ""))
            history.save_case(case, event)

    artifacts = [
        ("ev-access-review", "Q3 access review record", "clinical-rag", 9,
         "2026-07-01", "2026-09-30"),
        ("ev-auth-policy", "Authorized access policy v3", "clinical-rag", 40,
         "2026-01-01", "2026-06-30"),
        ("ev-auth-policy-old", "Authorized access policy v2", "clinical-rag", 400,
         None, None),
        ("ev-baa", "Business associate agreement", "clinical-rag", 120,
         "2026-01-01", "2026-12-31"),
        ("ev-ropa", "Record of processing activities", "customer-360", 30,
         "2026-01-01", "2026-12-31"),
        ("ev-dpia", "DPIA for the retrieval assistant", "ai-corpus", 60,
         "2026-01-01", "2026-12-31"),
        ("ev-pci-scope", "PCI scope definition", "payments-ops", 75,
         "2026-01-01", "2026-12-31"),
        ("ev-vendor-review", "Annual vendor review pack", "platform-runbooks", 20,
         "2026-01-01", "2026-12-31"),
    ]
    for index, (aid, title, scope, age, start, end) in enumerate(artifacts):
        current = EvidenceArtifact(
            id=aid, title=title, media_type="application/pdf",
            content_hash=f"{index:04x}" + "abcdef" * 10,
            collector="demo@example.test",
            collected_at=(now - dt.timedelta(days=age)).isoformat(),
            scope=scope, period_start=start, period_end=end)
        for state_name in ("integrity_checked", "available"):
            current = transition_artifact(current, to_state=state_name,
                                          actor="demo@example.test")
        history.save_artifact(current)
    history.save_artifact(transition_artifact(
        EvidenceArtifact(**history.get_artifact("ev-auth-policy-old")),
        to_state="superseded", actor="demo@example.test",
        reason="superseded by ev-auth-policy"))

    reviews = [
        ("rev-access", "ev-access-review", "HIPAA-SEC-ACCESS-01",
         "access_review_record", "clinical-rag", "2026-Q3", "accepted",
         "Covers the period and the systems in scope."),
        ("rev-policy", "ev-auth-policy", "HIPAA-SEC-ACCESS-01",
         "authorized_access_policy", "clinical-rag", "2026-Q3", "rejected",
         "Covers H1 only; the period under review is Q3."),
        # Requirements are the pack's own artifact keys, so each decision counts
        # toward the criterion it names. The BAA is judged twice on purpose:
        # the same file is sufficient for one obligation and not for another.
        ("rev-baa", "ev-baa", "HIPAA-164-308-B1-BAA-01",
         "business_associate_agreements", "clinical-rag", "2026", "accepted",
         "Executed, and names the retrieval corpus explicitly."),
        ("rev-baa-risk", "ev-baa", "HIPAA-SEC-EPHI-INVENTORY-01", "risk_analysis",
         "clinical-rag", "2026", "rejected",
         "A BAA is a vendor contract, not a risk analysis; it rates no risks to "
         "the corpus."),
        ("rev-ropa", "ev-ropa", "GDPR-ERASURE-01", "erasure_procedure",
         "customer-360", "2026", "rejected",
         "A record of processing is not an erasure procedure, and it does not "
         "list the vector store as a processing location."),
        ("rev-dpia", "ev-dpia", "AIACT-ART10-DATA-GOV-01", "data_governance_record",
         "ai-corpus", "2026", "accepted", "Covers the assistant and names the corpus."),
        ("rev-pci-scope", "ev-pci-scope", "PCI-DSS-3-STORAGE-01",
         "cde_scope_statement", "payments-ops", "2026", "rejected",
         "Scope predates the vector store and does not mention it."),
    ]
    for rid, aid, criterion, requirement, scope, period, decision, reason in reviews:
        current = transition_review(
            EvidenceReview(id=rid, artifact_id=aid, criterion_id=criterion,
                           requirement=requirement, scope=scope, period=period),
            to_state="submitted", reviewer="demo@example.test")
        current = transition_review(current, to_state=decision,
                                    reviewer="dpo@example.test", reason=reason)
        history.save_review(current)

    exceptions = [
        ("exc-profiles", "GDPR-SECURITY-32-01", "customer-360",
         "Marketing profiles sit behind a separate access path; re-embedding with "
         "a lower-inversion model is scheduled for next quarter.",
         "alex@example.test", 45, "ciso@example.test", 2),
        ("exc-pci-token", "PCI-DSS-3-STORAGE-01", "payments-ops",
         "Tokenisation rollout is in flight; requesting cover until it lands.",
         "priya@example.test", 20, None, None),
        ("exc-vendor", "SOC2-CC7.2-ANOMALY-01", "platform-runbooks",
         "Provenance backfill for two vendor documents is blocked on the supplier "
         "confirming the export date.",
         "sam@example.test", 60, "ciso@example.test", 5),
        ("exc-expired", "HIPAA-SEC-ACCESS-01", "clinical-rag",
         "Interim cover while the access review was rescheduled. It has already "
         "expired, and the gap it covered is open again.",
         "alex@example.test", -12, "ciso@example.test", 100),
    ]
    for eid, criterion, scope, rationale, requester, days, approver, ago in exceptions:
        history.save_exception(RiskException(
            id=eid, criterion_id=criterion, scope=scope, rationale=rationale,
            requested_by=requester,
            expires_at=(now + dt.timedelta(days=days)).isoformat(),
            approved_by=approver,
            approved_at=((now - dt.timedelta(days=ago)).isoformat() if ago else None),
            created_at=(now - dt.timedelta(days=abs(days) + 5)).isoformat()))

    jobs = [
        ("job-audit-clinical", "audit", "succeeded", "clinical-rag", 12, 11, None),
        ("job-audit-customer", "audit", "succeeded", "customer-360", 30, 28, None),
        ("job-scan-payments", "scan_classification", "succeeded",
         "payments-ops/chargeback_notes", 90, 89, None),
        ("job-integrity-ai", "scan_integrity", "interrupted",
         "ai-corpus/community_contrib", 180, 120,
         "worker restarted before this job finished; the work was not resumed and "
         "must be run again"),
        ("job-erasure-dry", "erasure_plan", "succeeded",
         "customer-360/support_tickets", 240, 239, None),
    ]
    for jid, kind, status, resource, created, finished, error in jobs:
        record = {
            "id": jid, "kind": kind, "status": status, "actor": "demo@example.test",
            "resource": resource,
            "created_at": (now - dt.timedelta(minutes=created)).isoformat(),
            "started_at": (now - dt.timedelta(minutes=created)).isoformat(),
            "finished_at": (now - dt.timedelta(minutes=finished)).isoformat(),
        }
        record["error" if error else "result"] = error or {"summary": {"ok": True}}
        history.save_async_job(record)


def seed_alerts(paths) -> None:
    from vecshield.models import Severity
    from vecshield_platform.runtime import Alert, AlertStore

    now = dt.datetime.now(dt.timezone.utc)
    alerts = AlertStore(paths.alerts_db)
    rows = [
        ("bulk_volume", "svc-support-bot", Severity.HIGH, "support_tickets",
         "150 queries in 60s against support_tickets (threshold 100)"),
        ("collection_sweep", "analyst@example.test", Severity.MEDIUM,
         "partner_shared", "Queried 3 of 3 collections within the window"),
        ("enumeration", "svc-support-bot", Severity.LOW, "support_tickets",
         "Sequential id access pattern observed"),
        ("bulk_volume", "svc-clinical-rag", Severity.HIGH, "referral_letters",
         "310 queries in 60s against referral_letters (threshold 100)"),
        ("collection_sweep", "contractor@example.test", Severity.MEDIUM,
         "gateway_runbooks", "Queried every collection in payments-ops in 90s"),
    ]
    for i, (rule, principal, severity, collection, message) in enumerate(rows):
        alerts.save(Alert(
            id=f"alert-demo-{i}", rule=rule, severity=severity, principal=principal,
            timestamp=(now - dt.timedelta(minutes=17 * (i + 1))).timestamp(),
            message=message, dedup_key=f"{rule}:{principal}:{collection}",
            collection=collection,
            evidence={"observed": 120 + i * 40, "threshold": 100}))


#: A registered store that is deliberately never assessed, so the Overview's
#: "stores never assessed" item and the Crypto estate's "never assessed" row
#: have something real to point at. It is not in `scenarios.py`: no scenario
#: rests on it, and the scenario check does not read it.
UNASSESSED_STORE = {
    "store_id": "legal-archive",
    "description": "Contract and policy archive, connected but not yet assessed",
    "collection": "contract_clauses",
    "docs": [
        "Standard limitation-of-liability clause for supplier agreements.",
        "Template confidentiality clause, mutual, three-year term.",
        "Governing-law clause options by region, with counsel notes.",
    ],
}


def seed_needs_you(history, config, stores_root: Path,
                   pg: "PgTarget | None" = None) -> list[str]:
    """Give the Overview's "Needs you" inbox one real item of each kind.

    Every item is made the way the console would make it, so each "Open" leads
    to a record that behaves: plans are staged from the stores' own findings
    with `actions.stage`, reviews are submitted and left for a decision, and
    exceptions are requested or approved with real expiry dates. Returns the
    inbox kinds it populated, for the check in `main`.
    """
    from vecshield_platform.actions import ActionError, stage, suggest_all
    from vecshield_platform.evidence import (
        EvidenceArtifact, EvidenceReview, RiskException, transition_artifact,
        transition_review,
    )

    now = dt.datetime.now(dt.timezone.utc)
    kinds: list[str] = []

    # Plans awaiting approval: staged by someone other than the demo user, so
    # the inbox can say "you may approve" under separation of duties.
    plans = [
        ("payments-ops", "tag_exclude", "chargeback_notes", "sam@example.test",
         "Keep the chargeback notes holding full PANs out of retrieval until "
         "tokenisation lands."),
        ("platform-runbooks", "redact_text", "deploy_runbooks", "alex@example.test",
         "Redact the credential pasted into a deploy runbook; rotation is tracked "
         "separately."),
    ]
    by_id = {spec.store_id: spec for spec in [*STORES, *PG_STORES]}
    staged = 0
    for store_id, action, collection, staged_by, note in plans:
        records = history.query_findings(
            stores=history.observed_store_names(store_id) or [store_id], limit=500)
        records = records.get("findings", []) if isinstance(records, dict) else records
        findings = []
        for record in records:
            finding = {**dict(record), "store": store_id}
            if isinstance(finding.get("evidence"), str):
                try:
                    finding["evidence"] = json.loads(finding["evidence"])
                except ValueError:
                    finding["evidence"] = {}
            findings.append(finding)
        suggestions, _ = suggest_all(findings)
        chosen = next((s for s in suggestions
                       if s.action == action and s.collection == collection), None)
        if chosen is None:
            print(f"  ! no {action} suggestion on {store_id}/{collection}; plan not staged")
            continue
        connector = open_demo_store(by_id[store_id], stores_root, pg)
        try:
            plan = stage([chosen], connector=connector, store=store_id,
                         staged_by=staged_by, note=note)
        except ActionError as exc:
            print(f"  ! could not stage {action} on {store_id}: {exc}")
            continue
        finally:
            connector.close()
        history.save_plan(plan)
        staged += 1
    if staged:
        kinds.append("plans_awaiting_approval")

    # The capability gap, shown rather than claimed. pgvector advertises only
    # `delete` among the write capabilities, and the PHI findings in
    # pgvector-clinical map to actions that all need a metadata or text write.
    # So there is no remediation plan to stage here at all — not because the
    # finding is benign, but because this backend cannot carry out the fix.
    # Attempting it and reporting the refusal is the honest version of that.
    if pg:
        spec = by_id["pgvector-clinical"]
        connector = open_demo_store(spec, stores_root, pg)
        try:
            missing = sorted({"metadata_write", "text_write"} - connector.capabilities())
            print(f"  i pgvector-clinical cannot be remediated in place: the "
                  f"connector does not offer {', '.join(missing)}, so its PHI "
                  f"findings have no stageable plan. Unavailable is not clean.")
        finally:
            connector.close()

    # Evidence reviews awaiting a decision: submitted, not yet decided. The
    # first is the statement that would clear the crypto gate's PHI rule for
    # clinical-rag once a reviewer accepts it.
    pending = [
        ("ev-disk-encryption", "Host disk encryption statement (FileVault / LUKS)",
         "clinical-rag", "rev-disk-encryption", "HIPAA-164-312-A2IV-ENCRYPTION-01",
         "encryption_at_rest_statement", "2026-Q3"),
        ("ev-transmission", "Transmission security statement for the payments API",
         "payments-ops", "rev-transmission", "PCI-DSS-4-2-1-TRANSMISSION-01",
         "pan_transmission_statement", "2026"),
    ]
    for index, (aid, title, scope, rid, criterion, requirement, period) in enumerate(pending):
        artifact = EvidenceArtifact(
            id=aid, title=title, media_type="application/pdf",
            content_hash=f"{0xe0 + index:04x}" + "fedcba" * 10,
            collector="priya@example.test",
            collected_at=(now - dt.timedelta(days=2 + index)).isoformat(),
            scope=scope, period_start="2026-07-01", period_end="2026-12-31")
        for state_name in ("integrity_checked", "available"):
            artifact = transition_artifact(artifact, to_state=state_name,
                                           actor="priya@example.test")
        history.save_artifact(artifact)
        history.save_review(transition_review(
            EvidenceReview(id=rid, artifact_id=aid, criterion_id=criterion,
                           requirement=requirement, scope=scope, period=period),
            to_state="submitted", reviewer="priya@example.test"))
    kinds.append("evidence_reviews_awaiting_decision")

    # Exceptions: one more awaiting approval beside exc-pci-token, and one
    # approved exception lapsing inside the fourteen-day window.
    for eid, criterion, scope, rationale, requester, days, approver, ago in (
        ("exc-support-backfill", "GDPR-ERASURE-01", "customer-360",
         "Erasure of pre-2024 support tickets waits on the legal hold review "
         "finishing; requesting cover until then.",
         "dpo@example.test", 30, None, None),
        ("exc-runbook-rotation", "SOC2-CC6.1-ENCRYPTION-01", "platform-runbooks",
         "Credential rotation for the deploy runbooks is scheduled; cover lapses "
         "next week unless renewed.",
         "alex@example.test", 6, "ciso@example.test", 24),
    ):
        history.save_exception(RiskException(
            id=eid, criterion_id=criterion, scope=scope, rationale=rationale,
            requested_by=requester,
            expires_at=(now + dt.timedelta(days=days)).isoformat(),
            approved_by=approver,
            approved_at=((now - dt.timedelta(days=ago)).isoformat() if ago else None),
            created_at=(now - dt.timedelta(days=(ago or 1) + 3)).isoformat()))
    kinds += ["exceptions_awaiting_approval", "exceptions_expiring"]

    # A store registered but never assessed. Built like the others so it can
    # be assessed from the console, which is the point of the inbox item.
    spec = UNASSESSED_STORE
    archive = StoreSpec(
        store_id=spec["store_id"], description=spec["description"],
        collections=[CollectionSpec(
            spec["collection"], spec["description"], ["legal"], spec["docs"],
            # Every document records the same source the inline build wrote.
            rare_sources={i: "contracts-dms" for i in range(len(spec["docs"]))})],
    )
    path = build_chroma_store(stores_root, archive, random.Random(4242))
    config.add_store(store_id=spec["store_id"], kind="chroma", conn={"path": path},
                     tenant_field="tenant_id", description=spec["description"])
    # Policies attach at registration, before any audit, as they would for a
    # store someone has connected and not yet assessed.
    config.add_policy_from_template("sec-secrets", scope_store=spec["store_id"])
    kinds.append("stores_never_assessed")
    return kinds


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", default="demo-state",
                        help="Directory for the demo config, history, and stores")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero if any scenario did not fire as written.")
    parser.add_argument(
        "--pgvector-dsn", default=os.environ.get("VECSHIELD_PG_DSN"),
        help="Postgres DSN (with the pgvector extension available) to build the "
             "two pgvector demo stores in. Defaults to $VECSHIELD_PG_DSN. "
             "Without it the demo is Chroma-only, exactly as before.")
    args = parser.parse_args()

    state = Path(args.state).resolve()
    state.mkdir(parents=True, exist_ok=True)
    stores_root = state / "stores"
    config_path = state / "vecshield.json"
    for stale in (config_path, config_path.with_suffix(".json.lock")):
        stale.unlink(missing_ok=True)
    for stale_dir in (state / "state", state / "chroma"):
        if stale_dir.exists():
            shutil.rmtree(stale_dir)

    pg = None
    if args.pgvector_dsn:
        pg = PgTarget.from_dsn(args.pgvector_dsn)
        # The audit below connects through the same indirect reference the
        # config carries, so the password is set here rather than inlined.
        os.environ[PG_PASSWORD_ENV] = pg.password

    # pgvector stores come second so the Chroma stores draw the same numbers
    # from the shared generator whether or not a database was given.
    active = [*STORES, *(PG_STORES if pg else [])]

    rng = random.Random(1729)
    print(f"Building {len(STORES)} synthetic Chroma stores under {stores_root} ...")
    for spec in STORES:
        build_store(stores_root, spec, rng)
        docs = sum(len(c.docs) for c in spec.collections)
        print(f"  {spec.store_id:20} {len(spec.collections)} collection(s), "
              f"{docs} documents")
    if pg:
        # Every schema is vetted before the first is dropped.
        check_pg_schemas(pg, PG_STORES)
        print(f"\nBuilding {len(PG_STORES)} pgvector stores in "
              f"{pg.host}:{pg.port}/{pg.dbname} ...")
        for spec in PG_STORES:
            where = build_store(stores_root, spec, rng, pg)
            docs = sum(len(c.docs) for c in spec.collections)
            print(f"  {spec.store_id:20} {len(spec.collections)} collection(s), "
                  f"{docs} documents  ({where})")
    else:
        print("\nNo --pgvector-dsn given: skipping the pgvector stores. "
              "The demo is Chroma-only.")

    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.api.state import resolve_state_paths
    from vecshield_platform.connectors import build_connector
    from vecshield_platform.history import ScanHistory
    from vecshield_platform.orchestrator import run_full_audit

    paths = resolve_state_paths(config_path, state / "state")
    config = ConfigStore(path=str(config_path))

    for spec in active:
        conn = (pg.stored_conn(spec) if spec.kind == "pgvector"
                else {"path": str(stores_root / spec.store_id)})
        config.add_store(store_id=spec.store_id, kind=spec.kind, conn=conn,
                         tenant_field=spec.tenant_field,
                         description=spec.description)
        for template in STORE_POLICIES.get(spec.store_id, []):
            try:
                config.add_policy_from_template(template, scope_store=spec.store_id)
            except Exception as exc:  # noqa: BLE001
                print(f"  ! policy {template} on {spec.store_id}: {exc}")

    history = ScanHistory(paths.history_db)
    print("\nRunning assessments ...")
    by_store: dict[str, object] = {}
    all_findings = []
    for spec in active:
        connector = open_demo_store(spec, stores_root, pg)
        try:
            # Posture is included so the Crypto screen's transport and storage
            # layers are observed rather than "excluded from this run".
            result = run_full_audit(
                connector, tenant_field=spec.tenant_field, include_integrity=True,
                include_posture=True,
                policies=config.effective_policies(spec.store_id))
            result.scope["store_id"] = spec.store_id
        finally:
            connector.close()
        history.save_audit(result, store_id=spec.store_id)
        by_store[spec.store_id] = result
        findings = list(result.all_findings())
        all_findings.extend(findings)
        print(f"  {spec.store_id:20} {len(findings):3} findings, "
              f"coverage {result.coverage['status']}")

    # One capped re-run, so the archive shows partial coverage beside complete
    # coverage rather than implying every run sees everything.
    connector = build_connector("chroma", path=str(stores_root / "customer-360"))
    try:
        capped = run_full_audit(
            connector, tenant_field="tenant_id", include_integrity=True,
            include_posture=True, max_chunks_per_collection=4,
            policies=config.effective_policies("customer-360"))
        capped.scope["store_id"] = "customer-360"
    finally:
        connector.close()
    history.save_audit(capped, store_id="customer-360")
    print(f"  {'customer-360 (capped)':20} coverage {capped.coverage['status']}")

    seed_workflow(history, all_findings)
    inbox = seed_needs_you(history, config, stores_root, pg)
    print(f"\nNeeds-you items seeded: {', '.join(inbox)}")
    history.close()
    seed_alerts(paths)

    report = verify_scenarios(by_store)
    # Verified only when the stores they describe were actually built. A
    # scenario that never ran is reported as skipped, never folded in with the
    # ones that ran and found nothing: "not run" and "not detected" are
    # different claims, and only one of them is a defect.
    pg_report = []
    if pg:
        pg_report = verify_scenarios(by_store, PG_SCENARIOS,
                                     title="pgvector scenario verification")
    else:
        pg_report = [{"id": sc.id, "framework": sc.framework,
                      "template": sc.template, "criterion": sc.criterion,
                      "store": sc.store, "collection": sc.collection,
                      "state": "skipped",
                      "detail": "no --pgvector-dsn given; the store was not built"}
                     for sc in PG_SCENARIOS]
    isolation = verify_isolation(by_store, capped)
    (state / "demo.json").write_text(json.dumps({
        "config": str(config_path),
        "state_dir": str(state / "state"),
        "stores": [s.store_id for s in active],
        # Registered but deliberately never assessed; see seed_needs_you.
        "unassessed_stores": [UNASSESSED_STORE["store_id"]],
        "collections": sum(len(s.collections) for s in active),
        "documents": sum(len(c.docs) for s in active for c in s.collections),
        "findings": len(all_findings),
        "scenarios": report,
        "pgvector": {
            "enabled": bool(pg),
            "endpoint": (f"{pg.host}:{pg.port}/{pg.dbname}" if pg else None),
            "stores": [s.store_id for s in PG_STORES] if pg else [],
            "scenarios": pg_report,
        },
        "isolation": isolation,
    }, indent=2))

    print("\nSeeded. Start the console with:\n")
    print(f"  vecshield-platform serve --config {config_path} "
          f"--state-dir {state / 'state'} --port 8088\n")
    unconfirmed = [r for r in [*report, *pg_report]
                   if r["state"] in ("not_observed", "partial", "changed")]
    if unconfirmed and args.strict:
        print(f"{len(unconfirmed)} scenario(s) did not fire as written.")
        return 1
    unverified = [r for r in isolation if r["problems"]]
    # A demo that claims a cross-tenant leak it does not show is the worst
    # kind of wrong, so a planted leak that goes undetected fails the seeder
    # whether or not --strict was given.
    missed_leaks = [r for r in unverified if r["expected_leak"]]
    if missed_leaks:
        for row in missed_leaks:
            print(f"ERROR: the planted cross-tenant leak in {row['store']}/"
                  f"{row['collection']} was not reported as specified: "
                  f"{'; '.join(row['problems'])}")
        return 1
    if unverified and args.strict:
        print(f"{len(unverified)} isolation outcome(s) not as specified.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
