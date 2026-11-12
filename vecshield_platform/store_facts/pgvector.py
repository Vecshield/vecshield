"""Store facts for :class:`~vecshield_platform.connectors.pgvector.PgVectorConnector`.

Connector attributes read: ``_conn`` (psycopg connection), ``_schema``,
``_table_filter`` (optional) and ``_endpoint`` (redacted DSN; used for the
host only when ``_conn.info.host`` is unavailable).

Every query here is a read of a catalog or a ``SHOW``; a failed statement is
rolled back so it cannot poison the connector's next scan query.

* server_info — ``SHOW server_version``, ``SELECT version()`` (as
  ``features.version_string``), every row of ``pg_extension`` (as
  ``features.extensions``, plus ``pgvector``/``pgvectorscale``/``pgai`` for
  the vector extensions), ``SHOW max_parallel_maintenance_workers`` and, when
  the role may read it, ``SHOW shared_preload_libraries``. Aurora is
  identified by the ``aurora_version()`` function, which exists only on Aurora
  PostgreSQL (https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora_version.html);
  RDS / Azure / Cloud SQL / AlloyDB by their ``rds.`` / ``azure.`` /
  ``cloudsql.`` / ``alloydb.`` settings names. Nothing else is inferred.
  For server hardening it also records ``features.settings`` (the allowlisted
  ``pg_settings`` rows in ``posture.pg_hardening.SETTINGS`` that this role can
  see, as ``{"name", "setting"}`` rows) and, when pg_stat_statements is installed,
  ``features.pg_read_all_stats_members`` (non-superuser login roles, other
  than the connecting one, that can read every role's statement text).
* distance metrics — the operator class of each index on a vector column
  (pg_index → pg_opclass): ``*_cosine_ops`` / ``*_ip_ops`` / ``*_l2_ops`` /
  ``*_l1_ops`` (pgvector README). Vector columns are ``vector``,
  ``halfvec``, ``sparsevec``, and ``bit`` under a pgvector bit index (the
  connector's ``VECTOR_TABLE_PREDICATE``). A table without such an index has no
  metric (queries pick one per statement) → None.
* model_integrations — pgai vectorizers: ``ai.vectorizer.config->'embedding'``
  (``implementation``, ``model``, ``base_url``); the ``api_key_name`` is an
  environment-variable name and is not copied. Vectorizers are executed by the
  pgai vectorizer worker, outside the database.
* store_location — hostnames that encode a region: RDS/Aurora
  ``<name>.<id>.<region>.rds.amazonaws.com``
  (https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Endpoints.Cluster.html),
  Neon ``<endpoint>.<region>.aws.neon.tech`` / ``.azure.neon.tech``
  (https://neon.com/faqs/check-neon-project-region), Supabase shared pooler
  ``aws-<n>-<region>.pooler.supabase.com``
  (https://supabase.com/docs/guides/troubleshooting/tenant-or-user-not-found).
  Azure Database for PostgreSQL (``<server>.postgres.database.azure.com``)
  and Supabase direct hosts (``db.<ref>.supabase.co``) carry no region.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from vecshield_platform.connectors.pgvector import VECTOR_TABLE_PREDICATE
from vecshield_platform.posture.pg_hardening import SETTINGS as HARDENING_SETTINGS
from vecshield_platform.store_facts import _selfhosted_util as u

CAPABILITIES = frozenset({"server_info", "location_introspection", "egress_introspection"})

_RDS_HOST = re.compile(r"^[a-z0-9-]+\.[a-z0-9-]+\.(?P<region>[a-z]{2}(?:-[a-z]+)+-\d)"
                       r"\.rds\.amazonaws\.com(?:\.cn)?$")
_NEON_HOST = re.compile(r"^ep-[a-z0-9-]+\.(?P<region>[a-z0-9-]+)\.(?P<cloud>aws|azure)"
                        r"\.neon\.tech$")
_SUPABASE_POOLER = re.compile(r"^(?P<cloud>aws|gcp|azure)-\d+-(?P<region>[a-z0-9-]+)"
                              r"\.pooler\.supabase\.com$")

_OPCLASS_METRIC = (("_cosine_ops", "cosine"), ("_ip_ops", "ip"), ("_l2_ops", "l2"),
                   ("_l1_ops", "l1"))


# ------------------------------------------------------------------- SQL #

def _query(conn: Any, sql: str, params: tuple = ()) -> tuple[list, Optional[BaseException]]:
    db: Any = getattr(conn, "_conn", None)
    try:
        with db.cursor() as cur:
            if params:
                cur.execute(sql, params)
            else:
                cur.execute(sql)
            return list(cur.fetchall()), None
    except Exception as exc:  # noqa: BLE001 - introspection must never break a scan
        rollback = getattr(db, "rollback", None)
        if callable(rollback):
            try:
                rollback()
            except Exception:  # pragma: no cover - best effort
                pass
        return [], exc


#: Installed extensions reported per database; bounded so a catalog with an
#: unusual number of them cannot bloat an assessment.
_MAX_EXTENSIONS = 200


def _extensions(conn: Any) -> tuple[dict[str, str], Optional[BaseException]]:
    """Every installed extension → its version (``pg_extension`` is world-readable)."""
    rows, err = _query(conn, "SELECT extname, extversion FROM pg_extension "
                             f"ORDER BY extname LIMIT {_MAX_EXTENSIONS}")
    return {str(r[0]): str(r[1]) for r in rows if r and r[0]}, err


def _setting(conn: Any, name: str) -> tuple[Optional[str], Optional[BaseException]]:
    """One ``SHOW`` value. ``name`` is always one of this module's literals."""
    rows, err = _query(conn, f"SHOW {name}")
    if err is not None or not rows or rows[0][0] is None:
        return None, err
    return str(rows[0][0]), None


def _managed_edition(conn: Any) -> Optional[str]:
    rows, _ = _query(conn, "SELECT 1 FROM pg_proc WHERE proname = 'aurora_version' LIMIT 1")
    if rows:
        return "aurora"
    rows, _ = _query(conn, "SELECT name FROM pg_settings WHERE name LIKE 'rds.%' OR name "
                           "LIKE 'azure.%' OR name LIKE 'cloudsql.%' OR name LIKE "
                           "'alloydb.%' LIMIT 50")
    names = [str(r[0]).lower() for r in rows]
    for prefix, edition in (("rds.", "aws_rds"), ("azure.", "azure"),
                            ("alloydb.", "alloydb"), ("cloudsql.", "cloud_sql")):
        if any(n.startswith(prefix) for n in names):
            return edition
    return None


def server_info(conn: Any) -> dict[str, Any]:
    source = "SHOW server_version; pg_extension"
    rows, err = _query(conn, "SHOW server_version")
    if err is not None:
        return u.server(product="postgresql", source=source,
                        reason=u.failed_reason(err, "server_version", "a login role"))
    version = str(rows[0][0]).split(" ")[0] if rows and rows[0][0] else None
    extensions, ext_err = _extensions(conn)
    features: dict[str, Any] = {}
    names = {"vector": "pgvector", "vectorscale": "pgvectorscale", "ai": "pgai",
             "pgml": "postgresml"}
    for ext, ver in extensions.items():
        if ext in names:
            features[names[ext]] = ver
    if ext_err is None:
        # Every installed extension, so an advisory against a contrib module
        # can be judged against what is actually installed.
        features["extensions"] = dict(sorted(extensions.items()))
    # The installed package's version (its control file). Backends load the
    # package's C library, so this is the code that runs; pg_extension's
    # extversion lags it until ALTER EXTENSION vector UPDATE.
    package, _ = _query(conn, "SELECT default_version FROM pg_available_extensions "
                              "WHERE name = 'vector'")
    if package and package[0][0]:
        features["pgvector_package"] = str(package[0][0])
    reasons = []
    # Configuration that decides whether specific advisories apply
    # (posture/data/advisory_conditions.json). Each is optional: a refused
    # read (shared_preload_libraries needs pg_read_all_settings) is recorded
    # as not reported, never as a failure of server_info.
    full, _ = _query(conn, "SELECT version()")
    if full and full[0][0]:
        features["version_string"] = str(full[0][0])
    workers, _ = _setting(conn, "max_parallel_maintenance_workers")
    if workers is not None:
        features["max_parallel_maintenance_workers"] = (
            int(workers) if workers.strip().isdigit() else workers)
    preload, preload_err = _setting(conn, "shared_preload_libraries")
    if preload is not None:
        features["shared_preload_libraries"] = sorted(
            p.strip().strip("\"'") for p in preload.split(",") if p.strip())
    elif preload_err is not None and u.is_denied(preload_err):
        reasons.append("shared_preload_libraries is readable only with pg_read_all_settings.")
    # Hardening inputs (posture/pg_hardening.py). pg_settings hides
    # superuser-only settings from other roles, so an absent name is
    # "not readable", never "off". Kept as pg_settings rows, not a mapping:
    # scrub() drops mapping keys that look like credentials, and
    # password_encryption names a hash algorithm, not a secret. The SQL
    # allowlist is what keeps anything else out.
    settings, _ = _query(conn, "SELECT name, setting FROM pg_settings WHERE name = ANY(%s)",
                         (list(HARDENING_SETTINGS),))
    if settings:
        features["settings"] = [{"name": str(n), "setting": "" if v is None else str(v)}
                                for n, v in settings]
    if "pg_stat_statements" in extensions:
        readers, readers_err = _query(
            conn, "SELECT r.rolname FROM pg_roles r WHERE r.rolcanlogin AND NOT r.rolsuper "
                  "AND r.rolname <> current_user "
                  "AND pg_has_role(r.oid, 'pg_read_all_stats', 'MEMBER') ORDER BY 1 LIMIT 50")
        if readers_err is None:
            features["pg_read_all_stats_members"] = [str(r[0]) for r in readers]
    edition = _managed_edition(conn)
    if edition == "aurora":
        aurora, _ = _query(conn, "SELECT aurora_version()")
        if aurora and aurora[0][0]:
            features["aurora_version"] = str(aurora[0][0])
    if ext_err is not None:
        reasons.append(u.failed_reason(ext_err, "pg_extension", "read access to pg_extension"))
    elif "vector" not in extensions:
        reasons.append("the vector extension is not installed in this database")
    return u.server(product="postgresql", source=source, version=version, edition=edition,
                    managed=edition is not None, features=features,
                    reason=" ".join(reasons))


# --------------------------------------------------------------- metrics #

def _opclass_metric(opclass: str) -> Optional[str]:
    for suffix, metric in _OPCLASS_METRIC:
        if opclass.endswith(suffix):
            return metric
    return None


def distance_metric_details(conn: Any) -> dict[str, dict[str, Any]]:
    schema = getattr(conn, "_schema", "public")
    table_filter = getattr(conn, "_table_filter", None)
    # The same tables the connector inventories: vector, halfvec and
    # sparsevec columns, and bit columns under a pgvector bit index.
    tables, err = _query(conn, f"""
        SELECT DISTINCT c.relname
        FROM pg_attribute a
        JOIN pg_type t      ON a.atttypid = t.oid
        JOIN pg_class c     ON a.attrelid = c.oid
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE {VECTOR_TABLE_PREDICATE} AND c.relkind = 'r' AND n.nspname = %s
          AND a.attnum > 0 AND NOT a.attisdropped""", (schema,))
    if err is not None:
        raise err
    rows, err = _query(conn, """
        SELECT c.relname, a.attname, opc.opcname, am.amname, ic.relname
        FROM pg_index i
        JOIN pg_class c      ON c.oid = i.indrelid
        JOIN pg_namespace n  ON n.oid = c.relnamespace
        JOIN pg_class ic     ON ic.oid = i.indexrelid
        JOIN pg_am am        ON am.oid = ic.relam
        CROSS JOIN LATERAL unnest(i.indkey::int2[], i.indclass::oid[]) AS k(attnum, opcoid)
        JOIN pg_attribute a  ON a.attrelid = c.oid AND a.attnum = k.attnum
        JOIN pg_opclass opc  ON opc.oid = k.opcoid
        WHERE n.nspname = %s""", (schema,))
    by_table: dict[str, dict[str, Any]] = {}
    for table, column, opclass, method, index in rows:
        opclass = str(opclass)
        if not opclass.startswith(("vector_", "halfvec_", "sparsevec_", "bit_")):
            continue  # not a pgvector operator class (a btree on the id, say)
        by_table.setdefault(str(table), {})[f"{column} ({index}, {method})"] = (
            _opclass_metric(opclass) or opclass)
    out: dict[str, dict[str, Any]] = {}
    for (table,) in tables:
        table = str(table)
        if table_filter and table not in table_filter:
            continue
        per = by_table.get(table, {})
        detail = u.combine(per, "pg_index/pg_opclass operator class")
        if err is not None:
            detail["error"] = u.describe_error(err)
        elif not per:
            detail["note"] = ("no pgvector index: each query chooses its own distance "
                              "operator")
        out[table] = detail
    return out


# ---------------------------------------------------------- integrations #

_PGAI_PROVIDERS = {"openai": "openai", "ollama": "self_hosted", "voyageai": "voyageai"}


def model_integrations(conn: Any) -> dict[str, Any]:
    source = "ai.vectorizer (pgai)"
    rows, err = _query(conn, "SELECT to_regclass('ai.vectorizer') IS NOT NULL")
    if err is not None:
        return u.integrations_result(observable=False, source=source,
                                     reason=u.failed_reason(err, "the catalog",
                                                            "a login role"))
    extensions, _ = _extensions(conn)
    if not rows or not rows[0][0]:
        reason = "pgai vectorizers are not installed in this database."
        if "ai" in extensions:
            reason += (f" The ai extension ({extensions['ai']}) is installed, so SQL can "
                       "call model providers directly (for example ai.openai_embed); "
                       "those calls are made per statement and are not recorded.")
        return u.integrations_result(observable=True, source=source, reason=reason,
                                     controls={"ai_extension": extensions.get("ai")}
                                     if "ai" in extensions else {})
    vrows, verr = _query(conn, "SELECT id, source_schema, source_table, config "
                               "FROM ai.vectorizer ORDER BY id")
    if verr is not None:
        return u.integrations_result(
            observable=False, source=source,
            reason=u.failed_reason(verr, "ai.vectorizer",
                                   "SELECT on ai.vectorizer (granted by ai.grant_ai_usage)"))
    integrations = []
    for vid, src_schema, src_table, config in vrows:
        if isinstance(config, (str, bytes)):
            try:
                config = json.loads(config)
            except ValueError:
                config = {}
        embedding = (config or {}).get("embedding") if isinstance(config, dict) else None
        embedding = embedding if isinstance(embedding, dict) else {}
        impl = str(embedding.get("implementation") or "unknown")
        model = embedding.get("model")
        endpoint = u.host_of(embedding.get("base_url"))
        provider = _PGAI_PROVIDERS.get(impl, impl)
        if impl == "litellm" and isinstance(model, str) and "/" in model:
            provider = model.split("/", 1)[0]
        if endpoint:
            by_host = u.provider_for_host(endpoint)
            if by_host:
                provider = by_host
            elif provider == "self_hosted":
                provider = "external"  # e.g. Ollama on a public host
        auth = ("none" if provider == "self_hosted"
                else "api_key" if embedding.get("api_key_name") else "unknown")
        integrations.append(u.integration(
            collection=str(src_table), stage="ingest", provider=provider,
            model=str(model) if model else None, endpoint_host=endpoint, auth=auth,
            module=f"pgai vectorizer ({impl})",
            evidence={"vectorizer_id": vid, "source_schema": str(src_schema),
                      "dimensions": embedding.get("dimensions"),
                      "execution": "pgai vectorizer worker"}))
    return u.integrations_result(
        observable=True, source=source, integrations=integrations,
        reason="pgai vectorizers embed rows through the vectorizer worker using the "
               "configured provider.",
        controls={"ai_extension": extensions.get("ai")} if "ai" in extensions else {})


# ------------------------------------------------------------- location #

def _host(conn: Any) -> Optional[str]:
    db = getattr(conn, "_conn", None)
    host = u.get(db, "info", "host")
    if isinstance(host, str) and host:
        return host
    endpoint = str(getattr(conn, "_endpoint", "") or "")
    m = re.search(r"(?:^|\s)host\s*=\s*'?([^\s']+)", endpoint)
    if m:
        return m.group(1)
    return u.host_of(endpoint)


def store_location(conn: Any) -> dict[str, Any]:
    source = "connection host"
    raw = _host(conn)
    if not raw:
        return u.unknown_host(source, None)
    if raw.startswith("/"):
        return u.self_hosted(source, None, local=True)  # a Unix socket directory
    host = u.host_of(raw) or raw.lower()
    for pattern, provider, doc in (
            (_RDS_HOST, "aws", "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/"
                               "Aurora.Endpoints.Cluster.html"),
            (_NEON_HOST, "neon", "https://neon.com/faqs/check-neon-project-region"),
            (_SUPABASE_POOLER, "supabase", "https://supabase.com/docs/guides/"
                                           "troubleshooting/tenant-or-user-not-found")):
        m = pattern.match(host)
        if m:
            evidence = {"host": host, "pattern_source": doc}
            if "cloud" in pattern.groupindex:
                evidence["cloud"] = m.group("cloud")
            return u.location(provider=provider, region=m.group("region"), source=source,
                              observable=True, evidence=evidence,
                              reason="The provider's endpoint hostname encodes the region.")
    if host.endswith(".postgres.database.azure.com"):
        return u.location(provider="azure", region=None, source=source, observable=False,
                          evidence={"host": host},
                          reason="Azure Database for PostgreSQL hostnames do not carry the "
                                 "region; declare the server's region.")
    if host.endswith(".supabase.co") or host.endswith(".supabase.com"):
        return u.location(provider="supabase", region=None, source=source, observable=False,
                          evidence={"host": host},
                          reason="This Supabase hostname does not carry the region; "
                                 "declare the project's region.")
    if u.is_private_host(host):
        edition = _managed_edition(conn)
        if edition is not None:
            return u.location(provider={"aurora": "aws", "aws_rds": "aws"}.get(edition, edition),
                              region=None, source=source, observable=False,
                              evidence={"host": host, "managed_hint": edition},
                              reason="The database is a managed service reached through a "
                                     "private address, which does not carry the region; "
                                     "declare it.")
        return u.self_hosted(source, host)
    return u.unknown_host(source, host)
