"""pgvector (PostgreSQL) connector.

pgvector tables have arbitrary, user-defined schemas, so the connector
introspects the catalog to find, per table:

  * the vector columns (pg_type.typname ``vector``, ``halfvec``, ``sparsevec``
    and ``bit``); each one's dimension comes from atttypmod, the most reliable
    source without scanning rows. ``bit`` is a core Postgres type also used for
    flags, so a ``bit`` column counts only when a pgvector ``bit_*_ops`` index
    covers it or the table already has another pgvector column
  * a text column (text/varchar), preferring common chunk column names
  * the key columns (every primary-key column, in key order; else the table's
    first column, which is not guaranteed to be unique)

Collection model: each table with at least one vector column is one
Collection, however many vector columns it has. The first dense column
(``vector`` or ``halfvec``) supplies ``Chunk.embedding``; every vector column,
with its type, dimension and whether it is dense, is listed in
``Collection.metadata["vector_columns"]``, and the ones not surfaced as the
embedding are named in ``metadata["unread_vector_columns"]``, so no vector
column is dropped without a trace. ``sparsevec`` and ``bit`` values are not
dense float vectors and are never decoded as one.

A chunk id is the key value as text. With a composite primary key it is a
JSON array of the key values as text, in key order, so every id names exactly
one row; ``delete_chunks`` takes the same form back.

Reads page by keyset over every primary-key column, so rows are neither
skipped nor repeated as the table changes; a table without a primary key is
read through one server-side cursor in a single statement. The connection is
in autocommit mode and writes run in explicit transactions, so a failed
catalog probe never poisons the next statement. Tables the connecting role
cannot SELECT are listed with an unknown count and a read error naming the
table, never as empty. Tables whose row-level security policies apply to the
connecting role (``row_security_active``) are read, but only the rows those
policies show it are counted and read, so each carries a read error too: a
count that matches a filtered read proves nothing about the table.

psycopg is imported lazily so the rest of VecShield works without it.

Crypto introspection reads only catalogs Postgres itself maintains:
``pg_stat_ssl`` for this session's TLS, ``pg_hba_file_rules`` for whether
plaintext clients are accepted (superuser-readable by default), and Percona
``pg_tde`` / EDB TDE for encryption at rest. Community Postgres has no
at-rest state to report, and ``pgcrypto`` being installed says nothing about
whether anything was encrypted with it.
"""

from __future__ import annotations

import json
import math
import os
import re
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from vecshield_platform.connectors.base import (
    AtRestObservation,
    Connector,
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    UnsupportedCapability,
    mapped_call,
    mapped_errors,
    retry_read,
)
from vecshield_platform.connectors.redact import redact_credentials
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

# Preferred names for the text/content column, best first.
_TEXT_NAME_PREFERENCE = (
    "content", "text", "document", "chunk", "body", "passage", "page_content",
)


#: libpq sslmode values, in increasing strength.
SSLMODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")

#: psycopg exception class names (SQLSTATE classes and transport errors) and
#: what they mean for a caller. Names, not classes, so psycopg stays optional;
#: translate_error walks the MRO, so a specific class wins over its base.
_ERRORS = {
    "InsufficientPrivilege": ConnectorAuthError,              # 42501
    "InvalidPassword": ConnectorAuthError,                    # 28P01
    "InvalidAuthorizationSpecification": ConnectorAuthError,  # 28000
    "UndefinedTable": ConnectorNotFound,                      # 42P01
    "InvalidSchemaName": ConnectorNotFound,                   # 3F000
    "QueryCanceled": ConnectorTimeout,                        # 57014 statement_timeout
    "ConnectionTimeout": ConnectorTimeout,
    "LockNotAvailable": ConnectorTimeout,                     # 55P03 lock_timeout
    "AdminShutdown": ConnectorUnavailable,                    # 57P01
    "CannotConnectNow": ConnectorUnavailable,                 # 57P03
    "TooManyConnections": ConnectorUnavailable,               # 53300
    "SerializationFailure": ConnectorUnavailable,             # 40001
    "DeadlockDetected": ConnectorUnavailable,                 # 40P01
    "ConnectionException": ConnectorUnavailable,              # 08xxx
    "OperationalError": ConnectorUnavailable,                 # lost connection
}

#: pgvector column types. ``vector`` and ``halfvec`` are dense float vectors;
#: ``sparsevec`` (``{i:v,...}/dim``) and ``bit`` (binary) are not.
VECTOR_TYPES = ("vector", "halfvec", "sparsevec", "bit")
DENSE_TYPES = ("vector", "halfvec")
_BIT_OPCLASSES = ("bit_hamming_ops", "bit_jaccard_ops")

#: True when a pgvector bit operator class indexes column ``a`` of table ``c``.
BIT_INDEXED_SQL = (
    "EXISTS (SELECT 1 FROM pg_index bi"
    " CROSS JOIN LATERAL unnest(bi.indkey::int2[], bi.indclass::oid[])"
    " AS bk(attnum, opcoid)"
    " JOIN pg_opclass bo ON bo.oid = bk.opcoid"
    " WHERE bi.indrelid = c.oid AND bk.attnum = a.attnum"
    " AND bo.opcname IN ('bit_hamming_ops', 'bit_jaccard_ops'))"
)

#: Which columns make a table a vector table (pg_type ``t``, pg_class ``c``,
#: pg_attribute ``a``). Shared with store_facts so both see the same tables.
#: A ``bit`` column co-located with another pgvector column needs no index;
#: such a table is already matched through that other column.
VECTOR_TABLE_PREDICATE = (
    "(t.typname IN ('vector', 'halfvec', 'sparsevec')"
    f" OR (t.typname = 'bit' AND {BIT_INDEXED_SQL}))"
)

_VECTOR_COLUMNS_SQL = f"""
    SELECT c.relname, a.attname, t.typname, a.atttypmod,
           has_table_privilege(c.oid, 'SELECT') AS readable,
           {BIT_INDEXED_SQL} AS bit_indexed,
           row_security_active(c.oid) AS row_filtered
    FROM pg_attribute a
    JOIN pg_type t      ON a.atttypid = t.oid
    JOIN pg_class c     ON a.attrelid = c.oid
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE t.typname IN ('vector', 'halfvec', 'sparsevec', 'bit')
      AND c.relkind = 'r'
      AND n.nspname = %s
      AND a.attnum > 0
      AND NOT a.attisdropped
    ORDER BY c.relname, a.attnum
"""

#: pgvector operator-class suffix -> (metric, the distance operator it indexes).
_OPCLASS_OPERATORS = (("_cosine_ops", "cosine", "<=>"), ("_l2_ops", "l2", "<->"),
                      ("_ip_ops", "ip", "<#>"), ("_l1_ops", "l1", "<+>"))

#: HNSW and IVFFlat indexes on one column of one table, full before partial.
_ANN_INDEX_SQL = """
    SELECT ic.relname, am.amname, opc.opcname, i.indpred IS NOT NULL
    FROM pg_index i
    JOIN pg_class c      ON c.oid = i.indrelid
    JOIN pg_namespace n  ON n.oid = c.relnamespace
    JOIN pg_class ic     ON ic.oid = i.indexrelid
    JOIN pg_am am        ON am.oid = ic.relam
    CROSS JOIN LATERAL unnest(i.indkey::int2[], i.indclass::oid[]) AS k(attnum, opcoid)
    JOIN pg_attribute a  ON a.attrelid = c.oid AND a.attnum = k.attnum
    JOIN pg_opclass opc  ON opc.oid = k.opcoid
    WHERE n.nspname = %s AND c.relname = %s AND a.attname = %s
      AND am.amname IN ('hnsw', 'ivfflat')
    ORDER BY i.indpred IS NOT NULL, ic.relname
"""

#: Settings that bound an approximate scan, as ann_index_info() reports them.
_ANN_SETTINGS = ("hnsw.iterative_scan", "hnsw.ef_search", "hnsw.max_scan_tuples",
                 "ivfflat.iterative_scan", "ivfflat.probes", "ivfflat.max_probes")

#: The iterative-scan mode query_iterative() sets per index type. IVFFlat
#: has only relaxed_order; for HNSW strict_order keeps results in distance
#: order (pgvector README, "Iterative Index Scans", 0.8.0+).
_ITERATIVE_SCAN = {"hnsw": ("hnsw.iterative_scan", "strict_order"),
                   "ivfflat": ("ivfflat.iterative_scan", "relaxed_order")}

#: Table privileges access_model() asks about for the retrieval role.
_TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")

#: Rows per DELETE statement for composite keys (all in one transaction).
_DELETE_BATCH = 500

_UNREADABLE_REASON = ("the connecting role has no SELECT privilege on this table, "
                      "so its rows and row count were not read")

_ROW_FILTERED_REASON = ("row-level security policies apply to the connecting role on "
                        "this table, so only the rows they show it were counted and "
                        "read; rows they hide were not scanned")


def group_vector_columns(rows: list) -> dict[str, dict[str, Any]]:
    """Catalog rows -> ``{table: {"readable", "row_filtered", "columns"}}``.

    ``rows`` are ``(table, column, type, atttypmod, readable, bit_indexed,
    row_filtered)`` in table and column order. A ``bit`` column is kept only
    when a pgvector bit operator class indexes it or the table has another
    pgvector column: ``bit`` alone is an ordinary Postgres type.
    ``row_filtered`` is ``row_security_active``: row-level security policies
    apply to the connecting role on that table.
    """
    tables: dict[str, dict[str, Any]] = {}
    for row in rows:
        table, column, typ, typmod = row[0], row[1], str(row[2]), row[3]
        readable = bool(row[4]) if len(row) > 4 and row[4] is not None else True
        bit_indexed = bool(row[5]) if len(row) > 5 else False
        row_filtered = bool(row[6]) if len(row) > 6 else False
        entry = tables.setdefault(str(table), {"readable": readable,
                                               "row_filtered": row_filtered,
                                               "columns": []})
        entry["readable"] = entry["readable"] and readable
        entry["row_filtered"] = entry["row_filtered"] or row_filtered
        entry["columns"].append({
            "column": str(column), "type": typ,
            "dimension": typmod if isinstance(typmod, int) and typmod > 0 else None,
            "dense": typ in DENSE_TYPES, "_bit_indexed": bit_indexed})
    out: dict[str, dict[str, Any]] = {}
    for table, entry in tables.items():
        has_pgvector = any(c["type"] != "bit" for c in entry["columns"])
        cols = [c for c in entry["columns"]
                if c["type"] != "bit" or c["_bit_indexed"] or has_pgvector]
        for c in cols:
            c.pop("_bit_indexed", None)
        if cols:
            out[table] = {"readable": entry["readable"],
                          "row_filtered": entry["row_filtered"], "columns": cols}
    return out


def _primary_vector(columns: list[dict[str, Any]]) -> dict[str, Any]:
    """The column whose values become Chunk.embedding: the first dense one."""
    for col in columns:
        if col["dense"]:
            return col
    return columns[0]


class PgVectorConnector(Connector):
    kind = "pgvector"

    def capabilities(self) -> set[str]:
        return {"query", "delete", "transport_introspection",
                "tls_enforcement_introspection", "session_auth_introspection",
                "access_introspection", "at_rest_introspection", "ann_iterative_scan"}

    def __init__(
        self,
        dsn: Optional[str] = None,
        *,
        host: Optional[str] = None,
        port: int = 5432,
        dbname: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        schema: str = "public",
        tables: Optional[list[str]] = None,
        sslmode: Optional[str] = None,
        retrieval_role: Optional[str] = None,
    ):
        if sslmode is not None and sslmode.lower() not in SSLMODES:
            raise ValueError(f"sslmode must be one of {', '.join(SSLMODES)}")
        sslmode = sslmode.lower() if sslmode else None
        try:
            import psycopg
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "psycopg not installed. Run: pip install 'vecshield[pgvector]'"
            ) from e

        self._schema = schema
        # The role the RAG application retrieves as. A name, never a
        # credential: access_model() judges its privileges from the catalog.
        self._retrieval_role = (retrieval_role or "").strip() or None
        self._table_filter = set(tables) if tables else None
        # The endpoint string is left exactly as before: finding fingerprints
        # are keyed on it. sslmode travels in describe().metadata instead.
        extra: dict[str, Any] = {"sslmode": sslmode} if sslmode else {}
        # Autocommit: every read is its own statement, so a failed catalog
        # probe cannot abort the transaction the next read runs in. Writes
        # open an explicit transaction (see _write_transaction).
        with mapped_errors(self.kind, _ERRORS):
            if dsn:
                self._conn = psycopg.connect(dsn, autocommit=True, **extra)
                self._endpoint = _redact_dsn(dsn)
            else:
                self._conn = psycopg.connect(
                    host=host or "localhost",
                    port=port,
                    dbname=dbname,
                    user=user,
                    password=password,
                    autocommit=True,
                    **extra,
                )
                self._endpoint = f"postgresql://{host or 'localhost'}:{port}/{dbname}"
        # Findings, and the suppressions and cases keyed on their fingerprints,
        # take the store name. Two stores scoped to different schemas of one
        # database must not share it, or a risk accepted on one mutes the
        # other. The default schema keeps the bare endpoint, so its existing
        # fingerprints are unchanged. Probes read `endpoint`, never the name.
        self._name = (self._endpoint if schema == "public"
                      else f"{self._endpoint} schema={schema}")
        self._transport = pg_transport_config(dsn, sslmode)
        self._credentials = pg_credential_config(dsn, password)
        # Per-table layout cache (see _build_layout).
        self._layout: dict[str, dict[str, Any]] = {}
        # Per-table metadata columns (everything but key/text/vector), cached.
        self._meta_cols: dict[str, list[str]] = {}

    # ------------------------------------------------------------------ #

    def describe(self) -> VectorStore:
        transport = getattr(self, "_transport", None)
        credentials = getattr(self, "_credentials", None)
        metadata: dict[str, Any] = {"transport": dict(transport)} if transport else {}
        if credentials and credentials["sources"]:
            metadata["credential_configured"] = True
            metadata["credential_sources"] = list(credentials["sources"])
        return VectorStore(
            kind=self.kind,
            name=getattr(self, "_name", self._endpoint),
            endpoint=self._endpoint,
            collections=self.list_collections(),
            metadata=metadata,
        )

    def list_collections(self) -> list[Collection]:
        out: list[Collection] = []
        table_filter = getattr(self, "_table_filter", None)
        vector_tables = self._vector_columns()
        for table in sorted((table_filter or set()) - set(vector_tables)):
            self._note_not_found(table)
        for table, info in vector_tables.items():
            if table_filter and table not in table_filter:
                continue
            lay = self._build_layout(table, info)
            self._layout[table] = lay
            metadata: dict[str, Any] = {
                "vector_column": lay["vec"], "vector_type": lay["vec_type"],
                "text_column": lay["text"],
                "vector_columns": [dict(c) for c in lay["vector_columns"]],
            }
            unread = [c["column"] for c in lay["vector_columns"]
                      if c["column"] != lay["vec"]]
            if unread:
                metadata["unread_vector_columns"] = unread
            if not lay["vec_dense"]:
                metadata["embedding_unavailable"] = (
                    f"{lay['vec_type']} values are not dense float vectors")
            if not lay["readable"]:
                self._note_unreadable(table)
                metadata.update(readable=False, count_known=False,
                                unreadable_reason=_UNREADABLE_REASON)
                out.append(Collection(name=table, count=0, dimension=lay["dim"],
                                      metadata=metadata))
                continue
            metadata.update(key_columns=list(lay["key_cols"]), id_source=lay["id_source"])
            if lay["row_filtered"]:
                self._note_row_filtered(table)
                metadata.update(row_security_filtered=True,
                                row_security_reason=_ROW_FILTERED_REASON)
            count: int = 0
            try:
                count = int(self._read(
                    f"SELECT COUNT(*) FROM {self._qtable(table)}", one=True)[0])
            except Exception as exc:  # noqa: BLE001 - an unknown count, not zero
                metadata.update(count_known=False, count_error=type(exc).__name__)
            out.append(Collection(name=table, count=count, dimension=lay["dim"],
                                  metadata=metadata))
        return out

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        lay = self._layout_for(collection)
        if not lay["readable"]:
            # Never a SELECT the role is known to be refused; the gap is a
            # read error naming the table, not an empty table.
            self._note_unreadable(collection)
            return
        if lay["row_filtered"]:
            # Recorded on every read, as passes reset read errors after
            # listing; the rows the policies show are still read.
            self._note_row_filtered(collection)
        meta_cols = self._metadata_columns(collection, lay)
        select = ", ".join(_quote_ident(c) for c in self._select_columns(lay, meta_cols))
        if lay["id_source"] == "primary_key":
            yield from self._iter_keyset(collection, lay, meta_cols, select, batch_size)
        else:
            yield from self._iter_cursor(collection, lay, meta_cols, select, batch_size)

    def _iter_keyset(self, collection: str, lay: dict[str, Any], meta_cols: list[str],
                     select: str, batch_size: int) -> Iterator[Chunk]:
        """Page by ``(k1, k2, ...) > (last)`` over every primary-key column.

        Stable where OFFSET is not: a row inserted or deleted ahead of the
        read position does not shift later pages, and a composite key orders
        totally because every key column is in the ORDER BY.
        """
        keys = [_quote_ident(k) for k in lay["key_cols"]]
        order = ", ".join(keys)
        base = f"SELECT {select} FROM {self._qtable(collection)}"
        if len(keys) == 1:
            after = f"{keys[0]} > %s"
        else:
            after = f"({order}) > ({', '.join(['%s'] * len(keys))})"
        last: Optional[tuple] = None
        while True:
            if last is None:
                sql, params = f"{base} ORDER BY {order} LIMIT %s", (batch_size,)
            else:
                sql = f"{base} WHERE {after} ORDER BY {order} LIMIT %s"
                params = (*last, batch_size)
            try:
                rows = self._read(sql, params)
            except Exception as exc:
                self._record_read_error(
                    collection, operation="page_read", error_type=type(exc).__name__,
                    reason="a page of rows could not be read; rows after it were "
                           "not scanned")
                raise
            if not rows:
                return
            for row in rows:
                yield self._row_chunk(collection, lay, meta_cols, row)
            last = tuple(rows[-1][:len(keys)])
            if len(rows) < batch_size:
                return

    def _iter_cursor(self, collection: str, lay: dict[str, Any], meta_cols: list[str],
                     select: str, batch_size: int) -> Iterator[Chunk]:
        """One statement through a server-side cursor, for tables without a key.

        A single SELECT reads one snapshot, so rows are not skipped or repeated
        however the table changes while it is read.
        """
        name = f"vecshield_{uuid.uuid4().hex[:16]}"
        try:
            with mapped_errors(self.kind, _ERRORS), self._transaction():
                with self._conn.cursor(name=name) as cur:
                    cur.execute(f"SELECT {select} FROM {self._qtable(collection)}")
                    while True:
                        rows = cur.fetchmany(batch_size)
                        if not rows:
                            return
                        for row in rows:
                            yield self._row_chunk(collection, lay, meta_cols, row)
        except Exception as exc:
            self._record_read_error(
                collection, operation="cursor_read", error_type=type(exc).__name__,
                reason="the table could not be read to the end; later rows were not "
                       "scanned")
            raise

    def query(
        self,
        collection: str,
        vector: list[float],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[QueryHit]:
        """Nearest-neighbor search with the distance operator the table is indexed for.

        The operator follows the operator class of the column's HNSW or IVFFlat
        index (``<=>`` cosine, ``<->`` L2, ``<#>`` negative inner product,
        ``<+>`` L1), so the query takes the path the application's queries
        take; a column without one is searched by cosine distance.

        `where` is applied as equality filters on real table columns; keys that
        aren't columns of the table are ignored (so a caller can't inject SQL or
        crash the probe on a typo). Scores rise as results get closer:
        ``1/(1+distance)``, or the inner product itself for ``<#>``. Only dense
        columns (``vector``, ``halfvec``) can be searched with a float query
        vector.
        """
        sql, params, lay, meta_cols, metric = self._knn_sql(collection, vector, top_k, where)
        return self._knn_hits(self._read(sql, params), lay, meta_cols, metric)

    def ann_index_info(self, collection: str) -> dict[str, Any]:
        """The column's approximate index, and the settings that bound its scans.

        ``{"index_type": "hnsw"|"ivfflat"|None, "index", "metric", "operator",
        "partial", "settings", "retrieval_role_settings", "pgvector_version",
        "iterative_scan_supported", "iterative_scan"}``. ``settings`` are this
        session's values (server, database and VecShield's own role);
        ``retrieval_role_settings`` are the declared retrieval role's
        ``ALTER ROLE ... SET`` values, which its sessions use instead.
        ``iterative_scan`` is the effective value for the index type: the
        retrieval role's setting when it has one, else this session's.
        """
        lay = self._layout_for(collection)
        info: dict[str, Any] = {"index_type": None}
        index = self._ann_index(collection, lay["vec"])
        if index and "error" in index:
            return {"index_type": None, "error": index["error"]}
        if index:
            info.update(index)
        info["settings"], info["retrieval_role_settings"] = self._ann_settings()
        version = self._pgvector_version()
        info["pgvector_version"] = version
        info["iterative_scan_supported"] = _version_at_least(version, (0, 8, 0))
        if info["index_type"]:
            info["iterative_scan"] = _effective_iterative_scan(
                info["index_type"], info["settings"], info["retrieval_role_settings"])
        return info

    def _ann_settings(self) -> tuple[dict[str, str], dict[str, str]]:
        """(this session's ANN settings, the declared retrieval role's own).

        pgvector defines its settings when the backend loads its library, and
        current_setting() reads them as NULL before that, so a vector literal
        is cast first; it loads the library and reads nothing.
        """
        self._catalog("SELECT '[0]'::vector IS NULL")
        rows, _ = self._catalog(
            "SELECT " + ", ".join(f"current_setting('{name}', true)"
                                  for name in _ANN_SETTINGS))
        session = ({n: str(v) for n, v in zip(_ANN_SETTINGS, rows[0]) if v is not None}
                   if rows else {})
        role = getattr(self, "_retrieval_role", None)
        role_settings: dict[str, str] = {}
        if role:
            rrows, _ = self._catalog(
                "SELECT unnest(s.setconfig) FROM pg_db_role_setting s "
                "JOIN pg_roles r ON r.oid = s.setrole WHERE r.rolname = %s "
                "AND s.setdatabase IN (0, (SELECT oid FROM pg_database "
                "WHERE datname = current_database()))", (role,))
            for (entry,) in rrows:
                name, _sep, value = str(entry).partition("=")
                if name in _ANN_SETTINGS:
                    role_settings[name] = value
        return session, role_settings

    def query_iterative(
        self,
        collection: str,
        vector: list[float],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[QueryHit]:
        """``query()`` with pgvector's iterative index scan on, for this statement only.

        Runs in a read-only transaction with ``SET LOCAL hnsw.iterative_scan =
        strict_order`` (or ``ivfflat.iterative_scan = relaxed_order``, the only
        mode IVFFlat has), so the index keeps scanning until ``top_k`` rows
        pass the filter or it reaches ``hnsw.max_scan_tuples`` /
        ``ivfflat.max_probes``. Nothing persists past the transaction.
        Unsupported without an HNSW/IVFFlat index or below pgvector 0.8.0.
        """
        lay = self._layout_for(collection)
        index = self._ann_index(collection, lay["vec"])
        if not index or "error" in index:
            raise UnsupportedCapability(
                f"{self.kind}: {collection!r} has no HNSW or IVFFlat index on "
                f"{lay['vec']!r}, so its scans are exact")
        version = self._pgvector_version()
        if not _version_at_least(version, (0, 8, 0)):
            raise UnsupportedCapability(
                f"{self.kind}: iterative index scans need pgvector 0.8.0 or later "
                f"(running {version or 'an unknown version'})")
        setting, value = _ITERATIVE_SCAN[index["index_type"]]
        sql, params, lay, meta_cols, metric = self._knn_sql(collection, vector, top_k, where)
        with mapped_errors(self.kind, _ERRORS), self._transaction():
            with self._conn.cursor() as cur:
                cur.execute("SET TRANSACTION READ ONLY")
                cur.execute(f"SET LOCAL {setting} = {value}")
                cur.execute(sql, params)
                rows = list(cur.fetchall())
        return self._knn_hits(rows, lay, meta_cols, metric)

    def _ann_index(self, table: str, column: str) -> Optional[dict[str, Any]]:
        """The first HNSW/IVFFlat index on ``column`` (a full index before a
        partial one), cached; ``{"error": ...}`` when the catalog refused."""
        cache = self.__dict__.setdefault("_ann_cache", {})
        if (table, column) not in cache:
            rows, error = self._catalog(_ANN_INDEX_SQL, (self._schema, table, column))
            if error:
                return {"error": error}  # not cached: a later read may succeed
            entry: Optional[dict[str, Any]] = None
            for name, method, opclass, partial in rows:
                metric, operator = _opclass_operator(str(opclass))
                if operator:
                    entry = {"index": str(name), "index_type": str(method),
                             "opclass": str(opclass), "metric": metric,
                             "operator": operator, "partial": bool(partial)}
                    break
            cache[(table, column)] = entry
        return cache[(table, column)]

    def _pgvector_version(self) -> Optional[str]:
        """The running pgvector: the installed package, else the catalog version."""
        rows, _ = self._catalog(
            "SELECT a.default_version, e.extversion FROM pg_extension e "
            "LEFT JOIN pg_available_extensions a ON a.name = e.extname "
            "WHERE e.extname = 'vector'")
        if not rows:
            return None
        package, catalog = rows[0]
        return str(package or catalog) if (package or catalog) else None

    def _knn_sql(self, collection: str, vector: list[float], top_k: int,
                 where: Optional[dict[str, Any]]) -> tuple[str, list, dict[str, Any],
                                                           list[str], str]:
        lay = self._layout_for(collection)
        if not lay["readable"]:
            raise ConnectorAuthError(
                f"{self.kind}: no SELECT privilege on table {collection!r}")
        if not lay["vec_dense"]:
            raise UnsupportedCapability(
                f"{self.kind}: {lay['vec_type']} column {lay['vec']!r} cannot be "
                "searched with a dense query vector")
        meta_cols = self._metadata_columns(collection, lay)
        select_sql = ", ".join(_quote_ident(c) for c in self._select_columns(
            lay, meta_cols, with_vector=False))

        vec_literal = "[" + ",".join(str(float(x)) for x in vector) + "]"
        params: list = [vec_literal]
        where_sql = ""
        if where:
            known = set(self._all_columns(collection))
            clauses = []
            for k, v in where.items():
                if k in known:
                    clauses.append(f"{_quote_ident(k)} = %s")
                    params.append(v)
            if clauses:
                where_sql = " WHERE " + " AND ".join(clauses)
        params.append(top_k)

        index = self._ann_index(collection, lay["vec"])
        metric, operator = "cosine", "<=>"
        if index and "error" not in index:
            metric, operator = index["metric"], index["operator"]
        sql = (
            f"SELECT {select_sql}, "
            f"({_quote_ident(lay['vec'])} {operator} %s::{lay['vec_type']}) AS _distance "
            f"FROM {self._qtable(collection)}{where_sql} "
            f"ORDER BY _distance LIMIT %s"
        )
        return sql, params, lay, meta_cols, metric

    def _knn_hits(self, rows: list, lay: dict[str, Any], meta_cols: list[str],
                  metric: str) -> list[QueryHit]:
        hits: list[QueryHit] = []
        for row in rows:
            _id, text, metadata, rest = self._split_row(lay, meta_cols, row)
            distance = rest[0] if rest else None
            # A zero-norm vector on either side makes pgvector's cosine
            # distance NaN (it divides by sqrt(norma * normb) and deliberately
            # preserves NaN), and 1/(1+NaN) is NaN. A score that is silently
            # NaN is worse than no score: it compares false against every
            # threshold, so a hit would be dropped by a caller that believes it
            # scored the hit. Report it as unscored instead.
            if distance is None or not math.isfinite(float(distance)):
                score = 0.0
            elif metric == "ip":
                # <#> is the negative inner product; the product is the score.
                score = -float(distance)
            else:
                score = 1.0 / (1.0 + float(distance))
            hits.append(QueryHit(id=_id, score=score, text=text, metadata=metadata))
        return hits

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        """Delete rows by chunk id, cast to the key columns' own types.

        Comparing the key as text would skip an index and, for types whose
        text form is not canonical, miss rows. The cast type comes from
        ``format_type()`` and is used only when it is a plain type name; any
        other key type falls back to comparing ``key::text``. The DELETE runs
        in one transaction, rolled back if any statement fails.
        """
        if not ids:
            return 0
        lay = self._layout_for(collection)
        keys, types = lay["key_cols"], lay["key_types"]
        qtable = self._qtable(collection)
        casts = [_safe_type(t) for t in types]
        statements: list[tuple[str, tuple]] = []
        if len(keys) == 1:
            col = _quote_ident(keys[0])
            if casts[0]:
                sql = f"DELETE FROM {qtable} WHERE {col} = ANY(%s::{casts[0]}[])"
            else:
                sql = f"DELETE FROM {qtable} WHERE {col}::text = ANY(%s::text[])"
            statements.append((sql, ([str(i) for i in ids],)))
        else:
            # Parsed before anything runs: a malformed id refuses the batch.
            tuples = [_split_id(i, len(keys)) for i in ids]
            left = ", ".join(_quote_ident(k) if c else f"{_quote_ident(k)}::text"
                             for k, c in zip(keys, casts))
            holder = "(" + ", ".join(f"%s::{c}" if c else "%s::text" for c in casts) + ")"
            for start in range(0, len(tuples), _DELETE_BATCH):
                batch = tuples[start:start + _DELETE_BATCH]
                sql = (f"DELETE FROM {qtable} WHERE ({left}) IN "
                       f"({', '.join([holder] * len(batch))})")
                statements.append((sql, tuple(v for t in batch for v in t)))
        deleted = 0
        with mapped_errors(self.kind, _ERRORS), self._transaction():
            with self._conn.cursor() as cur:
                for sql, params in statements:
                    cur.execute(sql, params)
                    deleted += max(int(cur.rowcount or 0), 0)
        return deleted

    # ----------------------------- helpers ----------------------------- #

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        """An explicit transaction: committed on success, rolled back on error."""
        tx = getattr(self._conn, "transaction", None)
        if callable(tx):
            with tx():
                yield
            return
        # A DB-API connection without psycopg's transaction() block.
        try:
            yield
        except BaseException:
            rollback = getattr(self._conn, "rollback", None)
            if callable(rollback):
                rollback()
            raise
        commit = getattr(self._conn, "commit", None)
        if callable(commit):
            commit()

    def _read(self, sql: str, params: Any = None, *, one: bool = False) -> Any:
        """One idempotent read, with errors mapped and transient ones retried."""
        def run() -> Any:
            with self._conn.cursor() as cur:
                if params is None:
                    cur.execute(sql)
                else:
                    cur.execute(sql, params)
                return cur.fetchone() if one else cur.fetchall()
        return retry_read(mapped_call(run, kind=self.kind, extra=_ERRORS))

    def _qtable(self, table: str) -> str:
        return f"{_quote_ident(self._schema)}.{_quote_ident(table)}"

    def _layout_for(self, collection: str) -> dict[str, Any]:
        if collection not in self._layout:
            self.list_collections()  # populate the layout cache
        if collection not in self._layout:
            raise ConnectorNotFound(f"{self.kind}: no vector table {collection!r}")
        return self._layout[collection]

    def _note_unreadable(self, table: str) -> None:
        """One read error per unreadable table, however often it is listed."""
        for entry in self.read_errors():
            if entry.get("collection") == table and entry.get("operation") == "select":
                return
        self._record_read_error(table, operation="select",
                                error_type="InsufficientPrivilege",
                                reason=_UNREADABLE_REASON)

    def _note_row_filtered(self, table: str) -> None:
        """One read error per table whose row security filters this role."""
        for entry in self.read_errors():
            if entry.get("collection") == table and entry.get("operation") == "row_security":
                return
        self._record_read_error(table, operation="row_security",
                                error_type="RowSecurityFiltered",
                                reason=_ROW_FILTERED_REASON)

    def _note_not_found(self, table: str) -> None:
        """One store-wide read error per configured table that is not listed.

        Store-wide (no collection) because the table is not a collection the
        scan can report on: without this, a filter matching nothing would
        scan nothing and pass.
        """
        for entry in self.read_errors():
            if entry.get("table") == table and entry.get("operation") == "inventory":
                return
        self._record_read_error(
            None, table=table, operation="inventory", error_type="TableNotFound",
            reason=(f"the configured table {table!r} is not a pgvector table in schema "
                    f"{self._schema!r}: it does not exist, is in another schema, has no "
                    "vector column, or is a partitioned parent (whose partitions are "
                    "listed by their own names), so it was not scanned"))

    def _build_layout(self, table: str, info: dict[str, Any]) -> dict[str, Any]:
        columns = info["columns"]
        primary = _primary_vector(columns)
        lay: dict[str, Any] = {
            "vec": primary["column"], "vec_type": primary["type"],
            "vec_dense": primary["dense"], "dim": primary["dimension"],
            "vector_columns": columns, "readable": info["readable"],
            "row_filtered": bool(info.get("row_filtered")),
            "text": None, "key_cols": [], "key_types": [], "id_source": None,
        }
        if not info["readable"]:
            return lay
        lay["text"] = self._text_column(table)
        keys = self._primary_key(table)
        if keys:
            lay["id_source"] = "primary_key"
        else:
            keys = self._first_column(table)
            lay["id_source"] = "first_column"
        lay["key_cols"] = [k for k, _t in keys]
        lay["key_types"] = [t for _k, t in keys]
        return lay

    def _select_columns(self, lay: dict[str, Any], meta_cols: list[str],
                        with_vector: bool = True) -> list[str]:
        cols = list(lay["key_cols"])
        if lay["text"]:
            cols.append(lay["text"])
        cols.extend(meta_cols)
        if with_vector:
            cols.append(lay["vec"])
        return cols

    def _split_row(self, lay: dict[str, Any], meta_cols: list[str],
                   row: Any) -> tuple[str, Optional[str], dict[str, Any], list]:
        """(chunk id, text, metadata, remaining values) from a selected row."""
        nkeys = len(lay["key_cols"])
        key_values = list(row[:nkeys])
        idx = nkeys
        text = None
        if lay["text"]:
            text = row[idx]
            idx += 1
        metadata: dict[str, Any] = {}
        if nkeys > 1:
            # The key columns are named in the id too, but a tenant column in
            # a composite key is exactly the metadata isolation checks need.
            metadata.update(zip(lay["key_cols"], key_values))
        for mc in meta_cols:
            metadata[mc] = row[idx]
            idx += 1
        return _compose_id(key_values), text, metadata, list(row[idx:])

    def _row_chunk(self, collection: str, lay: dict[str, Any], meta_cols: list[str],
                   row: Any) -> Chunk:
        _id, text, metadata, rest = self._split_row(lay, meta_cols, row)
        raw = rest[0] if rest else None
        embedding = _parse_vector(raw) if lay["vec_dense"] else None
        return Chunk(id=_id, collection=collection, text=text, embedding=embedding,
                     metadata=metadata)


    # ------------------------- crypto introspection ------------------------- #

    def _catalog(self, sql: str, params: tuple = ()) -> tuple[list, Optional[str]]:
        """Run a read-only catalog query; return (rows, error-description).

        A failed statement aborts the surrounding transaction in Postgres, so
        the connection is rolled back before returning — otherwise the next
        scan query would fail on a transaction this probe poisoned.
        """
        try:
            with self._conn.cursor() as cur:
                # No params, no placeholder parsing: catalog SQL may contain '%'.
                if params:
                    cur.execute(sql, params)
                else:
                    cur.execute(sql)
                return list(cur.fetchall()), None
        except Exception as exc:  # noqa: BLE001 - introspection must never break a scan
            rollback = getattr(self._conn, "rollback", None)
            if callable(rollback):
                try:
                    rollback()
                except Exception:  # pragma: no cover - best effort
                    pass
            return [], _describe_error(exc)

    def transport_session_info(self) -> dict[str, Any]:
        rows, error = self._catalog(
            "SELECT s.ssl, s.version, s.cipher, a.client_addr IS NULL "
            "FROM pg_stat_ssl s JOIN pg_stat_activity a ON a.pid = s.pid "
            "WHERE s.pid = pg_backend_pid()")
        if error or not rows:
            return {"tls": None, "version": None, "cipher": None, "source": "pg_stat_ssl",
                    "reason": (f"pg_stat_ssl could not be read ({error})" if error
                               else "pg_stat_ssl has no row for this session")}
        ssl_on, version, cipher, local_socket = rows[0]
        if local_socket and not ssl_on:
            # A Unix-socket session never crosses a network; ssl=false there
            # says nothing about TCP clients.
            return {"tls": None, "version": None, "cipher": None, "source": "pg_stat_ssl",
                    "local_socket": True,
                    "reason": "this session uses a local Unix socket, not the network"}
        return {"tls": bool(ssl_on), "version": version, "cipher": cipher,
                "source": "pg_stat_ssl"}

    def session_auth_info(self) -> dict[str, Any]:
        """``system_user`` (PostgreSQL 16+), then libpq's own password flag.

        system_user is ``auth_method:identity``, or NULL when the session was
        not authenticated, as under trust. Below 16, libpq can still say a
        password was demanded and sent; any other outcome stays unknown, since
        peer, certificate and trust all send none.
        """
        version = getattr(getattr(self._conn, "info", None), "server_version", None)
        if isinstance(version, int) and version >= 160000:
            rows, error = self._catalog("SELECT system_user")
            if not error and rows:
                value = rows[0][0]
                if value is None:
                    return {"observed": True, "authenticated": False, "auth_method": None,
                            "source": "system_user",
                            "reason": "PostgreSQL reports system_user as NULL for this "
                                      "session: the server admitted it without "
                                      "authenticating it (trust authentication)"}
                method = str(value).split(":", 1)[0]
                return {"observed": True, "authenticated": True, "auth_method": method,
                        "source": "system_user",
                        "reason": f"the server authenticated this session with {method}"}
            unread = f"system_user could not be read ({error or 'no row'})"
        else:
            unread = "system_user needs PostgreSQL 16 or later"
        pgconn = getattr(self._conn, "pgconn", None)
        if getattr(pgconn, "used_password", False) is True:
            return {"observed": True, "authenticated": True, "auth_method": "password",
                    "source": "libpq",
                    "reason": "the server required a password for this session "
                              f"({unread}, so the exact method is not known)"}
        return {"observed": False, "authenticated": None, "auth_method": None,
                "source": "system_user",
                "reason": f"{unread}, and no password was requested, which certificate, "
                          "peer, GSSAPI and trust authentication all look like"}

    def access_model(self) -> dict[str, Any]:
        """Roles, row security and grants on the vector tables, from the catalog.

        Every read is a world-readable catalog or a privilege-inquiry
        function (``pg_roles``, ``pg_class``, ``pg_policy``,
        ``has_table_privilege``, ``has_schema_privilege``, ``pg_has_role``),
        so any login role can answer it. A refused read leaves its section
        unreadable with the reason; it never reads as "no grants".

        The retrieval principal is the declared ``retrieval_role``, or else
        the role VecShield connected as, flagged ``assumed``.
        """
        from datetime import datetime, timezone

        readable: dict[str, bool] = {}
        reasons: dict[str, str] = {}
        model: dict[str, Any] = {
            "engine": "postgresql", "observed_as": None, "retrieval_principal": None,
            "tables": [], "schemas": [], "functions": {},
            "sections_readable": readable, "reasons": reasons,
            "inventory_complete": False,
            "observed_at": datetime.now(timezone.utc).isoformat()}

        me = self._role_facts(None)
        readable["roles"] = me is not None and "error" not in me
        if me is None or "error" in me:
            reasons["roles"] = ("pg_roles could not be read ("
                                f"{me['error'] if me else 'no row for current_user'})")
            return model
        model["observed_as"] = {k: me[k] for k in ("principal", "superuser", "bypassrls",
                                                   "createrole")}
        declared = getattr(self, "_retrieval_role", None)
        principal = me if not declared else self._role_facts(declared)
        role_name: Optional[str] = None
        if principal is None:
            model["retrieval_principal"] = {"name": declared, "assumed": False,
                                            "exists": False}
            reasons["retrieval_principal"] = (f"the declared retrieval role '{declared}' "
                                              "does not exist in this database")
        elif "error" in principal:
            model["retrieval_principal"] = {"name": declared, "assumed": False,
                                            "exists": None}
            reasons["retrieval_principal"] = ("the declared retrieval role could not be "
                                              f"read ({principal['error']})")
        else:
            role_name = principal["principal"]
            model["retrieval_principal"] = {
                "name": role_name, "assumed": not declared, "exists": True,
                **{k: v for k, v in principal.items() if k != "principal"}}

        rows: list = []
        error: Optional[str] = None
        vector_columns: dict[str, dict[str, Any]] = {}
        try:
            vector_columns = self._vector_columns_in_scope()
        except Exception as exc:  # noqa: BLE001 - an unreadable inventory, not an empty one
            error = _describe_error(exc)
        tables = list(vector_columns)
        if tables:
            rows, error = self._catalog(
                "SELECT c.relname, pg_get_userbyid(c.relowner), c.relrowsecurity, "
                "c.relforcerowsecurity, has_table_privilege('public', c.oid, 'SELECT') "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = %s AND c.relname = ANY(%s) ORDER BY c.relname",
                (self._schema, tables))
        readable["tables"] = error is None
        if error:
            reasons["tables"] = f"the vector tables' catalog entries could not be read ({error})"
        by_table: dict[str, dict[str, Any]] = {}
        for name, owner, rls, force, public_select in rows:
            by_table[str(name)] = {"table": str(name), "owner": owner, "rls": bool(rls),
                                   "force_rls": bool(force),
                                   "public_select": bool(public_select),
                                   "policies": None, "retrieval_privileges": None}
        if by_table:
            prows, perror = self._catalog(
                "SELECT c.relname, count(p.oid) FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "LEFT JOIN pg_policy p ON p.polrelid = c.oid "
                "WHERE n.nspname = %s AND c.relname = ANY(%s) GROUP BY c.relname",
                (self._schema, list(by_table)))
            readable["policies"] = perror is None
            if perror:
                reasons["policies"] = f"pg_policy could not be read ({perror})"
            for name, count in prows:
                if str(name) in by_table:
                    by_table[str(name)]["policies"] = int(count)
        if by_table and role_name:
            grows, gerror = self._catalog(
                "SELECT c.relname, " + ", ".join(
                    f"has_table_privilege(%s, c.oid, '{p}')" for p in _TABLE_PRIVILEGES)
                + " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = %s AND c.relname = ANY(%s)",
                (*([role_name] * len(_TABLE_PRIVILEGES)), self._schema, list(by_table)))
            readable["grants"] = gerror is None
            if gerror:
                reasons["grants"] = f"table privileges could not be read ({gerror})"
            for name, *flags in grows:
                if str(name) in by_table:
                    by_table[str(name)]["retrieval_privileges"] = [
                        p for p, ok in zip(_TABLE_PRIVILEGES, flags) if ok]
        # Row security filters the rows an approximate index returns, so an
        # RLS table on HNSW/IVFFlat can come back short (never leaky).
        session, role_settings = self._ann_settings() if by_table else ({}, {})
        for name, entry in by_table.items():
            column = _primary_vector(vector_columns[name]["columns"])["column"]
            index = self._ann_index(name, column)
            if index and "error" not in index:
                entry["ann_index"] = {"index": index["index"],
                                      "index_type": index["index_type"],
                                      "metric": index["metric"]}
                entry["iterative_scan"] = _effective_iterative_scan(
                    index["index_type"], session, role_settings)
        model["tables"] = [by_table[t] for t in sorted(by_table)]

        srows, serror = self._catalog(
            "SELECT n.nspname, has_schema_privilege('public', n.oid, 'CREATE'), "
            "EXISTS (SELECT 1 FROM pg_extension e WHERE e.extname = 'vector' "
            "AND e.extnamespace = n.oid), n.nspname = ANY(current_schemas(false)) "
            "FROM pg_namespace n WHERE n.nspname = ANY(current_schemas(false)) "
            "OR n.oid IN (SELECT extnamespace FROM pg_extension WHERE extname = 'vector') "
            "ORDER BY n.nspname")
        readable["schemas"] = serror is None
        if serror:
            reasons["schemas"] = f"schema privileges could not be read ({serror})"
        model["schemas"] = [
            {"schema": str(name), "public_create": bool(create),
             "uses": [use for use, on in (("vector_extension", ext), ("search_path", path))
                      if on]}
            for name, create, ext, path in srows]

        functions = self._function_facts(role_name)
        readable["functions"] = "error" not in functions
        if "error" in functions:
            reasons["functions"] = functions.pop("error")
        model["functions"] = functions
        model["inventory_complete"] = (all(readable.values())
                                       and model["retrieval_principal"]["exists"] is True)
        return model

    def _role_facts(self, name: Optional[str]) -> Optional[dict[str, Any]]:
        """A role's attributes and the privileged roles it is a member of.

        ``name=None`` is the connecting role. None when the role does not
        exist; ``{"error": ...}`` when pg_roles could not be read. Membership
        is ``pg_has_role(..., 'MEMBER')``, direct or inherited.
        """
        where = "r.rolname = current_user" if name is None else "r.rolname = %s"
        rows, error = self._catalog(
            "SELECT r.rolname, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcanlogin, "
            "ARRAY(SELECT g.rolname FROM pg_roles g WHERE g.oid <> r.oid AND g.rolsuper "
            "AND pg_has_role(r.oid, g.oid, 'MEMBER') ORDER BY 1), "
            "ARRAY(SELECT g.rolname FROM pg_roles g WHERE g.oid <> r.oid AND g.rolbypassrls "
            "AND pg_has_role(r.oid, g.oid, 'MEMBER') ORDER BY 1) "
            f"FROM pg_roles r WHERE {where}", () if name is None else (name,))
        if error:
            return {"error": error}
        if not rows:
            return None
        rolname, sup, bypass, createrole, login, via_super, via_bypass = rows[0]
        return {"principal": str(rolname), "superuser": bool(sup),
                "bypassrls": bool(bypass), "createrole": bool(createrole),
                "can_login": bool(login),
                "member_of_superuser": [str(r) for r in via_super or []],
                "member_of_bypassrls": [str(r) for r in via_bypass or []]}

    def _function_facts(self, role: Optional[str]) -> dict[str, Any]:
        """SECURITY DEFINER functions the retrieval role may call, and LEAKPROOF ones.

        Facts only; no rule judges them yet. A SECURITY DEFINER function runs
        with its owner's rights, so one owned by a superuser widens what the
        retrieval role can reach. pgvector marks none of its functions
        LEAKPROOF, so the planner applies its operators after row security.
        """
        leak, error = self._catalog(
            "SELECT count(*) FROM pg_proc p JOIN pg_depend d ON d.objid = p.oid "
            "AND d.classid = 'pg_proc'::regclass AND d.deptype = 'e' "
            "JOIN pg_extension e ON e.oid = d.refobjid "
            "WHERE e.extname = 'vector' AND p.proleakproof")
        if error:
            return {"error": f"pg_proc could not be read ({error})"}
        out: dict[str, Any] = {"vector_leakproof_functions": int(leak[0][0]) if leak else 0}
        if role:
            rows, error = self._catalog(
                "SELECT n.nspname, p.proname, pg_get_userbyid(p.proowner), o.rolsuper "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "JOIN pg_roles o ON o.oid = p.proowner "
                "WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND has_function_privilege(%s, p.oid, 'EXECUTE') "
                "ORDER BY 1, 2 LIMIT 50", (role,))
            if error:
                return {"error": f"function privileges could not be read ({error})"}
            out["security_definer_executable"] = [
                {"function": f"{schema}.{name}", "owner": owner,
                 "owner_superuser": bool(sup)} for schema, name, owner, sup in rows]
        return out

    def _vector_columns_in_scope(self) -> dict[str, dict[str, Any]]:
        table_filter = getattr(self, "_table_filter", None)
        return {t: info for t, info in self._vector_columns().items()
                if not table_filter or t in table_filter}

    def tls_enforcement_info(self) -> dict[str, Any]:
        rows, error = self._catalog(
            "SELECT line_number, type, database, user_name, address, netmask, "
            "auth_method, error FROM pg_hba_file_rules ORDER BY line_number")
        if error:
            return {"plaintext_accepted": None, "method": "catalog",
                    "source": "pg_hba_file_rules", "readable": False, "evidence": {},
                    "reason": f"pg_hba_file_rules is not readable by this role ({error}); "
                              "it is superuser-only unless granted"}
        verdict = hba_plaintext_verdict(rows)
        return {"method": "catalog", "source": "pg_hba_file_rules", "readable": True,
                **verdict}

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """EDB TDE for the cluster, or Percona pg_tde for each table and what it stores.

        pg_tde is per relation: a table is enabled only if the table, every
        partition, every index and every TOAST relation report encrypted, and
        disabled if any of them does not. Without either, Postgres reports
        nothing about storage encryption; the hosting provider is identified
        (never as evidence) only to say what to supply instead.
        """
        edb_version, edb_error = self._edb_tde_version()
        if edb_version is not None and edb_version > 0:
            return AtRestObservation(
                state="enabled", scope="store", collection=collection,
                source="pg_control_init.data_encryption_version",
                mechanism="EDB transparent data encryption (cluster-wide)",
                reason="the cluster was initialised with transparent data encryption",
                evidence={"data_encryption_version": edb_version})

        tde_rows, tde_error = self._catalog(
            "SELECT extversion FROM pg_extension WHERE extname = 'pg_tde'")
        if tde_rows:
            return self._pg_tde_state(collection, tde_rows[0][0])

        if edb_version == 0:
            return AtRestObservation(
                state="disabled", scope="store", collection=collection,
                source="pg_control_init.data_encryption_version",
                evidence={"data_encryption_version": 0},
                reason="this EDB cluster reports transparent data encryption off. "
                       "Volume or disk encryption beneath it is not visible here")

        provider = self._provider_hint()
        reason, supply, default = _PROVIDER_EXPLANATIONS[provider]
        evidence: dict[str, Any] = {"provider_hint": provider,
                                    "provider_hint_note": "identification only, not "
                                                          "evidence of encryption"}
        notes = {k: v for k, v in (("edb_tde", edb_error), ("pg_tde", tde_error)) if v}
        if notes:
            evidence["errors"] = notes
        return AtRestObservation(
            state="not_observable", scope="store", collection=collection,
            source=None, evidence=evidence, reason=reason,
            evidence_to_supply=list(supply),
            documented_default=dict(default) if default else None)

    def _pg_tde_state(self, collection: Optional[str], version: Any) -> AtRestObservation:
        wal_rows, _ = self._catalog("SHOW pg_tde.wal_encrypt")
        evidence: dict[str, Any] = {
            "pg_tde_version": version,
            "wal_encrypt": wal_rows[0][0] if wal_rows else None,
            "not_covered": "temporary files and statistics are not covered by pg_tde"}
        if collection is None:
            return AtRestObservation(
                state="not_observable", scope="store", source="pg_tde",
                per_collection=True, evidence=evidence,
                reason="pg_tde encrypts table by table; each table is reported "
                       "separately")
        relations = self._storage_relations(collection)
        results: dict[str, list[str]] = {"encrypted": [], "unencrypted": [], "unknown": []}
        kinds: dict[str, int] = {}
        errors: list[str] = []
        for name, kind in relations:
            kinds[kind] = kinds.get(kind, 0) + 1
            rows, error = self._catalog("SELECT pg_tde_is_encrypted(%s)", (name,))
            if error:
                errors.append(error)
                results["unknown"].append(name)
            elif not rows or rows[0][0] is None:
                results["unknown"].append(name)
            else:
                results["encrypted" if rows[0][0] else "unencrypted"].append(name)
        evidence.update(relations_checked=kinds,
                        unencrypted_relations=results["unencrypted"][:10])
        if results["unencrypted"]:
            return AtRestObservation(
                state="disabled", scope="collection", collection=collection,
                source="pg_tde", evidence=evidence,
                reason=f"pg_tde is installed but {len(results['unencrypted'])} of "
                       f"{len(relations)} relation(s) storing this table (table, "
                       "partitions, indexes, TOAST) are not encrypted")
        if results["unknown"]:
            return AtRestObservation(
                state="error" if errors else "not_observable", scope="collection",
                collection=collection, source="pg_tde", evidence=evidence,
                reason=(f"pg_tde_is_encrypted() failed ({errors[0]})" if errors
                        else "pg_tde_is_encrypted() returned no answer"))
        return AtRestObservation(
            state="enabled", scope="collection", collection=collection, source="pg_tde",
            mechanism="pg_tde (tde_heap access method)", evidence=evidence,
            reason="pg_tde reports the table, its partitions, indexes and TOAST "
                   "encrypted")

    def _storage_relations(self, table: str) -> list[tuple[str, str]]:
        """(regclass text, role) for every relation holding this table's data.

        Partitioned parents and partitioned indexes have no storage of their
        own and are skipped; their partitions are what pg_tde encrypts.
        """
        rows, error = self._catalog(
            "WITH RECURSIVE tree(oid) AS ("
            " SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = %s AND c.relname = %s"
            " UNION ALL SELECT i.inhrelid FROM pg_inherits i JOIN tree t ON i.inhparent = t.oid)"
            " SELECT c.oid::regclass::text, 'table' FROM tree t JOIN pg_class c ON c.oid = t.oid"
            " WHERE c.relkind IN ('r', 'm')"
            " UNION ALL SELECT x.indexrelid::regclass::text, 'index' FROM tree t"
            " JOIN pg_index x ON x.indrelid = t.oid"
            " JOIN pg_class ic ON ic.oid = x.indexrelid WHERE ic.relkind = 'i'"
            " UNION ALL SELECT c.reltoastrelid::regclass::text, 'toast' FROM tree t"
            " JOIN pg_class c ON c.oid = t.oid WHERE c.reltoastrelid <> 0",
            (self._schema, table))
        if error or not rows:
            return [(f"{_quote_ident(self._schema)}.{_quote_ident(table)}", "table")]
        return [(str(r[0]), str(r[1])) for r in rows]

    def _provider_hint(self) -> str:
        """Which managed service hosts this database, from its settings names.

        Used only to choose what to ask the customer for. It is never evidence
        that anything is encrypted.
        """
        rows, _ = self._catalog(
            "SELECT name FROM pg_settings WHERE name LIKE 'rds.%' OR name LIKE "
            "'azure.%' OR name LIKE 'cloudsql.%' OR name LIKE 'alloydb.%' LIMIT 50")
        names = [str(r[0]).lower() for r in rows]
        if any(n.startswith("rds.") for n in names):
            return "aws_rds"
        if any(n.startswith("azure.") for n in names):
            return "azure"
        if any(n.startswith("alloydb.") for n in names):
            return "alloydb"
        if any(n.startswith("cloudsql.") for n in names):
            return "cloud_sql"
        return "self_managed"

    def _edb_tde_version(self) -> tuple[Optional[int], Optional[str]]:
        """EDB TDE's data_encryption_version, or None where the column is absent.

        The column is checked in pg_proc first so community Postgres — where
        pg_control_init() exists without it — never sees a failing statement.
        """
        rows, error = self._catalog(
            "SELECT proargnames FROM pg_proc WHERE proname = 'pg_control_init'")
        if error or not rows:
            return None, error
        names = rows[0][0] or []
        if isinstance(names, str):
            names = names.strip("{}").split(",")
        if "data_encryption_version" not in names:
            return None, None
        rows, error = self._catalog("SELECT data_encryption_version FROM pg_control_init()")
        if error or not rows or rows[0][0] is None:
            return None, error
        try:
            return int(rows[0][0]), None
        except (TypeError, ValueError):
            return None, "unreadable data_encryption_version"

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # pragma: no cover
            pass

    # ----------------------------- catalog ---------------------------- #

    def _vector_columns(self) -> dict[str, dict[str, Any]]:
        """``{table: {"readable", "columns"}}`` for every pgvector table."""
        rows = self._read(_VECTOR_COLUMNS_SQL, (self._schema,))
        return group_vector_columns(rows)

    def _text_column(self, table: str) -> Optional[str]:
        sql = """
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s
              AND data_type IN ('text', 'character varying', 'character', 'varchar')
        """
        cols = {r[0]: r[1] for r in self._read(sql, (self._schema, table))}
        if not cols:
            return None
        for pref in _TEXT_NAME_PREFERENCE:
            if pref in cols:
                return pref
        return next(iter(cols))  # any text column

    def _primary_key(self, table: str) -> list[tuple[str, str]]:
        """Every primary-key column with its type, in key order."""
        sql = """
            SELECT a.attname, format_type(a.atttypid, a.atttypmod)
            FROM pg_index i
            CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
            JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
            JOIN pg_class c     ON c.oid = i.indrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE i.indisprimary AND c.relname = %s AND n.nspname = %s
            ORDER BY k.ord
        """
        return [(str(r[0]), str(r[1])) for r in self._read(sql, (table, self._schema))]

    def _first_column(self, table: str) -> list[tuple[str, str]]:
        sql = """
            SELECT a.attname, format_type(a.atttypid, a.atttypmod)
            FROM pg_attribute a
            JOIN pg_class c     ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = %s AND n.nspname = %s
              AND a.attnum > 0 AND NOT a.attisdropped
            ORDER BY a.attnum LIMIT 1
        """
        return [(str(r[0]), str(r[1])) for r in self._read(sql, (table, self._schema))]

    def _all_columns(self, table: str) -> list[str]:
        sql = """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s
            ORDER BY ordinal_position
        """
        return [r[0] for r in self._read(sql, (self._schema, table))]

    def _metadata_columns(self, table: str, lay: dict[str, Any]) -> list[str]:
        """Columns surfaced as chunk metadata: everything but key/text/vector.

        Every vector column is left out, not only the one read as the
        embedding: vector literals are not metadata.
        """
        if table not in self._meta_cols:
            exclude = set(lay["key_cols"])
            exclude.update(c["column"] for c in lay["vector_columns"])
            if lay["text"]:
                exclude.add(lay["text"])
            self._meta_cols[table] = [
                c for c in self._all_columns(table) if c not in exclude
            ]
        return self._meta_cols[table]



def pg_transport_config(dsn: Optional[str], sslmode: Optional[str]) -> dict[str, Any]:
    """The effective sslmode and where it came from, without the DSN itself.

    Precedence follows libpq: an explicit keyword beats the DSN, and the DSN
    beats ``PGSSLMODE``. With none of them libpq uses ``prefer``, which falls
    back to plaintext silently — recorded as ``sslmode=None`` so the posture
    check calls it unverified rather than encrypted.
    """
    if sslmode:
        return {"sslmode": sslmode.lower(), "source": "connector_flag"}
    if dsn:
        m = re.search(r"sslmode\s*=\s*([A-Za-z-]+)", dsn)
        if m:
            return {"sslmode": m.group(1).lower(), "source": "dsn"}
    env = os.environ.get("PGSSLMODE")
    if env:
        return {"sslmode": env.lower(), "source": "environment"}
    return {"sslmode": None, "source": None}


def pg_credential_config(dsn: Optional[str], password: Optional[str]) -> dict[str, Any]:
    """Which credential sources libpq was given: their names, never their values.

    A keyword DSN or host/port settings carry no ``user:password@`` for the
    authentication check to see, so the sources are listed here instead.
    """
    sources: list[str] = []
    text = dsn or ""
    if password:
        sources.append("password_option")
    if (re.search(r"(?:^|[\s?&])password\s*=", text)
            or re.search(r"://[^/@\s]*:[^/@\s]*@", text)):
        sources.append("dsn_password")
    if os.environ.get("PGPASSWORD"):
        sources.append("environment_password")
    if (re.search(r"(?:^|[\s?&])passfile\s*=", text) or os.environ.get("PGPASSFILE")
            or _default_passfile().is_file()):
        sources.append("password_file")
    if re.search(r"(?:^|[\s?&])sslcert\s*=", text) or os.environ.get("PGSSLCERT"):
        sources.append("client_certificate")
    return {"sources": sources}


def _default_passfile() -> Path:
    """libpq's default password file location."""
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", "")) / "postgresql" / "pgpass.conf"
    return Path.home() / ".pgpass"


#: provider hint -> (not-observable reason, evidence to supply, documented default)
_PROVIDER_EXPLANATIONS: dict[str, tuple[str, tuple[str, ...], Optional[dict[str, str]]]] = {
    "aws_rds": (
        "Amazon RDS reports storage encryption only through the AWS API, not SQL. "
        "Provide StorageEncrypted and KmsKeyId from DescribeDBInstances or "
        "DescribeDBClusters.",
        ("StorageEncrypted and KmsKeyId from DescribeDBInstances or DescribeDBClusters",),
        None),
    "azure": (
        "Azure Database for PostgreSQL encrypts storage, but reports it only through "
        "Azure, not SQL. Provide the server's dataEncryption setting.",
        ("The server's dataEncryption setting (service-managed or customer-managed key)",),
        {"text": "Microsoft documents that Azure Database for PostgreSQL always "
                 "encrypts all data at rest.",
         "source_url": "https://learn.microsoft.com/azure/postgresql/security/"
                       "security-data-encryption"}),
    "cloud_sql": (
        "Google encrypts this database by default, but reports it only through the "
        "Cloud SQL API. Provide the instance's encryption configuration.",
        ("The Cloud SQL instance's encryption configuration (CMEK key name, if any)",),
        {"text": "Google documents that Cloud SQL encrypts customer content at rest "
                 "by default.",
         "source_url": "https://docs.cloud.google.com/sql/docs/postgres/cmek"}),
    "alloydb": (
        "Google encrypts this database by default, but reports it only through the "
        "AlloyDB API. Provide the cluster's encryption configuration.",
        ("The AlloyDB cluster's encryption configuration (CMEK key name, if any)",),
        {"text": "Google documents that AlloyDB encrypts customer content at rest "
                 "by default.",
         "source_url": "https://docs.cloud.google.com/alloydb/docs/cmek"}),
    "self_managed": (
        "PostgreSQL does not report disk or storage encryption to database "
        "connections. Provide your host's volume-encryption configuration or your "
        "provider's encryption setting.",
        ("The database host's volume-encryption configuration (LUKS, EBS, or the "
         "provider's setting)",),
        None),
}


_PLAINTEXT_HBA_TYPES = ("host", "hostnossl", "hostnogssenc")
_ENCRYPTED_HBA_TYPES = ("hostssl", "hostgssenc")


def _families(address: Optional[str], netmask: Optional[str]) -> set[str]:
    addr = (address or "").lower()
    if ":" in addr or ":" in (netmask or ""):
        return {"v6"}
    if re.fullmatch(r"[0-9.]+", addr):
        return {"v4"}
    return {"v4", "v6"}  # all, samenet, host names


def _is_loopback(address: Optional[str], netmask: Optional[str]) -> bool:
    addr = (address or "").lower()
    mask = (netmask or "").lower()
    if addr in ("samehost", "localhost", "::1"):
        return True
    if addr.startswith("127.") and mask.startswith("255."):
        return True
    return False


def _is_blanket(address: Optional[str], netmask: Optional[str]) -> bool:
    addr = (address or "").lower()
    return addr == "all" or (addr in ("0.0.0.0", "::") and (netmask or "") in ("0.0.0.0", "::"))


def _covers_all(values: Any) -> bool:
    if isinstance(values, str):
        values = values.strip("{}").split(",")
    return list(values or []) == ["all"]


def hba_plaintext_verdict(rows: list) -> dict[str, Any]:
    """Decide from pg_hba rules whether a non-local plaintext client is accepted.

    ``rows`` are ``(line_number, type, database, user_name, address, netmask,
    auth_method, error)`` in file order. pg_hba is first-match, so a blanket
    ``hostnossl … reject`` (or ``host … reject``) earlier in the file shuts
    plaintext out for the address family it covers. Loopback-only rules do
    not count: plaintext over loopback never crosses a network. A file with
    parse errors is not trusted — the server keeps its previously loaded rules.

    Returns ``{"plaintext_accepted": bool|None, "reason": str, "evidence": {...}}``
    where the evidence lists rule line numbers and types, not the whole file.
    """
    covered: set[str] = set()
    accepting: list[dict[str, Any]] = []
    encrypted_rules = 0
    errors: list[int] = []
    for row in rows:
        line, kind, database, users, address, netmask, method, error = row[:8]
        if error:
            errors.append(line)
            continue
        kind = (kind or "").lower()
        method = (method or "").lower()
        if kind in _ENCRYPTED_HBA_TYPES:
            if method != "reject":
                encrypted_rules += 1
            continue
        if kind not in _PLAINTEXT_HBA_TYPES:
            continue  # local (Unix socket) rules
        families = _families(address, netmask)
        if method == "reject":
            if _is_blanket(address, netmask) and _covers_all(database) and _covers_all(users):
                covered |= families
            continue
        if _is_loopback(address, netmask):
            continue
        if families <= covered:
            # Plaintext clients were already rejected above; this rule can
            # only admit encrypted ones.
            encrypted_rules += 1
            continue
        accepting.append({"line": line, "type": kind, "auth_method": method})

    evidence = {"rules_accepting_plaintext": accepting[:10],
                "encrypted_rules": encrypted_rules,
                "weak_auth_rules": hba_weak_auth_rules(rows),
                "note": "pg_hba_file_rules shows the file on disk; a pending reload "
                        "can differ from the rules the server has loaded"}
    if errors:
        return {"plaintext_accepted": None, "evidence": {**evidence, "error_lines": errors},
                "reason": "pg_hba.conf has lines the server could not parse, so the "
                          "rules it is enforcing cannot be read from the file"}
    if accepting:
        first = accepting[0]
        return {"plaintext_accepted": True, "evidence": evidence,
                "reason": f"pg_hba.conf line {first['line']} ({first['type']}) accepts "
                          "non-local connections without TLS"}
    if encrypted_rules:
        return {"plaintext_accepted": False, "evidence": evidence,
                "reason": "every non-local pg_hba.conf rule that admits a client "
                          "requires an encrypted connection"}
    return {"plaintext_accepted": None, "evidence": evidence,
            "reason": "pg_hba.conf admits no non-local TCP clients, so there is no "
                      "network path to enforce TLS on"}


#: pg_hba methods that authenticate nobody (trust) or weakly (md5, password).
WEAK_HBA_METHODS = ("trust", "md5", "password")


def hba_weak_auth_rules(rows: list) -> list[dict[str, Any]]:
    """Non-local pg_hba rules whose method is trust, md5 or password.

    Rows as for :func:`hba_plaintext_verdict`. Every TCP connection type
    counts, encrypted ones included: TLS does not make trust authenticate
    anyone. Loopback-only and unparsable lines are left out. Line numbers and
    methods only; addresses and user names stay in the file.
    """
    weak: list[dict[str, Any]] = []
    for row in rows:
        line, kind, _database, _users, address, netmask, method, error = row[:8]
        kind = (kind or "").lower()
        method = (method or "").lower()
        if error or kind == "local" or method not in WEAK_HBA_METHODS:
            continue
        if _is_loopback(address, netmask):
            continue
        weak.append({"line": line, "type": kind, "auth_method": method})
    return weak[:20]


def _opclass_operator(opclass: str) -> tuple[Optional[str], Optional[str]]:
    for suffix, metric, operator in _OPCLASS_OPERATORS:
        if opclass.endswith(suffix):
            return metric, operator
    return None, None


def _effective_iterative_scan(index_type: str, session: dict[str, str],
                              role_settings: dict[str, str]) -> Optional[str]:
    """The retrieval role's own setting when it has one, else this session's."""
    name = f"{index_type}.iterative_scan"
    return role_settings.get(name) or session.get(name)


def _version_at_least(version: Optional[str], minimum: tuple[int, ...]) -> bool:
    parts = re.findall(r"\d+", version or "")
    if not parts:
        return False
    return tuple(int(p) for p in parts[:3]) >= minimum


def _describe_error(exc: BaseException) -> str:
    """Short, credential-free description of a database error."""
    name = type(exc).__name__
    code = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    if code == "42501" or "permission denied" in str(exc).lower():
        return f"{name}: permission denied"
    return f"{name} ({code})" if code else name


def _parse_vector(raw) -> Optional[list[float]]:
    """A dense ``vector`` / ``halfvec`` value as floats.

    Without an adapter registered both come back as text, ``'[0.1,0.2,...]'``.
    With pgvector-python's adapters they are objects with ``to_list()``.
    Only dense values are passed here: ``sparsevec`` text (``{1:0.5}/3``) and
    ``bit`` strings are never read as a dense vector.
    """
    if raw is None:
        return None
    to_list = getattr(raw, "to_list", None) or getattr(raw, "tolist", None)
    if callable(to_list) and not isinstance(raw, (str, bytes)):
        raw = to_list()
    if isinstance(raw, (list, tuple)):
        try:
            return [float(x) for x in raw]
        except (TypeError, ValueError):
            return None
    if isinstance(raw, str):
        s = raw.strip()
        if not (s.startswith("[") and s.endswith("]")):
            return None
        s = s[1:-1].strip()
        if not s:
            return None
        try:
            return [float(x) for x in s.split(",")]
        except ValueError:
            return None
    return None


#: A type name format_type() produced that is safe to put after ``::``:
#: identifiers (quoted or not), schema dots, spaces and a typmod in brackets.
#: Anything else (an array type, odd characters) falls back to text.
_SAFE_TYPE = re.compile(r'[A-Za-z_"][A-Za-z0-9_ ."]*(\([0-9, ]*\))?')


def _safe_type(type_name: Any) -> Optional[str]:
    """``type_name`` if it can be used as a cast target as is, else None."""
    text = str(type_name or "").strip()
    if not text or not _SAFE_TYPE.fullmatch(text) or text.count('"') % 2:
        return None
    return text


def _compose_id(values: list) -> str:
    """The chunk id for a row: the key as text, or a JSON array for a composite key."""
    if len(values) == 1:
        return str(values[0])
    return json.dumps([None if v is None else str(v) for v in values],
                      separators=(",", ":"))


def _split_id(chunk_id: Any, arity: int) -> tuple:
    """Parse a composite-key chunk id back into its key values (as text)."""
    try:
        values = json.loads(str(chunk_id))
    except ValueError:
        values = None
    if not isinstance(values, list) or len(values) != arity or any(
            not isinstance(v, str) for v in values):
        raise ValueError(
            f"chunk id {chunk_id!r} is not a {arity}-column key of this table")
    return tuple(values)


def _redact_dsn(dsn: str) -> str:
    """Mask credentials in a DSN before using it as a display name.

    Handles URL userinfo (including a password holding ``@``), password
    query parameters and libpq keyword DSNs (``password=...``). The common
    ``postgresql://user:pw@host/db`` form redacts exactly as before
    (``user:***@host``), so fingerprints keyed on it are unchanged.
    """
    return redact_credentials(dsn)


def _quote_ident(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'
