"""Persistent scan history backed by SQLite.

Stores every ScanJob (and its Findings) produced by run_full_audit or any
manual scan. Enables:
  - dashboard history view (list of past scans, severity trends)
  - scheduled-scan baseline comparisons
  - evidence export for auditors

The DB is a single SQLite file, auto-created on first use. All writes are
wrapped in transactions and use the WAL journal mode for concurrent reads.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from vecshield.models import ScanJob
from vecshield_platform.compliance.fingerprint import fingerprint_finding


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    store       TEXT NOT NULL,
    kind        TEXT,
    started_at  TEXT,
    finished_at TEXT,
    max_severity TEXT,
    stats       TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    job_id      TEXT NOT NULL,
    store       TEXT,
    collection  TEXT,
    category    TEXT,
    severity    TEXT,
    title       TEXT,
    description TEXT,
    evidence    TEXT,
    remediation TEXT,
    created_at  TEXT,
    fingerprint TEXT,
    suppressed  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE INDEX IF NOT EXISTS ix_findings_job  ON findings(job_id);
CREATE INDEX IF NOT EXISTS ix_findings_sev  ON findings(severity);
CREATE INDEX IF NOT EXISTS ix_findings_cat  ON findings(category);
CREATE INDEX IF NOT EXISTS ix_jobs_store    ON jobs(store);
CREATE INDEX IF NOT EXISTS ix_jobs_created  ON jobs(created_at);

CREATE TABLE IF NOT EXISTS dsars (
    id           TEXT PRIMARY KEY,
    subject      TEXT NOT NULL,
    status       TEXT NOT NULL,
    requested_at TEXT,
    executed_at  TEXT,
    notes        TEXT,
    record_json  TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS ix_dsars_status    ON dsars(status);
CREATE INDEX IF NOT EXISTS ix_dsars_created   ON dsars(created_at);

CREATE TABLE IF NOT EXISTS async_jobs (
    id          TEXT PRIMARY KEY,
    kind        TEXT,
    status      TEXT NOT NULL,
    actor       TEXT,
    resource    TEXT,
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    result      TEXT,
    error       TEXT
);

CREATE INDEX IF NOT EXISTS ix_async_jobs_status  ON async_jobs(status);
CREATE INDEX IF NOT EXISTS ix_async_jobs_created ON async_jobs(created_at);

CREATE TABLE IF NOT EXISTS audit_snapshots (
    id TEXT PRIMARY KEY,
    store_id TEXT NOT NULL,
    store TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    report_html TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audits_store ON audit_snapshots(store_id, finished_at);
"""


class ScanHistory:
    """Thread-safe SQLite-backed scan job store."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self._path = str(db_path)
        self._subject_salt: Optional[bytes] = None
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after the initial schema to pre-existing DBs.

        ``CREATE TABLE IF NOT EXISTS`` never alters an existing table, so older
        history files created before the ``fingerprint`` column must be patched
        in place. ``ADD COLUMN`` is a cheap metadata-only change in SQLite.
        """
        cols = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(findings)").fetchall()}
        if "fingerprint" not in cols:
            self._conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT")
        if "suppressed" not in cols:
            self._conn.execute(
                "ALTER TABLE findings ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_findings_fp ON findings(fingerprint)")
        job_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(jobs)")}
        if "audit_id" not in job_cols:
            self._conn.execute("ALTER TABLE jobs ADD COLUMN audit_id TEXT")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_jobs_audit ON jobs(audit_id)")
        # Who opened a DSAR, so executing it can require a second person.
        dsar_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(dsars)")}
        if "created_by" not in dsar_cols:
            self._conn.execute("ALTER TABLE dsars ADD COLUMN created_by TEXT")
        # Case state lives beside the finding, and its trail in its own table.
        # A case is what people decided; a finding is what a scan saw.
        finding_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(findings)")}
        if "case_state" not in finding_cols:
            self._conn.execute(
                "ALTER TABLE findings ADD COLUMN case_state TEXT NOT NULL DEFAULT 'new'")
        if "case_owner" not in finding_cols:
            self._conn.execute("ALTER TABLE findings ADD COLUMN case_owner TEXT")
        if "case_reason" not in finding_cols:
            self._conn.execute("ALTER TABLE findings ADD COLUMN case_reason TEXT")
        if "case_updated_at" not in finding_cols:
            self._conn.execute("ALTER TABLE findings ADD COLUMN case_updated_at TEXT")
        if "case_verified_by" not in finding_cols:
            self._conn.execute("ALTER TABLE findings ADD COLUMN case_verified_by TEXT")
        # A self-approval is recorded as one, so both approval tables carry the
        # flag; older history files gain the column in place.
        for table_name, extra in (("action_approvals", ("self_approved INTEGER NOT NULL DEFAULT 0",
                                                        "separation_of_duties TEXT NOT NULL DEFAULT 'required'")),
                                  ("risk_exceptions", ("self_approved INTEGER NOT NULL DEFAULT 0",))):
            if not self._conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table_name,)).fetchone():
                continue
            have = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table_name})")}
            for column in extra:
                if column.split()[0] not in have:
                    self._conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column}")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS finding_case_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            at TEXT NOT NULL,
            from_state TEXT NOT NULL,
            to_state TEXT NOT NULL,
            owner TEXT,
            reason TEXT,
            verified_by_job_id TEXT
        )""")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_case_events ON finding_case_events(finding_id, at)")

        # Where each data subject was observed. Holds a keyed hash and a
        # location, never an identifier — see subject_index.py for why the key
        # lives outside this database. The uniqueness constraint makes a
        # re-scan idempotent rather than accumulating a row per run.
        self._conn.execute("""CREATE TABLE IF NOT EXISTS subject_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_key TEXT NOT NULL,
            store_id TEXT NOT NULL,
            collection TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            detector TEXT NOT NULL,
            surface TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            scan_id TEXT,
            coverage_complete INTEGER NOT NULL DEFAULT 0,
            UNIQUE(subject_key, store_id, collection, chunk_id, detector)
        )""")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_subject_key ON subject_index(subject_key)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_subject_store ON subject_index(store_id, collection)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_findings_case ON findings(case_state)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_findings_owner ON findings(case_owner)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_findings_sev ON findings(severity)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_findings_store ON findings(store)")

        # Evidence, its reviews, and the exceptions attached to gaps. Three
        # tables because they are three different assertions.
        self._conn.execute("""CREATE TABLE IF NOT EXISTS evidence_artifacts (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, media_type TEXT,
            state TEXT NOT NULL DEFAULT 'collected', content_hash TEXT,
            size_bytes INTEGER, collector TEXT, collected_at TEXT, scope TEXT,
            period_start TEXT, period_end TEXT, supersedes TEXT, note TEXT
        )""")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS evidence_reviews (
            id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, criterion_id TEXT NOT NULL,
            scope TEXT, period TEXT, state TEXT NOT NULL DEFAULT 'requested',
            reviewer TEXT, reason TEXT, decided_at TEXT, requirement TEXT
        )""")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS risk_exceptions (
            id TEXT PRIMARY KEY, criterion_id TEXT NOT NULL, scope TEXT NOT NULL,
            rationale TEXT NOT NULL, requested_by TEXT NOT NULL, expires_at TEXT NOT NULL,
            approved_by TEXT, approved_at TEXT, revoked_at TEXT, created_at TEXT,
            self_approved INTEGER NOT NULL DEFAULT 0
        )""")
        # A staged action plan, frozen. The body is stored as written and the
        # hash alongside it, so a plan that was altered in the database no
        # longer matches its own hash and is refused rather than executed.
        self._conn.execute("""CREATE TABLE IF NOT EXISTS action_plans (
            id TEXT PRIMARY KEY, store TEXT NOT NULL, staged_by TEXT NOT NULL,
            staged_at TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'staged',
            plan_hash TEXT NOT NULL, store_fingerprint TEXT NOT NULL,
            note TEXT, body TEXT NOT NULL
        )""")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_plans_store ON action_plans(store, staged_at)")
        # Approvals and executions are separate rows from the plan, and from
        # each other. An approval that was given is a fact about a person; an
        # execution is a fact about a store. Folding them into plan columns
        # would make it impossible to record an approval that was never acted
        # on, which is a thing that happens and should stay visible.
        self._conn.execute("""CREATE TABLE IF NOT EXISTS action_approvals (
            id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, plan_hash TEXT NOT NULL,
            approver TEXT NOT NULL, reason TEXT NOT NULL, approved_at TEXT NOT NULL,
            typed_store_id TEXT, operations TEXT,
            self_approved INTEGER NOT NULL DEFAULT 0,
            separation_of_duties TEXT NOT NULL DEFAULT 'required'
        )""")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS action_executions (
            id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, approval_id TEXT NOT NULL,
            store TEXT NOT NULL, executed_by TEXT NOT NULL, started_at TEXT NOT NULL,
            finished_at TEXT, halted INTEGER NOT NULL DEFAULT 0,
            safe_mode INTEGER NOT NULL DEFAULT 1, body TEXT NOT NULL,
            verification TEXT
        )""")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_approvals_plan ON action_approvals(plan_id)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_executions_plan ON action_executions(plan_id)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_reviews_criterion ON evidence_reviews(criterion_id)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_exceptions_criterion ON risk_exceptions(criterion_id)")

        # A reviewer's conclusion about one criterion for one store. Append-only:
        # a changed mind is a new row, and the newest row per criterion is the
        # one that applies. The pack version and criterion digest bind the
        # decision to the wording it was made about, so a rewritten criterion
        # does not silently inherit it.
        self._conn.execute("""CREATE TABLE IF NOT EXISTS reviewer_decisions (
            id TEXT PRIMARY KEY, store_id TEXT NOT NULL, criterion_id TEXT NOT NULL,
            conclusion TEXT NOT NULL, rationale TEXT NOT NULL, reviewer TEXT NOT NULL,
            decided_at TEXT NOT NULL, audit_id TEXT, period TEXT NOT NULL DEFAULT '',
            pack_version TEXT NOT NULL, criterion_digest TEXT, seq INTEGER
        )""")
        # ``seq`` is the write order. Not the implicit rowid, which VACUUM may
        # renumber on a table without an INTEGER PRIMARY KEY.
        decision_cols = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(reviewer_decisions)")}
        if "seq" not in decision_cols:
            self._conn.execute("ALTER TABLE reviewer_decisions ADD COLUMN seq INTEGER")
        self._conn.execute("UPDATE reviewer_decisions SET seq = rowid WHERE seq IS NULL")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_decisions_store "
            "ON reviewer_decisions(store_id, criterion_id, decided_at)")
        # Applicability answers per store, also append-only; the newest answer
        # per question is the current one, and the older rows are the trail.
        self._conn.execute("""CREATE TABLE IF NOT EXISTS store_applicability (
            id INTEGER PRIMARY KEY AUTOINCREMENT, store_id TEXT NOT NULL,
            question TEXT NOT NULL, answer TEXT NOT NULL,
            answered_by TEXT NOT NULL, answered_at TEXT NOT NULL
        )""")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_applicability_store "
            "ON store_applicability(store_id, question)")
        # A store's registration ending. Decisions and answers written before
        # the newest marker belong to an earlier registration of the same id
        # and are ignored, never deleted: the rows stay as history. The
        # boundary is a write sequence, not a timestamp, so ordering is exact.
        self._conn.execute("""CREATE TABLE IF NOT EXISTS store_retirements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, store_id TEXT NOT NULL,
            retired_at TEXT NOT NULL, retired_by TEXT NOT NULL,
            decisions_through INTEGER NOT NULL DEFAULT 0,
            answers_through INTEGER NOT NULL DEFAULT 0
        )""")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_retirements_store ON store_retirements(store_id)")

        async_cols = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(async_jobs)")}
        # Ownership and liveness of a background job: a row left "running" by a
        # dead process is not evidence that work is still running.
        if "runner_id" not in async_cols:
            self._conn.execute("ALTER TABLE async_jobs ADD COLUMN runner_id TEXT")
        if "heartbeat_at" not in async_cols:
            self._conn.execute("ALTER TABLE async_jobs ADD COLUMN heartbeat_at TEXT")
        if "progress" not in async_cols:
            self._conn.execute("ALTER TABLE async_jobs ADD COLUMN progress TEXT")
        # Legacy child jobs deliberately retain a null parent; timestamps do not
        # establish run identity. This migration is additive and idempotent.

    def ping(self) -> None:
        """Cheap liveness check for readiness probes.

        Runs a trivial query to confirm the underlying SQLite connection is
        usable. Raises the underlying ``sqlite3`` error if the DB is not
        reachable.
        """
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()

    # ------------------------------------------------------------------ #
    # Write                                                                #
    # ------------------------------------------------------------------ #

    def save_job(self, job: ScanJob, *, kind: Optional[str] = None) -> None:
        """Persist a ScanJob and all its Findings atomically."""
        with self._lock:
            with self._conn:
                parent = self._conn.execute(
                    "SELECT audit_id FROM jobs WHERE id = ?", (job.id,)
                ).fetchone()
                if parent and parent["audit_id"]:
                    raise ValueError("cannot overwrite a job in an immutable audit snapshot")
                self._save_job(job, kind=kind)

    def _save_job(self, job: ScanJob, *, kind: Optional[str] = None) -> None:
        """Write within the caller's lock and transaction."""
        self._conn.execute(
            """INSERT OR REPLACE INTO jobs
               (id, store, kind, started_at, finished_at, max_severity, stats)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                job.id,
                job.store,
                kind,
                job.started_at.isoformat() if job.started_at else None,
                job.finished_at.isoformat() if job.finished_at else None,
                job.max_severity.value,
                json.dumps(job.stats),
            ),
        )
        for f in job.findings:
            self._conn.execute(
                """INSERT OR REPLACE INTO findings
                   (id, job_id, store, collection, category, severity,
                    title, description, evidence, remediation, created_at,
                    fingerprint, suppressed)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f.id,
                    job.id,
                    f.store,
                    f.collection,
                    f.category,
                    f.severity.value,
                    f.title,
                    f.description,
                    json.dumps(f.evidence),
                    f.remediation,
                    f.created_at.isoformat(),
                    (f.evidence or {}).get("fingerprint")
                    or fingerprint_finding(f),
                    1 if (f.evidence or {}).get("suppressed") else 0,
                ),
            )

    # ------------------------------------------------------------------ #
    # Read                                                                 #
    # ------------------------------------------------------------------ #

    def list_jobs(
        self,
        *,
        store: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        sql = "SELECT j.*, COUNT(f.id) AS finding_count FROM jobs j LEFT JOIN findings f ON f.job_id = j.id"
        params: list = []
        if store:
            sql += " WHERE j.store = ?"
            params.append(store)
        sql += " GROUP BY j.id ORDER BY j.created_at DESC, j.id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row(r) for r in rows]

    def get_job(self, job_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _row(row) if row else None

    def list_findings(
        self,
        *,
        store: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        job_id: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list = []
        if store:
            clauses.append("store = ?")
            params.append(store)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if job_id:
            clauses.append("job_id = ?")
            params.append(job_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM findings{where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row(r) for r in rows]

    def severity_trend(
        self,
        *,
        store: Optional[str] = None,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """Daily worst severity and recorded finding counts per store.

        ``findings`` and ``by_severity`` count every finding recorded by that
        day's runs, so re-running a scan counts its findings again. Distinct
        open findings are a different number (see the home summary).
        """
        store_clause = "AND j.store = ?" if store else ""
        params: list = []
        if store:
            params.append(store)
        params.append(days)
        sql = f"""
            SELECT date(j.created_at) AS day,
                   j.store,
                   CASE MAX(CASE j.max_severity
                       WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                       WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                       WHEN 4 THEN 'critical' WHEN 3 THEN 'high'
                       WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE 'info'
                   END AS max_severity,
                   COUNT(f.id) AS findings,
                   SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS sev_critical,
                   SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS sev_high,
                   SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS sev_medium,
                   SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS sev_low,
                   SUM(CASE WHEN f.severity = 'info' THEN 1 ELSE 0 END) AS sev_info
            FROM jobs j
            LEFT JOIN findings f ON f.job_id = j.id
            WHERE j.created_at >= date('now', '-' || ? || ' days')
              {store_clause}
            GROUP BY day, j.store
            ORDER BY day DESC, j.store
        """
        # Reorder params: days first, then store filter
        if store:
            params = [days, store]
        else:
            params = [days]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = _row(r)
            # Same basis as ``findings``: every finding recorded that day in
            # that store's runs, suppressed ones included. Not distinct.
            d["by_severity"] = {name: int(d.pop(f"sev_{name}") or 0)
                                for name in ("critical", "high", "medium", "low", "info")}
            out.append(d)
        return out

    def save_audit(self, result, *, store_id: str) -> None:
        """Freeze the parent, report, and child links in one transaction.

        Re-saving the identical snapshot is safe; rewriting an existing audit
        or reparenting an existing job is rejected. No historical grouping is
        inferred from observation times.
        """
        from vecshield_platform.compliance.report import build_audit_report

        snapshot = result.to_dict()
        snapshot["store_id"] = store_id
        serialized = json.dumps(snapshot, sort_keys=True)
        report = build_audit_report(result, title=f"VecShield — {store_id}")
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT snapshot_json FROM audit_snapshots WHERE id = ?", (result.id,)
            ).fetchone()
            if existing:
                if existing["snapshot_json"] != serialized:
                    raise ValueError("audit snapshots are immutable")
                return
            for job in result.jobs:
                if self._conn.execute("SELECT 1 FROM jobs WHERE id = ?", (job.id,)).fetchone():
                    raise ValueError("audit child job already exists")
            self._conn.execute(
                "INSERT INTO audit_snapshots VALUES (?, ?, ?, ?, ?, ?, ?)",
                (result.id, store_id, result.store, result.started_at,
                 result.finished_at, serialized, report),
            )
            for job in result.jobs:
                self._save_job(job)
                self._conn.execute("UPDATE jobs SET audit_id = ? WHERE id = ?",
                                   (result.id, job.id))

    def get_audit(self, audit_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT snapshot_json FROM audit_snapshots WHERE id = ?", (audit_id,)
            ).fetchone()
        if not row:
            return None
        from vecshield_platform.coverage import upgrade_legacy_snapshot

        # Posture jobs saved by an earlier engine carry no per-check outcomes;
        # they are rebuilt on read. The stored row is never rewritten.
        return upgrade_legacy_snapshot(json.loads(row["snapshot_json"]))

    def list_audits(self, *, store_id: Optional[str] = None, limit: int = 50,
                    offset: int = 0) -> list[dict[str, Any]]:
        where = " WHERE store_id = ?" if store_id else ""
        params = ([store_id] if store_id else []) + [limit, offset]
        with self._lock:
            rows = self._conn.execute(
                "SELECT snapshot_json FROM audit_snapshots" + where +
                " ORDER BY finished_at DESC, id DESC LIMIT ? OFFSET ?", params,
            ).fetchall()
        return [{key: value for key, value in json.loads(row[0]).items()
                 if key not in {"jobs", "violations", "scope", "check_outcomes"}}
                for row in rows]

    def get_audit_report(self, *, store_id: str,
                         audit_id: Optional[str] = None) -> Optional[str]:
        where = "store_id = ?" + (" AND id = ?" if audit_id else "")
        params = [store_id] + ([audit_id] if audit_id else [])
        with self._lock:
            row = self._conn.execute(
                "SELECT report_html FROM audit_snapshots WHERE " + where +
                " ORDER BY finished_at DESC, id DESC LIMIT 1", params,
            ).fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------------ #
    # Findings as cases                                                    #
    # ------------------------------------------------------------------ #

    #: Fields a caller may sort by. Anything else is rejected rather than
    #: interpolated into SQL.
    FINDING_SORTS = {
        "created_at": "f.created_at", "severity": "sev_rank", "store": "f.store",
        "collection": "f.collection", "category": "f.category",
        "case_state": "f.case_state", "case_updated_at": "f.case_updated_at",
    }

    _SEV_RANK = ("CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
                 "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END")

    def observed_store_names(self, store_id: str) -> list[str]:
        """The connector-reported names a registered store has been seen under.

        Findings record the store as the connector describes itself (an endpoint
        or path), while the registry keys everything by ``store_id``. Audits
        carry both, so they are the bridge between the two.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT store FROM audit_snapshots WHERE store_id = ?",
                (store_id,)).fetchall()
        return [r["store"] for r in rows if r["store"]]

    def query_findings(self, *, store: Optional[str] = None,
                       stores: Optional[list[str]] = None,
                       collection: Optional[str] = None,
                       severity: Optional[str] = None,
                       min_severity: Optional[str] = None,
                       category: Optional[str] = None,
                       case_state: Optional[str] = None,
                       owner: Optional[str] = None,
                       suppressed: Optional[bool] = None,
                       search: Optional[str] = None,
                       sort: str = "created_at", direction: str = "desc",
                       limit: int = 50, offset: int = 0,
                       latest_audit_ids: Optional[list[str]] = None) -> dict[str, Any]:
        """Filter findings in SQL and report the true total.

        The console used to filter client-side over a capped fetch, so "138 of
        500" silently meant "of the first 500". ``total`` here is the count of
        everything matching, not the size of the page.

        With ``latest_audit_ids`` the rows are distinct findings from those
        audits only: one row per (audit, fingerprint), every other filter
        applying on top. The representative occurrence is a live one where any
        exists, then the most severe, then the lowest id, so a fingerprint
        reads as suppressed only when every occurrence of it was, and at the
        severity of its worst live occurrence. That is the home summary's
        definition of an open finding, row for row.
        """
        if sort not in self.FINDING_SORTS:
            raise ValueError(f"cannot sort findings by {sort!r}")
        if direction.lower() not in ("asc", "desc"):
            raise ValueError(f"unknown sort direction {direction!r}")

        clauses: list[str] = []
        params: list[Any] = []
        if store:
            clauses.append("f.store = ?")
            params.append(store)
        if stores is not None:
            if not stores:
                # An explicit empty set matches nothing, rather than everything.
                clauses.append("1 = 0")
            else:
                clauses.append(f"f.store IN ({', '.join('?' * len(stores))})")
                params.extend(stores)
        if collection:
            clauses.append("f.collection = ?")
            params.append(collection)
        if severity:
            clauses.append("f.severity = ?")
            params.append(severity)
        if min_severity:
            order = ["info", "low", "medium", "high", "critical"]
            if min_severity not in order:
                raise ValueError(f"unknown severity {min_severity!r}")
            wanted = order[order.index(min_severity):]
            clauses.append(f"f.severity IN ({', '.join('?' * len(wanted))})")
            params.extend(wanted)
        if category:
            clauses.append("f.category = ?")
            params.append(category)
        if case_state:
            clauses.append("f.case_state = ?")
            params.append(case_state)
        if owner:
            clauses.append("f.case_owner = ?")
            params.append(owner)
        if suppressed is not None:
            clauses.append("f.suppressed = ?")
            params.append(1 if suppressed else 0)
        if search:
            like = f"%{search}%"
            clauses.append("(f.title LIKE ? OR f.description LIKE ? OR f.evidence LIKE ? "
                           "OR f.id LIKE ? OR f.fingerprint LIKE ?)")
            params.extend([like] * 5)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        source = "findings f"
        if latest_audit_ids is not None:
            ids = [a for a in latest_audit_ids if a] or [""]
            source = (
                "(SELECT * FROM (SELECT f.*, ROW_NUMBER() OVER ("
                "PARTITION BY j.audit_id, COALESCE(f.fingerprint, f.id) "
                f"ORDER BY f.suppressed ASC, {self._SEV_RANK} DESC, f.id ASC) AS rep_rank "
                "FROM findings f JOIN jobs j ON f.job_id = j.id "
                f"WHERE j.audit_id IN ({', '.join('?' * len(ids))})) "
                "WHERE rep_rank = 1) f")
            params = [*ids, *params]

        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM {source}{where}", params).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT f.*, {self._SEV_RANK} AS sev_rank FROM {source}{where} "
                f"ORDER BY {self.FINDING_SORTS[sort]} {direction.upper()}, f.id ASC "
                "LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
            facets = {
                "severity": self._facet("severity", where, params, source),
                "category": self._facet("category", where, params, source),
                "store": self._facet("store", where, params, source),
                "case_state": self._facet("case_state", where, params, source),
            }
        return {
            "findings": [_finding_row(r) for r in rows],
            "total": total, "limit": limit, "offset": offset,
            "has_more": offset + len(rows) < total,
            "next_offset": offset + limit if offset + len(rows) < total else None,
            "facets": facets,
        }

    def _facet(self, column: str, where: str, params: list[Any],
               source: str = "findings f") -> dict[str, int]:
        rows = self._conn.execute(
            f"SELECT f.{column} AS value, COUNT(*) AS cnt FROM {source}{where} "
            f"GROUP BY f.{column} ORDER BY cnt DESC", params).fetchall()
        return {str(r["value"]): r["cnt"] for r in rows if r["value"] is not None}

    def get_finding(self, finding_id: str) -> Optional[dict[str, Any]]:
        """One finding with its evidence and case, or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return _finding_row(row) if row is not None else None

    def findings_for_chunk(self, chunk_id: str, *, store: Optional[str] = None,
                           collection: Optional[str] = None,
                           limit: int = 50) -> list[dict[str, Any]]:
        """Findings whose captured examples name this chunk.

        Evidence is stored as JSON, so this is a text match narrowed by store
        and collection first; the caller filters the decoded examples again.
        """
        clauses = ["evidence LIKE ?"]
        params: list[Any] = [f'%"chunk_id": "{chunk_id}"%']
        if store:
            clauses.append("store = ?")
            params.append(store)
        if collection:
            clauses.append("collection = ?")
            params.append(collection)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM findings WHERE {' AND '.join(clauses)} "
                "ORDER BY created_at DESC LIMIT ?", [*params, limit]).fetchall()
        out = []
        for row in rows:
            finding = _finding_row(row)
            examples = ((finding.get("evidence") or {}).get("examples")) or []
            if any(str(e.get("chunk_id")) == chunk_id for e in examples if isinstance(e, dict)):
                out.append(finding)
        return out

    def findings_by_fingerprint(self, fingerprint: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """Every recorded occurrence of the same observation, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE fingerprint = ? ORDER BY created_at DESC LIMIT ?",
                (fingerprint, limit)).fetchall()
        return [_finding_row(r) for r in rows]

    def get_case(self, finding_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, case_state, case_owner, case_reason, case_updated_at, "
                "case_verified_by FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            return None
        return {"finding_id": row["id"], "state": row["case_state"] or "new",
                "owner": row["case_owner"], "reason": row["case_reason"] or "",
                "updated_at": row["case_updated_at"],
                "verified_by_job_id": row["case_verified_by"]}

    def save_case(self, state, event) -> None:
        """Persist a case change and append its event in one transaction."""
        with self._lock, self._conn:
            updated = self._conn.execute(
                "UPDATE findings SET case_state = ?, case_owner = ?, case_reason = ?, "
                "case_updated_at = ?, case_verified_by = ? WHERE id = ?",
                (state.state, state.owner, state.reason, state.updated_at,
                 state.verified_by_job_id, state.finding_id)).rowcount
            if not updated:
                raise KeyError(state.finding_id)
            self._conn.execute(
                "INSERT INTO finding_case_events "
                "(finding_id, actor, at, from_state, to_state, owner, reason, verified_by_job_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event.finding_id, event.actor, event.at, event.from_state,
                 event.to_state, event.owner, event.reason, event.verified_by_job_id))

    def case_events(self, finding_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT actor, at, from_state, to_state, owner, reason, verified_by_job_id "
                "FROM finding_case_events WHERE finding_id = ? ORDER BY at ASC, id ASC",
                (finding_id,)).fetchall()
        return [dict(r) for r in rows]

    def case_summary(self, *, store: Optional[str] = None) -> dict[str, Any]:
        where, params = (" WHERE store = ?", [store]) if store else ("", [])
        with self._lock:
            rows = self._conn.execute(
                f"SELECT case_state, COUNT(*) AS cnt FROM findings{where} "
                "GROUP BY case_state", params).fetchall()
        return {str(r["case_state"] or "new"): r["cnt"] for r in rows}

    # ------------------------------------------------------------------ #
    # Evidence, reviews, and exceptions                                    #
    # ------------------------------------------------------------------ #

    def save_artifact(self, artifact) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO evidence_artifacts VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (artifact.id, artifact.title, artifact.media_type, artifact.state,
                 artifact.content_hash, artifact.size_bytes, artifact.collector,
                 artifact.collected_at, artifact.scope, artifact.period_start,
                 artifact.period_end, artifact.supersedes, artifact.note))

    def get_artifact(self, artifact_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM evidence_artifacts WHERE id = ?", (artifact_id,)).fetchone()
        return dict(row) if row else None

    def list_artifacts(self, *, scope: Optional[str] = None,
                       state: Optional[str] = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if scope:
            clauses.append("scope = ?")
            params.append(scope)
        if state:
            clauses.append("state = ?")
            params.append(state)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM evidence_artifacts{where} ORDER BY collected_at DESC, id",
                params).fetchall()
        return [dict(r) for r in rows]

    def save_review(self, review) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO evidence_reviews VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (review.id, review.artifact_id, review.criterion_id, review.scope,
                 review.period, review.state, review.reviewer, review.reason,
                 review.decided_at, review.requirement))

    def get_review(self, review_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM evidence_reviews WHERE id = ?", (review_id,)).fetchone()
        return dict(row) if row else None

    def list_reviews(self, *, criterion_id: Optional[str] = None,
                     scope: Optional[str] = None,
                     artifact_id: Optional[str] = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        for column, value in (("criterion_id", criterion_id), ("scope", scope),
                              ("artifact_id", artifact_id)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM evidence_reviews{where} ORDER BY decided_at DESC, id",
                params).fetchall()
        return [dict(r) for r in rows]

    def save_exception(self, exception) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO risk_exceptions (id, criterion_id, scope, rationale, "
                "requested_by, expires_at, approved_by, approved_at, revoked_at, created_at, "
                "self_approved) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (exception.id, exception.criterion_id, exception.scope,
                 exception.rationale, exception.requested_by, exception.expires_at,
                 exception.approved_by, exception.approved_at, exception.revoked_at,
                 exception.created_at, 1 if getattr(exception, "self_approved", False) else 0))

    def get_exception(self, exception_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM risk_exceptions WHERE id = ?", (exception_id,)).fetchone()
        return dict(row) if row else None

    def list_exceptions(self, *, criterion_id: Optional[str] = None,
                        scope: Optional[str] = None) -> list[dict[str, Any]]:
        """Exceptions, optionally filtered.

        ``None`` means "do not filter on this column". The empty string does
        **not**: ``scope`` is ``NOT NULL`` and an exception that applies to the
        whole estate is stored with an empty scope, so ``scope=""`` is a real
        query for the estate-wide ones.

        The distinction used to be lost to a truthiness test, which made
        ``scope=""`` return every exception in the table. The caller that asks
        for "this store's, plus the estate-wide ones" therefore got the whole
        table twice over, and store-scoped exceptions appeared duplicated on
        the criteria view.
        """
        clauses, params = [], []
        for column, value in (("criterion_id", criterion_id), ("scope", scope)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM risk_exceptions{where} ORDER BY expires_at DESC, id",
                params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    # Reviewer decisions and applicability answers                         #
    # ------------------------------------------------------------------ #

    _DECISION_COLUMNS = ("id", "store_id", "criterion_id", "conclusion", "rationale",
                         "reviewer", "decided_at", "audit_id", "period",
                         "pack_version", "criterion_digest")

    def save_reviewer_decision(self, record: dict[str, Any]) -> None:
        """Append a decision. An existing id is never rewritten."""
        values = tuple(record.get(column) for column in self._DECISION_COLUMNS)
        with self._lock, self._conn:
            if self._conn.execute("SELECT 1 FROM reviewer_decisions WHERE id = ?",
                                  (record["id"],)).fetchone():
                raise ValueError(f"decision {record['id']} already exists")
            seq = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM reviewer_decisions").fetchone()[0]
            self._conn.execute(
                f"INSERT INTO reviewer_decisions ({', '.join(self._DECISION_COLUMNS)}, seq) "
                f"VALUES ({', '.join('?' * len(self._DECISION_COLUMNS))}, ?)",
                (*values, seq))

    def _retirement_bounds(self, store_id: str) -> tuple[int, int]:
        """(decisions_through, answers_through) of the store's newest retirement."""
        row = self._conn.execute(
            "SELECT decisions_through, answers_through FROM store_retirements "
            "WHERE store_id = ? ORDER BY id DESC LIMIT 1", (store_id,)).fetchone()
        return (row["decisions_through"], row["answers_through"]) if row else (0, 0)

    def list_reviewer_decisions(self, store_id: str) -> list[dict[str, Any]]:
        """Every decision recorded for the store's current registration, newest first.

        Decisions made before the store was last deregistered are excluded.
        Criterion ids are returned as stored; the caller resolves retired ids,
        so filtering by criterion happens after that resolution, not here.
        """
        with self._lock:
            through, _ = self._retirement_bounds(store_id)
            rows = self._conn.execute(
                "SELECT * FROM reviewer_decisions WHERE store_id = ? AND seq > ? "
                "ORDER BY decided_at DESC, seq DESC", (store_id, through)).fetchall()
        return [{k: v for k, v in dict(r).items() if k != "seq"} for r in rows]

    def retire_store_records(self, store_id: str, *, retired_by: str,
                             retired_at: str) -> dict[str, int]:
        """End a registration: later reads ignore its decisions and answers.

        Nothing is deleted. Returns how many decisions and current answers
        stopped applying, for the audit log.
        """
        with self._lock, self._conn:
            decisions_before, answers_before = self._retirement_bounds(store_id)
            decisions_max = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM reviewer_decisions").fetchone()[0]
            answers_max = self._conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM store_applicability").fetchone()[0]
            decisions = self._conn.execute(
                "SELECT COUNT(*) FROM reviewer_decisions WHERE store_id = ? AND seq > ?",
                (store_id, decisions_before)).fetchone()[0]
            answers = self._conn.execute(
                "SELECT COUNT(DISTINCT question) FROM store_applicability "
                "WHERE store_id = ? AND id > ?", (store_id, answers_before)).fetchone()[0]
            self._conn.execute(
                "INSERT INTO store_retirements "
                "(store_id, retired_at, retired_by, decisions_through, answers_through) "
                "VALUES (?, ?, ?, ?, ?)",
                (store_id, retired_at, retired_by, decisions_max, answers_max))
        return {"reviewer_decisions": decisions, "applicability_answers": answers}

    def save_applicability_answers(self, store_id: str, answers: dict[str, str], *,
                                   answered_by: str, answered_at: str) -> None:
        """Append one row per answered question, in one transaction."""
        rows = [(store_id, question, answer, answered_by, answered_at)
                for question, answer in sorted(answers.items())]
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO store_applicability "
                "(store_id, question, answer, answered_by, answered_at) "
                "VALUES (?, ?, ?, ?, ?)", rows)

    def applicability_answers(self, store_id: str) -> dict[str, dict[str, Any]]:
        """The current answer per question for a store, with who gave it and when.

        Answers given before the store was last deregistered are excluded.
        """
        with self._lock:
            _, through = self._retirement_bounds(store_id)
            rows = self._conn.execute(
                "SELECT question, answer, answered_by, answered_at FROM store_applicability "
                "WHERE store_id = ? AND id > ? ORDER BY id DESC",
                (store_id, through)).fetchall()
        current: dict[str, dict[str, Any]] = {}
        for row in rows:
            current.setdefault(row["question"], {
                "answer": row["answer"], "answered_by": row["answered_by"],
                "answered_at": row["answered_at"]})
        return dict(sorted(current.items()))

    # ------------------------------------------------------------------ #
    # Estate-wide reads for the home summary                               #
    # ------------------------------------------------------------------ #

    def latest_audit_ids(self) -> dict[str, str]:
        """store_id -> id of its newest saved audit, without reading snapshots.

        Newest by the same order as :meth:`latest_audit_snapshots` and
        :meth:`list_audits`: finished_at, then id.
        """
        with self._lock:
            rows = self._conn.execute(
                """SELECT a.store_id, a.id FROM audit_snapshots a
                   WHERE a.id = (SELECT b.id FROM audit_snapshots b
                                 WHERE b.store_id = a.store_id
                                 ORDER BY b.finished_at DESC, b.id DESC LIMIT 1)"""
            ).fetchall()
        return {r["store_id"]: r["id"] for r in rows}

    def audit_finish_times(self, audit_ids: Iterable[Optional[str]]) -> dict[str, str]:
        """When each named audit finished, without reading its snapshot."""
        ids = sorted({a for a in audit_ids if a})
        if not ids:
            return {}
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, finished_at FROM audit_snapshots "
                f"WHERE id IN ({', '.join('?' * len(ids))})", ids).fetchall()
        return {r["id"]: r["finished_at"] for r in rows}

    def latest_audit_snapshots(self) -> dict[str, dict[str, Any]]:
        """The newest saved audit for every store that has one, in one query."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT a.store_id, a.snapshot_json FROM audit_snapshots a
                   WHERE a.id = (SELECT b.id FROM audit_snapshots b
                                 WHERE b.store_id = a.store_id
                                 ORDER BY b.finished_at DESC, b.id DESC LIMIT 1)"""
            ).fetchall()
        out: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                out[row["store_id"]] = json.loads(row["snapshot_json"])
            except ValueError:
                out[row["store_id"]] = {"id": None, "store_id": row["store_id"],
                                        "unreadable": True}
        return out

    def audit_finding_fingerprints(self, audit_ids: list[str]) -> list[dict[str, Any]]:
        """One row per (audit, fingerprint) for findings recorded under these audits.

        ``suppressed`` is true only when every occurrence of the fingerprint in
        that audit was suppressed; ``severities`` lists the severity of each
        live (unsuppressed) occurrence, so the caller can take the highest
        without a suppressed occurrence raising it. It is empty when every
        occurrence was suppressed.
        """
        ids = [a for a in audit_ids if a]
        if not ids:
            return []
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT j.audit_id AS audit_id,
                           COALESCE(f.fingerprint, f.id) AS fingerprint,
                           GROUP_CONCAT(CASE WHEN f.suppressed = 0
                                             THEN f.severity END) AS severities,
                           MIN(f.suppressed) AS all_suppressed
                    FROM findings f JOIN jobs j ON f.job_id = j.id
                    WHERE j.audit_id IN ({', '.join('?' * len(ids))})
                    GROUP BY j.audit_id, COALESCE(f.fingerprint, f.id)""",
                ids).fetchall()
        return [{"audit_id": r["audit_id"], "fingerprint": r["fingerprint"],
                 "severities": [s for s in (r["severities"] or "").split(",") if s],
                 "suppressed": bool(r["all_suppressed"])} for r in rows]

    def save_plan(self, plan) -> None:
        """Persist a staged plan. Refuses to overwrite one that already exists.

        A plan is the thing an approval is scoped to. Letting a second write
        land on the same id would let an approved plan be swapped for a
        different one under the same name.
        """
        body = plan.to_dict()
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT plan_hash FROM action_plans WHERE id = ?", (plan.id,)).fetchone()
            if existing:
                raise ValueError(f"plan {plan.id} is already staged and cannot be replaced")
            self._conn.execute(
                "INSERT INTO action_plans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (plan.id, plan.store, plan.staged_by, plan.staged_at, plan.state,
                 plan.plan_hash, plan.store_fingerprint, plan.note,
                 json.dumps(body, sort_keys=True)))

    def get_plan(self, plan_id: str) -> Optional[dict[str, Any]]:
        """Read a plan back, verifying it still hashes to what was stored.

        ``body_intact`` false means the stored plan and its recorded hash
        disagree. The caller must treat that as a plan to re-stage, never as a
        plan to act on.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM action_plans WHERE id = ?", (plan_id,)).fetchone()
        if not row:
            return None
        record = dict(row)
        try:
            body = json.loads(record["body"])
        except ValueError:
            record["body"] = None
            record["body_intact"] = False
            return record
        from vecshield_platform.actions import verify_body

        record["body"] = body
        # Recomputed from the operations, not compared against the copy of the
        # hash stored inside the body: anyone who edited the body could have
        # left that field alone, and the check would pass on an altered plan.
        record["body_intact"] = (verify_body(body)
                                 and body.get("plan_hash") == record["plan_hash"])
        # The column is where a plan's state moves; the body was frozen at
        # staging and still says "staged". Handing the stale copy to a caller
        # would let an executed plan be approved or run a second time. State is
        # not part of the hash, so this does not disturb the integrity check.
        body["state"] = record["state"]
        return record

    def list_plans(self, *, store: Optional[str] = None,
                   state: Optional[str] = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        for column, value in (("store", store), ("state", state)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT id, store, staged_by, staged_at, state, plan_hash, note "
                f"FROM action_plans{where} ORDER BY staged_at DESC, id", params).fetchall()
        return [dict(r) for r in rows]

    def set_plan_state(self, plan_id: str, state: str) -> bool:
        """Move a plan to a terminal or stale state. The body never changes."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE action_plans SET state = ? WHERE id = ?", (state, plan_id))
        return cur.rowcount > 0

    def claim_plan(self, plan_id: str) -> bool:
        """Atomically move a staged plan to ``executing``.

        Exactly one caller wins for a given plan; everyone else gets False.
        Reading the state and then acting on it let two concurrent requests
        both see ``staged`` and both write to the store.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE action_plans SET state = 'executing' "
                "WHERE id = ? AND state = 'staged'", (plan_id,))
        return cur.rowcount == 1

    def release_plan(self, plan_id: str) -> bool:
        """Hand an ``executing`` claim back to ``staged``.

        Only for an execution refused before anything was written (safe mode,
        staleness, separation of duties); a run that touched the store settles
        its claim with :meth:`set_plan_state` instead.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE action_plans SET state = 'staged' "
                "WHERE id = ? AND state = 'executing'", (plan_id,))
        return cur.rowcount == 1

    def save_approval(self, approval) -> None:
        """Record an authorization. One approval per id, never rewritten."""
        with self._lock, self._conn:
            if self._conn.execute("SELECT 1 FROM action_approvals WHERE id = ?",
                                  (approval.id,)).fetchone():
                raise ValueError(f"approval {approval.id} already exists")
            self._conn.execute(
                "INSERT INTO action_approvals (id, plan_id, plan_hash, approver, reason, "
                "approved_at, typed_store_id, operations, self_approved, "
                "separation_of_duties) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (approval.id, approval.plan_id, approval.plan_hash, approval.approver,
                 approval.reason, approval.approved_at, approval.typed_store_id,
                 json.dumps(list(approval.operations)),
                 1 if getattr(approval, "self_approved", False) else 0,
                 getattr(approval, "separation_of_duties", "required")))

    def get_approval(self, approval_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM action_approvals WHERE id = ?", (approval_id,)).fetchone()
        if not row:
            return None
        record = dict(row)
        try:
            record["operations"] = json.loads(record["operations"] or "[]")
        except ValueError:
            record["operations"] = []
        record["self_approved"] = bool(record.get("self_approved"))
        return record

    def list_approvals(self, *, plan_id: Optional[str] = None) -> list[dict[str, Any]]:
        where, params = ("", [])
        if plan_id:
            where, params = (" WHERE plan_id = ?", [plan_id])
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM action_approvals{where} ORDER BY approved_at DESC",
                params).fetchall()
        return [dict(r) for r in rows]

    def save_execution(self, execution, verification=None) -> None:
        """Record what an execution did. Written once, including a failure.

        A failed or halted execution is stored exactly like a successful one.
        Dropping it would leave a store that was half-changed with no record of
        what changed it.
        """
        with self._lock, self._conn:
            if self._conn.execute("SELECT 1 FROM action_executions WHERE id = ?",
                                  (execution.id,)).fetchone():
                raise ValueError(f"execution {execution.id} already exists")
            self._conn.execute(
                "INSERT INTO action_executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (execution.id, execution.plan_id, execution.approval_id, execution.store,
                 execution.executed_by, execution.started_at, execution.finished_at,
                 1 if execution.halted else 0, 1 if execution.safe_mode else 0,
                 json.dumps(execution.to_dict(), sort_keys=True),
                 json.dumps(verification.to_dict()) if verification is not None else None))

    def set_execution_verification(self, execution_id: str, verification) -> bool:
        """Attach the read-back to an execution already recorded.

        The execution is saved as soon as the store has been written, so a
        read-back that fails cannot take the record of the write with it. Set
        once: a stored verification is never replaced.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE action_executions SET verification = ? "
                "WHERE id = ? AND verification IS NULL",
                (json.dumps(verification.to_dict()), execution_id))
        return cur.rowcount == 1

    def get_execution(self, execution_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM action_executions WHERE id = ?", (execution_id,)).fetchone()
        if not row:
            return None
        record = dict(row)
        for key in ("body", "verification"):
            try:
                record[key] = json.loads(record[key]) if record[key] else None
            except ValueError:
                record[key] = None
        return record

    def list_executions(self, *, plan_id: Optional[str] = None,
                        store: Optional[str] = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        for column, value in (("plan_id", plan_id), ("store", store)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT id, plan_id, approval_id, store, executed_by, started_at, "
                f"finished_at, halted, safe_mode FROM action_executions{where} "
                f"ORDER BY started_at DESC", params).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        """Quick summary counts for the dashboard header."""
        with self._lock:
            total_jobs = self._conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            total_findings = self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            by_sev = {
                r["severity"]: r["cnt"]
                for r in self._conn.execute(
                    "SELECT severity, COUNT(*) AS cnt FROM findings GROUP BY severity"
                ).fetchall()
            }
        return {
            "total_jobs": total_jobs,
            "total_findings": total_findings,
            "by_severity": by_sev,
        }

    # ------------------------------------------------------------------ #
    # DSAR                                                               #
    # ------------------------------------------------------------------ #

    # ---------------------------------------------------------------- #
    # Subject index                                                     #
    # ---------------------------------------------------------------- #

    def subject_salt(self) -> bytes:
        """The key this deployment files subject locations under.

        Created once beside the database file and cached on the instance. An
        in-memory history gets an ephemeral key, which is right: its rows do
        not outlive the process either.
        """
        if self._subject_salt is None:
            from vecshield_platform.subject_index import (
                load_or_create_salt, salt_path_for,
            )
            if self._path == ":memory:":
                import secrets
                self._subject_salt = secrets.token_bytes(32)
            else:
                self._subject_salt = load_or_create_salt(salt_path_for(self._path))
        return self._subject_salt

    def record_subject_locations(self, locations, *, scan_id: str = "",
                                 coverage_complete: bool = False) -> int:
        """Record where subjects were observed. Idempotent across re-scans.

        ``coverage_complete`` is the scan's own answer about whether it saw its
        whole scope, carried onto every row so a later lookup can say how much
        of the estate the index actually covers. It is stored per row rather
        than per scan because a lookup returns rows, and a caveat that lives
        somewhere else is a caveat nobody reads.
        """
        rows = [(loc.subject_key, loc.store_id, loc.collection, loc.chunk_id,
                 loc.detector, loc.surface, _now(), scan_id,
                 1 if coverage_complete else 0) for loc in locations]
        if not rows:
            return 0
        with self._lock, self._conn:
            self._conn.executemany(
                """INSERT INTO subject_index
                   (subject_key, store_id, collection, chunk_id, detector, surface,
                    observed_at, scan_id, coverage_complete)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(subject_key, store_id, collection, chunk_id, detector)
                   DO UPDATE SET observed_at=excluded.observed_at,
                                 scan_id=excluded.scan_id,
                                 coverage_complete=excluded.coverage_complete""",
                rows)
        return len(rows)

    def finalize_subject_scan(self, store_id: str, scan_id: str,
                              coverage_complete: bool) -> int:
        """Stamp the finishing scan's coverage onto the rows it just wrote.

        Rows are written while the scan is still running, when whether it will
        see its whole scope is not yet known, so they land conservatively as
        incomplete. This settles them once the answer exists. Only rows this
        scan wrote are touched — an earlier scan's coverage is its own.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE subject_index SET scan_id = ?, coverage_complete = ? "
                "WHERE store_id = ? AND (scan_id IS NULL OR scan_id = '')",
                (scan_id, 1 if coverage_complete else 0, store_id))
            return cur.rowcount or 0

    def lookup_subject(self, subject_keys, *, store_ids=None, limit: int = 5000
                       ) -> list[dict]:
        """Locations recorded for any of these keys. Never an authority on absence."""
        keys = [k for k in (subject_keys or []) if k]
        if not keys:
            return []
        sql = ("SELECT subject_key, store_id, collection, chunk_id, detector, surface, "
               "observed_at, scan_id, coverage_complete FROM subject_index "
               f"WHERE subject_key IN ({','.join('?' * len(keys))})")
        params: list = list(keys)
        stores = [s for s in (store_ids or []) if s]
        if stores:
            sql += f" AND store_id IN ({','.join('?' * len(stores))})"
            params.extend(stores)
        sql += " ORDER BY store_id, collection, chunk_id LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [{**dict(r), "coverage_complete": bool(r["coverage_complete"])}
                for r in rows]

    def forget_subject(self, subject_keys) -> int:
        """Remove a subject's rows.

        Called when their data is erased: an index that outlived the chunks it
        pointed at would be a standing record that a particular person once
        asked to be forgotten.
        """
        keys = [k for k in (subject_keys or []) if k]
        if not keys:
            return 0
        with self._lock, self._conn:
            cur = self._conn.execute(
                f"DELETE FROM subject_index WHERE subject_key IN ({','.join('?' * len(keys))})",
                keys)
            return cur.rowcount or 0

    def forget_store_subjects(self, store_id: str) -> int:
        """Drop an entire store's rows, for when it is deregistered."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM subject_index WHERE store_id = ?", (store_id,))
            return cur.rowcount or 0

    def subject_index_stats(self) -> dict:
        """Size and reach of the index, with no subject detail in it."""
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) AS n FROM subject_index").fetchone()["n"]
            subjects = self._conn.execute(
                "SELECT COUNT(DISTINCT subject_key) AS n FROM subject_index").fetchone()["n"]
            stores = [dict(r) for r in self._conn.execute(
                "SELECT store_id, COUNT(*) AS locations, "
                "MIN(coverage_complete) AS all_complete, MAX(observed_at) AS last_indexed "
                "FROM subject_index GROUP BY store_id ORDER BY store_id").fetchall()]
        return {
            "locations": total,
            "subjects": subjects,
            "stores": [{**r, "all_complete": bool(r["all_complete"])} for r in stores],
        }

    def save_dsar(self, dsar, *, created_by: Optional[str] = None) -> None:
        """Persist (or update) a DSARRecord.

        ``created_by`` is recorded on the first save and never overwritten, so
        a later update cannot change who opened the request.
        """
        with self._lock:
            with self._conn:
                self._conn.execute(
                    # An upsert, not INSERT OR REPLACE: a replace deletes the
                    # row and re-inserts it, resetting created_at, so executing
                    # a request moved it to the top of the list as if new.
                    """INSERT INTO dsars
                       (id, subject, status, requested_at, executed_at, notes, record_json,
                        created_by)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                         subject = excluded.subject, status = excluded.status,
                         requested_at = excluded.requested_at,
                         executed_at = excluded.executed_at, notes = excluded.notes,
                         record_json = excluded.record_json,
                         created_by = COALESCE(dsars.created_by, excluded.created_by)""",
                    (
                        dsar.id,
                        dsar.subject,
                        dsar.status,
                        dsar.requested_at,
                        dsar.executed_at,
                        dsar.notes,
                        json.dumps(dsar.to_dict()),
                        created_by,
                    ),
                )

    def list_dsars(
        self,
        *,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM dsars{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_dsar_summary_row(_row(r)) for r in rows]

    def get_dsar(self, dsar_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM dsars WHERE id = ?", (dsar_id,)
            ).fetchone()
        if not row:
            return None
        d = _row(row)
        if isinstance(d.get("record_json"), str):
            try:
                d["record"] = json.loads(d["record_json"])
            except Exception:
                pass
        return d

    # ------------------------------------------------------------------ #
    # Async jobs (background task queue)                                   #
    # ------------------------------------------------------------------ #

    def save_async_job(self, record: dict[str, Any]) -> None:
        """Persist (or update) a background job record. `result` and `progress`
        are stored as JSON text; all other fields are plain strings/None."""
        result = record.get("result")
        progress = record.get("progress")
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """INSERT OR REPLACE INTO async_jobs
                       (id, kind, status, actor, resource, created_at,
                        started_at, finished_at, result, error,
                        runner_id, heartbeat_at, progress)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record["id"],
                        record.get("kind"),
                        record["status"],
                        record.get("actor"),
                        record.get("resource"),
                        record["created_at"],
                        record.get("started_at"),
                        record.get("finished_at"),
                        json.dumps(result) if result is not None else None,
                        record.get("error"),
                        record.get("runner_id"),
                        record.get("heartbeat_at"),
                        json.dumps(progress) if progress is not None else None,
                    ),
                )

    def touch_async_jobs(self, job_ids: list[str], *, runner_id: str, at: str) -> None:
        """Record that ``runner_id`` still owns these unfinished jobs."""
        if not job_ids:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                "UPDATE async_jobs SET heartbeat_at = ?, runner_id = ? WHERE id = ?",
                [(at, runner_id, job_id) for job_id in job_ids],
            )

    def interrupt_abandoned_async_jobs(self, *, runner_id: str, stale_before: str,
                                       at: str, reason: str) -> list[dict[str, Any]]:
        """Mark unfinished jobs no live runner is claiming as ``interrupted``.

        A job is abandoned when it is not owned by the calling runner and its
        last heartbeat predates ``stale_before`` (or it never recorded one).
        Jobs a sibling process is actively heartbeating are left alone.
        """
        with self._lock, self._conn:
            rows = self._conn.execute(
                """SELECT * FROM async_jobs
                   WHERE status IN ('queued', 'running')
                     AND (runner_id IS NULL OR runner_id != ?)
                     AND (heartbeat_at IS NULL OR heartbeat_at < ?)""",
                (runner_id, stale_before),
            ).fetchall()
            if rows:
                self._conn.executemany(
                    """UPDATE async_jobs
                       SET status = 'interrupted', finished_at = ?, error = ?
                       WHERE id = ?""",
                    [(at, reason, row["id"]) for row in rows],
                )
        return [_async_job_row(row) for row in rows]

    def get_async_job(self, job_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM async_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _async_job_row(row) if row else None

    def list_async_jobs(
        self,
        *,
        kind: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM async_jobs{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_async_job_row(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "ScanHistory":
        return self

    def __exit__(self, *_) -> None:
        self.close()


def _row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for key in ("stats", "evidence"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except Exception:
                pass
    return d


def _finding_row(row: sqlite3.Row) -> dict[str, Any]:
    """A finding with its case attached, and the two kept distinguishable.

    `suppressed` says what is shown; `case` says what people decided. Neither
    implies the other, so they travel as separate fields.
    """
    d = _row(row)
    d.pop("sev_rank", None)
    d.pop("rep_rank", None)
    d["case"] = {
        "state": d.pop("case_state", None) or "new",
        "owner": d.pop("case_owner", None),
        "reason": d.pop("case_reason", None) or "",
        "updated_at": d.pop("case_updated_at", None),
        "verified_by_job_id": d.pop("case_verified_by", None),
    }
    d["suppressed"] = bool(d.get("suppressed"))
    return d


def _async_job_row(row: sqlite3.Row) -> dict[str, Any]:
    """Deserialize a persisted async_jobs row, parsing JSON `result` and `progress`."""
    d = dict(row)
    for key in ("result", "progress"):
        if isinstance(d.get(key), str):
            try:
                d[key] = json.loads(d[key])
            except Exception:
                pass
    return d


def _dsar_summary_row(d: dict[str, Any]) -> dict[str, Any]:
    """Replace the raw record_json payload with the summary counters the
    dashboard list view renders (found/deleted/match/error totals)."""
    raw = d.pop("record_json", None)
    record: dict[str, Any] = {}
    if isinstance(raw, str):
        try:
            record = json.loads(raw)
        except Exception:
            record = {}
    for key in ("total_chunks_found", "total_chunks_deleted",
                "stores_with_matches", "stores_with_errors"):
        d[key] = record.get(key, 0)
    d["stores_scanned"] = len(record.get("stores", []))
    return d
