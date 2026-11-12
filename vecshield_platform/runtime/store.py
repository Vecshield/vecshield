"""Persistent runtime-alert store backed by SQLite.

Mirrors :class:`vecshield_platform.history.ScanHistory`: a single, auto-created
SQLite file (or ``:memory:``), WAL journal mode, one lock serializing writes, and
row-dict reads. It persists every :class:`~vecshield_platform.runtime.events.Alert`
the live :class:`~vecshield_platform.runtime.engine.MonitorEngine` emits so an
operator can query the alert history through the REST API / dashboard rather than
only replaying a static log.

The store is deliberately independent of the engine: the engine dispatches to
sinks, and :class:`~vecshield_platform.runtime.sinks.PersistentAlertSink` is the
sink that writes here. That keeps the detection hot-path free of storage concerns
and lets tests use an in-memory store trivially.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

from vecshield_platform.runtime.events import Alert


_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS alerts (
    id               TEXT PRIMARY KEY,
    rule             TEXT,
    severity         TEXT,
    principal        TEXT,
    collection       TEXT,
    timestamp        REAL,
    message          TEXT,
    dedup_key        TEXT,
    evidence         TEXT,
    suppressed_since INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS ix_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS ix_alerts_rule       ON alerts(rule);
CREATE INDEX IF NOT EXISTS ix_alerts_principal  ON alerts(principal);
CREATE INDEX IF NOT EXISTS ix_alerts_created    ON alerts(created_at);
CREATE INDEX IF NOT EXISTS ix_alerts_ts         ON alerts(timestamp);
"""


class AlertStore:
    """Thread-safe SQLite-backed store for runtime alerts."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self._path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    def ping(self) -> None:
        """Cheap liveness check for readiness probes."""
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()

    # ------------------------------------------------------------------ #
    # Write                                                                #
    # ------------------------------------------------------------------ #

    def save(self, alert: Alert) -> None:
        """Persist a single alert (idempotent on ``alert.id``)."""
        with self._lock:
            with self._conn:
                self._insert(alert)

    def save_many(self, alerts: Iterable[Alert]) -> int:
        """Persist several alerts in one transaction; returns the count."""
        n = 0
        with self._lock:
            with self._conn:
                for alert in alerts:
                    self._insert(alert)
                    n += 1
        return n

    def _insert(self, alert: Alert) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO alerts
               (id, rule, severity, principal, collection, timestamp,
                message, dedup_key, evidence, suppressed_since)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.id,
                alert.rule,
                alert.severity.value,
                alert.principal,
                alert.collection,
                alert.timestamp,
                alert.message,
                alert.dedup_key,
                json.dumps(alert.evidence),
                alert.suppressed_since,
            ),
        )

    # ------------------------------------------------------------------ #
    # Read                                                                 #
    # ------------------------------------------------------------------ #

    def list_alerts(
        self,
        *,
        severity: Optional[str] = None,
        rule: Optional[str] = None,
        principal: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if rule:
            clauses.append("rule = ?")
            params.append(rule)
        if principal:
            clauses.append("principal = ?")
            params.append(principal)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (f"SELECT * FROM alerts{where} "
               "ORDER BY created_at DESC, timestamp DESC LIMIT ? OFFSET ?")
        params += [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row(r) for r in rows]

    def get_alert(self, alert_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        return _row(row) if row else None

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def stats(self) -> dict[str, Any]:
        """Summary counts for the dashboard header."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by_sev = {
                r["severity"]: r["cnt"]
                for r in self._conn.execute(
                    "SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity"
                ).fetchall()
            }
            by_rule = {
                r["rule"]: r["cnt"]
                for r in self._conn.execute(
                    "SELECT rule, COUNT(*) AS cnt FROM alerts GROUP BY rule"
                ).fetchall()
            }
        return {"total": total, "by_severity": by_sev, "by_rule": by_rule}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "AlertStore":
        return self

    def __exit__(self, *_) -> None:
        self.close()


def _row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    if isinstance(d.get("evidence"), str):
        try:
            d["evidence"] = json.loads(d["evidence"])
        except Exception:
            pass
    return d
