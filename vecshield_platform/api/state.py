"""Filesystem layout helpers for served VecShield state.

The legacy CLI kept durable stores next to the config file. New deployments can
pass ``--state-dir`` (or ``VECSHIELD_STATE_DIR``) to keep SQLite DBs, WAL/SHM
sidecars, and audit logs under a single explicit directory.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StatePaths:
    history_db: Path
    alerts_db: Path
    audit_log: Path
    legacy: bool
    #: Local accounts and sessions (ADR 0002).
    users_db: Path = Path("users.db")


def resolve_state_paths(config_path: str | Path, state_dir: Optional[str | Path] = None) -> StatePaths:
    """Return durable state paths for a served instance.

    ``state_dir`` opts into the organized layout:

    ``<state-dir>/sqlite/history.db``
    ``<state-dir>/sqlite/alerts.db``
    ``<state-dir>/sqlite/users.db``
    ``<state-dir>/audit/audit.jsonl``

    When omitted, paths remain beside the config file for backward
    compatibility with existing deployments.
    """

    cfg = Path(config_path)
    root = Path(state_dir) if state_dir else None
    if root is None:
        # F10: the legacy layout puts history, accounts and the audit log
        # beside the config file, in whatever directory that is, without the
        # owner-only (0700) state directory the organized layout creates.
        logger.warning(
            "no --state-dir (VECSHIELD_STATE_DIR) given: history, accounts and the "
            "audit log are kept beside %s without a private (0700) state directory. "
            "Pass --state-dir to use the organized, owner-only layout.", cfg)
        return StatePaths(
            history_db=cfg.with_suffix(".history.db"),
            alerts_db=cfg.with_suffix(".alerts.db"),
            audit_log=cfg.with_suffix(".audit.jsonl"),
            legacy=True,
            users_db=cfg.with_suffix(".users.db"),
        )

    sqlite_dir = root / "sqlite"
    audit_dir = root / "audit"
    _mkdir_private(root)
    _mkdir_private(sqlite_dir)
    _mkdir_private(audit_dir)
    return StatePaths(
        history_db=sqlite_dir / "history.db",
        alerts_db=sqlite_dir / "alerts.db",
        audit_log=audit_dir / "audit.jsonl",
        legacy=False,
        users_db=sqlite_dir / "users.db",
    )


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        # Best effort: chmod is unavailable or denied on some mounted volumes.
        pass
