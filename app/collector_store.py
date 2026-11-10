"""Shared SQLite snapshot store for every cache the executive-summary
route reads, so the route stays consistent across Gunicorn web workers
and survives a container restart — see
~/Documents/4thealth-notes/scale-review-1000-devices.md section C1.

Each cache module keeps its own in-memory dict exactly as before (this
is a read-through/write-through addition, not a replacement) and calls
write_snapshot() every time it updates that dict; callers read the
in-memory value first and fall back to read_snapshot() only when the
in-memory value is still at its pending/never-populated default —
i.e. a fresh worker (RUN_SCHEDULERS != "inline") that has never run a
sweep itself, or a process that just restarted.

One key-value table, one row per named cache ("cache_key"), storing
that cache's latest snapshot as a JSON blob plus its own collected_at
(when the source data was produced) and updated_at (when this row was
last written) — no history, just "the latest known-good value."
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

_DB_PATH = Path(__file__).parent.parent / "collector_state.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache_snapshots (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    collected_at TEXT,
    updated_at TEXT NOT NULL
);
"""

_lock = threading.Lock()
logger = logging.getLogger(__name__)
_VALID_JOURNAL_MODES = ("WAL", "DELETE")


_LOCK_RETRIES = 8


def _retry_locked(fn):
    """Run *fn*, retrying a transient ``database is locked`` with short backoff.

    SQLite does not apply the busy timeout to the first journal-mode switch or
    schema creation on a brand-new file, so two processes (web and collector)
    starting at once can see a spurious lock error. Anything else, or a lock
    that persists, is raised unchanged.
    """
    for attempt in range(_LOCK_RETRIES):
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == _LOCK_RETRIES - 1:
                raise
            time.sleep(0.05 * (2**attempt))
    raise AssertionError("unreachable")  # pragma: no cover


def _db_path() -> Path:
    """``COLLECTOR_DB_PATH`` if set, else the project-root default."""
    override = os.environ.get("COLLECTOR_DB_PATH", "").strip()
    return Path(override) if override else _DB_PATH


def _journal_mode() -> str:
    """``COLLECTOR_DB_JOURNAL`` (WAL or DELETE); anything else warns and uses WAL."""
    raw = os.environ.get("COLLECTOR_DB_JOURNAL", "WAL").strip().upper() or "WAL"
    if raw not in _VALID_JOURNAL_MODES:
        logger.warning(
            "COLLECTOR_DB_JOURNAL=%r is not one of %s; using WAL",
            raw,
            _VALID_JOURNAL_MODES,
        )
        return "WAL"
    return raw


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not path.exists()
    conn = sqlite3.connect(path, timeout=30)
    if is_new:
        path.chmod(0o600)
    _retry_locked(lambda: conn.execute(f"PRAGMA journal_mode={_journal_mode()}"))
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    conn = _connect()
    try:
        _retry_locked(lambda: conn.executescript(_SCHEMA))
        conn.commit()
    finally:
        conn.close()


def write_snapshot(
    cache_key: str, payload: dict, collected_at: str | None = None
) -> None:
    """Persist *payload* (JSON-serializable) as the latest snapshot for
    *cache_key*, replacing whatever was stored for that key before."""
    with _lock:
        _init_db()
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO cache_snapshots (cache_key, payload, collected_at, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(cache_key) DO UPDATE SET "
                "payload=excluded.payload, collected_at=excluded.collected_at, "
                "updated_at=excluded.updated_at",
                (
                    cache_key,
                    json.dumps(payload),
                    collected_at,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def read_snapshot(cache_key: str) -> dict | None:
    """Return the latest persisted payload for *cache_key*, or None if
    nothing has ever been written for it."""
    with _lock:
        _init_db()
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT payload FROM cache_snapshots WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        finally:
            conn.close()
    if row is None:
        return None
    return json.loads(row["payload"])


def read_snapshot_meta(cache_key: str) -> dict | None:
    """Like :func:`read_snapshot` but returns ``{payload, collected_at, updated_at}``
    so callers can judge how fresh the stored value is."""
    with _lock:
        _init_db()
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT payload, collected_at, updated_at FROM cache_snapshots "
                "WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        finally:
            conn.close()
    if row is None:
        return None
    return {
        "payload": json.loads(row["payload"]),
        "collected_at": row["collected_at"],
        "updated_at": row["updated_at"],
    }


def read_snapshots_by_prefix(prefix: str) -> list[dict]:
    """All snapshots whose key starts with *prefix*, as
    ``{key, payload, collected_at, updated_at}`` dicts."""
    with _lock:
        _init_db()
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT cache_key, payload, collected_at, updated_at FROM cache_snapshots "
                "WHERE substr(cache_key, 1, ?) = ?",
                (len(prefix), prefix),
            ).fetchall()
        finally:
            conn.close()
    return [
        {
            "key": r["cache_key"],
            "payload": json.loads(r["payload"]),
            "collected_at": r["collected_at"],
            "updated_at": r["updated_at"],
        }
        for r in rows
    ]


def delete_stale_snapshots(prefix: str, max_age_seconds: float) -> int:
    """Delete snapshots under *prefix* not updated for *max_age_seconds*; returns the count."""
    cutoff = datetime.fromtimestamp(time.time() - max_age_seconds, UTC).isoformat()
    with _lock:
        _init_db()
        conn = _connect()
        try:
            cur = conn.execute(
                "DELETE FROM cache_snapshots WHERE substr(cache_key, 1, ?) = ? AND updated_at < ?",
                (len(prefix), prefix, cutoff),
            )
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()
