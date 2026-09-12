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
import sqlite3
import threading
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


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    conn = _connect()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def write_snapshot(cache_key: str, payload: dict, collected_at: str | None = None) -> None:
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
