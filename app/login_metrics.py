"""Login attempt metrics — success/failure counts, SQLite-backed.

Records one row per login attempt into login_events.db (gitignored, project
root — same pattern as app/host_metrics.py). A daily job prunes rows older
than 90 days. GET /admin/api/login-metrics reads aggregated, time-bucketed
rows for the Admin page Logins chart.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from flask import Flask

_DB_PATH = Path(__file__).parent.parent / "login_events.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS login_events (
    ts      INTEGER NOT NULL,
    success INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_events_ts ON login_events (ts);
"""

_RETENTION_DAYS = 90

# range_key -> (window_seconds, bucket_seconds)
_RANGES = {
    "1h": (3_600, 60),
    "4h": (14_400, 300),
    "12h": (43_200, 600),
    "1d": (86_400, 900),
    "7d": (604_800, 3_600),
    "14d": (1_209_600, 7_200),
}
_DEFAULT_RANGE = "1h"


def _init_db() -> None:
    conn = sqlite3.connect(_DB_PATH)
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def record_event(success: bool) -> None:
    """Insert one login attempt row. Never raises."""
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        try:
            conn.execute(
                "INSERT INTO login_events (ts, success) VALUES (?, ?)",
                (int(time.time()), int(bool(success))),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def prune_old_data() -> None:
    """Delete rows older than _RETENTION_DAYS. Never raises."""
    try:
        cutoff = int(time.time()) - _RETENTION_DAYS * 86_400
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        try:
            conn.execute("DELETE FROM login_events WHERE ts < ?", (cutoff,))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def get_metrics(range_key: str) -> dict:
    """Bucketed success/failure series for range_key (defaults to 1h if invalid)."""
    window, bucket = _RANGES.get(range_key, _RANGES[_DEFAULT_RANGE])
    if range_key not in _RANGES:
        range_key = _DEFAULT_RANGE

    _init_db()
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT (ts / ?) * ? AS bucket_ts, SUM(success) AS ok_count, "
            "SUM(1 - success) AS fail_count FROM login_events WHERE ts >= ? "
            "GROUP BY bucket_ts ORDER BY bucket_ts",
            (bucket, bucket, int(time.time()) - window),
        ).fetchall()
    finally:
        conn.close()

    success = [{"ts": r["bucket_ts"], "v": r["ok_count"]} for r in rows]
    failed = [{"ts": r["bucket_ts"], "v": r["fail_count"]} for r in rows]
    return {
        "success": success,
        "failed": failed,
        "range": range_key,
        "generated_at": int(time.time()),
    }


def init_scheduler(app: Flask) -> None:
    """Register the daily prune job."""
    from apscheduler.schedulers.background import BackgroundScheduler

    _init_db()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=prune_old_data,
        trigger="cron",
        hour=3,
        minute=30,
        id="login_metrics_prune",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
