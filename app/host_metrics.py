"""Host resource metrics — CPU/memory/disk, SQLite-backed.

Samples psutil every 60 seconds into host_metrics.db (gitignored, project
root — same pattern as app/ai_usage.py). A daily job prunes rows older than
90 days. GET /admin/api/host-metrics reads aggregated, time-bucketed rows
for the Admin page graphs.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import psutil
from flask import Flask

_DB_PATH = Path(__file__).parent.parent / "host_metrics.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS host_metrics (
    ts   INTEGER NOT NULL,
    cpu  REAL,
    mem  REAL,
    disk REAL
);
CREATE INDEX IF NOT EXISTS idx_host_metrics_ts ON host_metrics (ts);
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


def _connect() -> sqlite3.Connection:
    # timeout=30 + WAL: this file is now written by the collector process
    # and read by the web process concurrently (see app/collector.py) —
    # WAL avoids the reader/writer lock contention the default rollback
    # journal hits under that access pattern (same fix as
    # app/collector_store.py).
    conn = sqlite3.connect(_DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db() -> None:
    conn = _connect()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def record_sample() -> None:
    """Sample CPU/mem/disk and insert one row. Never raises."""
    try:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent

        _init_db()
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO host_metrics (ts, cpu, mem, disk) VALUES (?, ?, ?, ?)",
                (int(time.time()), cpu, mem, disk),
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
        conn = _connect()
        try:
            conn.execute("DELETE FROM host_metrics WHERE ts < ?", (cutoff,))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def get_metrics(range_key: str) -> dict:
    """Bucketed cpu/mem/disk series for range_key (defaults to 1h if invalid)."""
    window, bucket = _RANGES.get(range_key, _RANGES[_DEFAULT_RANGE])
    if range_key not in _RANGES:
        range_key = _DEFAULT_RANGE

    _init_db()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT (ts / ?) * ? AS bucket_ts, AVG(cpu) AS cpu, AVG(mem) AS mem, "
            "AVG(disk) AS disk FROM host_metrics WHERE ts >= ? GROUP BY bucket_ts "
            "ORDER BY bucket_ts",
            (bucket, bucket, int(time.time()) - window),
        ).fetchall()
    finally:
        conn.close()

    cpu = [{"ts": r["bucket_ts"], "v": r["cpu"]} for r in rows]
    mem = [{"ts": r["bucket_ts"], "v": r["mem"]} for r in rows]
    disk = [{"ts": r["bucket_ts"], "v": r["disk"]} for r in rows]
    return {
        "cpu": cpu,
        "mem": mem,
        "disk": disk,
        "range": range_key,
        "generated_at": int(time.time()),
    }


def init_scheduler(app: Flask) -> None:
    """Register the 60s sampling job and the daily prune job."""
    from apscheduler.schedulers.background import BackgroundScheduler

    record_sample()  # initial sample at startup, cheap and non-blocking

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=record_sample,
        trigger="interval",
        seconds=60,
        id="host_metrics_sample",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.add_job(
        func=prune_old_data,
        trigger="cron",
        hour=3,
        minute=0,
        id="host_metrics_prune",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
