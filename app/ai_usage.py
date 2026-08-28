"""AI Assist usage/cost tracking — SQLite-backed.

One row per AI Assist LLM call (success or failure), recorded from inside
each provider's ``narrate()`` (see app/llm/*_provider.py). SQLite (stdlib,
no new dependency) rather than another flat JSON file: this is genuinely
time-series data needing range queries, unlike this app's other JSON
runtime-data files.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from pathlib import Path

_DB_PATH = Path(__file__).parent.parent / "ai_usage.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cost_usd REAL NOT NULL,
    success INTEGER NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_usage_timestamp ON ai_usage (timestamp);
"""


def _init_db() -> None:
    conn = sqlite3.connect(_DB_PATH)
    try:
        conn.executescript(_SCHEMA)
        # Idempotent migration for databases created before attribution existed.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(ai_usage)")}
        if "feature" not in columns:
            conn.execute("ALTER TABLE ai_usage ADD COLUMN feature TEXT")
        if "user" not in columns:
            conn.execute("ALTER TABLE ai_usage ADD COLUMN user TEXT")
        conn.commit()
    finally:
        conn.close()


def record_usage(
    *,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
    success: bool,
    feature: str,
    user: str | None = None,
    error: str | None = None,
) -> None:
    """Record one AI Assist LLM call. Never raises — a tracking failure
    must never break the actual AI Assist request that triggered it."""
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        try:
            conn.execute(
                "INSERT INTO ai_usage (timestamp, provider, model, input_tokens, "
                "output_tokens, cost_usd, success, error, feature, user) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    dt.datetime.now(dt.UTC).isoformat(),
                    provider,
                    model,
                    input_tokens,
                    output_tokens,
                    cost_usd,
                    1 if success else 0,
                    error,
                    feature,
                    user,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def query_usage(start: dt.datetime, end: dt.datetime) -> list[dict]:
    """Raw usage rows with timestamp in [start, end], oldest first."""
    _init_db()
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM ai_usage WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp",
            (start.isoformat(), end.isoformat()),
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "provider": r["provider"],
            "model": r["model"],
            "input_tokens": r["input_tokens"],
            "output_tokens": r["output_tokens"],
            "cost_usd": r["cost_usd"],
            "success": bool(r["success"]),
            "error": r["error"],
            "feature": r["feature"],
            "user": r["user"],
        }
        for r in rows
    ]


def usage_summary(
    start: dt.datetime,
    end: dt.datetime,
    num_buckets: int = 24,
    *,
    by_feature: bool = False,
) -> dict:
    """Bucket the [start, end] range into num_buckets equal time slices,
    plus running totals for the whole range.

    With by_feature=True, also adds a "by_feature" key mapping each feature
    label (rows predating attribution count as "unknown") to its own
    calls/cost_usd/failures totals.
    """
    rows = query_usage(start, end)

    span = (end - start).total_seconds()
    bucket_seconds = span / num_buckets if num_buckets > 0 else span
    buckets = []
    for i in range(num_buckets):
        b_start = start + dt.timedelta(seconds=bucket_seconds * i)
        b_end = start + dt.timedelta(seconds=bucket_seconds * (i + 1))
        buckets.append(
            {
                "start": b_start.isoformat(),
                "end": b_end.isoformat(),
                "count": 0,
                "cost_usd": 0.0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
        )

    total_calls = 0
    total_cost = 0.0
    total_failures = 0
    total_input = 0
    total_output = 0

    for row in rows:
        total_calls += 1
        total_cost += row["cost_usd"]
        total_input += row["input_tokens"]
        total_output += row["output_tokens"]
        if not row["success"]:
            total_failures += 1

        ts = dt.datetime.fromisoformat(row["timestamp"])
        if bucket_seconds > 0:
            idx = int((ts - start).total_seconds() // bucket_seconds)
            idx = max(0, min(idx, num_buckets - 1))
        else:
            idx = 0
        buckets[idx]["count"] += 1
        buckets[idx]["cost_usd"] += row["cost_usd"]
        buckets[idx]["input_tokens"] += row["input_tokens"]
        buckets[idx]["output_tokens"] += row["output_tokens"]

    result = {
        "buckets": buckets,
        "total_calls": total_calls,
        "total_cost_usd": total_cost,
        "total_failures": total_failures,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
    }
    if by_feature:
        by_feature_totals: dict[str, dict] = {}
        for row in rows:
            key = row["feature"] or "unknown"
            entry = by_feature_totals.setdefault(
                key, {"calls": 0, "cost_usd": 0.0, "failures": 0}
            )
            entry["calls"] += 1
            entry["cost_usd"] += row["cost_usd"]
            if not row["success"]:
                entry["failures"] += 1
        result["by_feature"] = by_feature_totals
    return result
