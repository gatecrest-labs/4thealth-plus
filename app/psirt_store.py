"""Persistent PSIRT advisory assessments — SQLite-backed (psirt.db).

The PSIRT engine (app/psirt/engine.py) is otherwise stateless: every
Advisory Assessment run in Audit Review > PSIRT vanished once the response
left the server. This module gives assessments a durable home so:

  - Directors can see fleet-wide exposure without re-running every advisory
    (see compute_psirt_rollup(), consumed by the executive summary).
  - A remediated advisory can be marked "closed" so it stops counting
    towards open exposure (close_advisory()), and mean-time-to-remediate
    can be computed from that history.
  - A scheduler (app/psirt_reassess_scheduler.py) can re-run assess() for
    every still-open advisory on a cadence, without the user re-pasting the
    advisory email each time.

Two tables:
  advisories  — one row per advisory, upserted on every save. ``closed_at``
                is only ever set by close_advisory() — saving a fresh
                assessment (manual or scheduled) never reopens or closes an
                advisory on its own.
  assessments — one row per assess() run, append-only history.

JSON columns (cves, affected_ranges, devices_affected, summary) are stored
as TEXT via json.dumps/json.loads — this is runtime data with a handful of
rows per advisory, not a hot path needing real columns.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path

_DB_PATH = Path(__file__).parent.parent / "psirt.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT PRIMARY KEY,
    cves TEXT NOT NULL,
    cvss REAL,
    severity TEXT,
    kev INTEGER NOT NULL DEFAULT 0,
    affected_ranges TEXT NOT NULL,
    workaround_text TEXT,
    created_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    ran_at TEXT NOT NULL,
    devices_affected TEXT NOT NULL,
    summary TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assessments_advisory_id ON assessments (advisory_id);
CREATE INDEX IF NOT EXISTS idx_assessments_ran_at ON assessments (ran_at);
"""

_MEAN_REMEDIATION_WINDOW_DAYS = 90


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _init_db() -> None:
    conn = sqlite3.connect(_DB_PATH)
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _connect() -> sqlite3.Connection:
    _init_db()
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Writes ──────────────────────────────────────────────────────────────────


def save_assessment_result(assessment: dict) -> None:
    """Persist one completed PsirtAssessment.to_dict() result.

    Upserts the advisory row (refreshing cvss/severity/kev/affected_ranges/
    workaround_text from the advisory that was actually assessed —
    enrichment can change these between runs — but leaving created_at and
    closed_at untouched) and appends one assessments row.

    devices_affected is derived from findings with in_range=True (the
    device's firmware falls in the advisory's affected range, regardless of
    whether a workaround is in place — that distinction lives in
    workaround_applied, not in whether the device is counted at all).
    """
    advisory = assessment.get("advisory") or {}
    advisory_id = str(advisory.get("advisory_id", "")).strip()
    if not advisory_id:
        raise ValueError("assessment.advisory.advisory_id is required")

    findings = assessment.get("findings") or []
    devices_affected = [
        {
            "name": f.get("device", ""),
            "adom": f.get("adom", ""),
            "version": f.get("current_version", ""),
            "workaround_applied": f.get("workaround_status") == "in_place",
        }
        for f in findings
        if f.get("in_range")
    ]
    verdict_counts: dict[str, int] = {}
    for f in findings:
        v = f.get("verdict", "unknown")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1
    summary = {
        "priority": assessment.get("priority", ""),
        "priority_rationale": assessment.get("priority_rationale", ""),
        "kev_hit": bool(assessment.get("kev_hit", False)),
        "degraded": bool(assessment.get("degraded", False)),
        "warnings": list(assessment.get("warnings") or []),
        "findings_count": len(findings),
        "verdict_counts": verdict_counts,
    }

    now = _now_iso()
    conn = _connect()
    try:
        existing = conn.execute(
            "SELECT created_at FROM advisories WHERE advisory_id = ?",
            (advisory_id,),
        ).fetchone()
        created_at = existing["created_at"] if existing else now
        conn.execute(
            "INSERT INTO advisories "
            "(advisory_id, cves, cvss, severity, kev, affected_ranges, "
            "workaround_text, created_at, closed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
            "COALESCE((SELECT closed_at FROM advisories WHERE advisory_id = ?), NULL)) "
            "ON CONFLICT(advisory_id) DO UPDATE SET "
            "cves=excluded.cves, cvss=excluded.cvss, severity=excluded.severity, "
            "kev=excluded.kev, affected_ranges=excluded.affected_ranges, "
            "workaround_text=excluded.workaround_text",
            (
                advisory_id,
                json.dumps(advisory.get("cve_ids") or []),
                advisory.get("cvss_score"),
                advisory.get("fortinet_severity", ""),
                1 if assessment.get("kev_hit") else 0,
                json.dumps(advisory.get("affected_ranges") or []),
                advisory.get("workaround_text", ""),
                created_at,
                advisory_id,
            ),
        )
        conn.execute(
            "INSERT INTO assessments (advisory_id, ran_at, devices_affected, summary) "
            "VALUES (?, ?, ?, ?)",
            (advisory_id, now, json.dumps(devices_affected), json.dumps(summary)),
        )
        conn.commit()
    finally:
        conn.close()


def close_advisory(advisory_id: str) -> bool:
    """Set closed_at on the advisory. Returns False if it doesn't exist."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT advisory_id FROM advisories WHERE advisory_id = ?",
            (advisory_id,),
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "UPDATE advisories SET closed_at = ? WHERE advisory_id = ?",
            (_now_iso(), advisory_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def reopen_advisory(advisory_id: str) -> bool:
    """Clear closed_at. Returns False if it doesn't exist."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT advisory_id FROM advisories WHERE advisory_id = ?",
            (advisory_id,),
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "UPDATE advisories SET closed_at = NULL WHERE advisory_id = ?",
            (advisory_id,),
        )
        conn.commit()
        return True
    finally:
        conn.close()


# ── Reads ───────────────────────────────────────────────────────────────────


def _row_to_advisory(row: sqlite3.Row) -> dict:
    return {
        "advisory_id": row["advisory_id"],
        "cves": json.loads(row["cves"]),
        "cvss": row["cvss"],
        "severity": row["severity"],
        "kev": bool(row["kev"]),
        "affected_ranges": json.loads(row["affected_ranges"]),
        "workaround_text": row["workaround_text"],
        "created_at": row["created_at"],
        "closed_at": row["closed_at"],
    }


def get_advisory(advisory_id: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM advisories WHERE advisory_id = ?", (advisory_id,)
        ).fetchone()
        return _row_to_advisory(row) if row else None
    finally:
        conn.close()


def get_open_advisories() -> list[dict]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM advisories WHERE closed_at IS NULL ORDER BY created_at"
        ).fetchall()
        return [_row_to_advisory(r) for r in rows]
    finally:
        conn.close()


def get_latest_assessment(advisory_id: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM assessments WHERE advisory_id = ? "
            "ORDER BY ran_at DESC LIMIT 1",
            (advisory_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "advisory_id": row["advisory_id"],
            "ran_at": row["ran_at"],
            "devices_affected": json.loads(row["devices_affected"]),
            "summary": json.loads(row["summary"]),
        }
    finally:
        conn.close()


def list_advisories(*, open_only: bool = False) -> list[dict]:
    """Every advisory (or just open ones), each with its latest assessment
    summary merged in for the UI's "Open PSIRT Advisories" table."""
    advisories = get_open_advisories() if open_only else _get_all_advisories()
    out = []
    for adv in advisories:
        latest = get_latest_assessment(adv["advisory_id"])
        out.append(
            {
                **adv,
                "latest_assessment": latest,
            }
        )
    return out


def _get_all_advisories() -> list[dict]:
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM advisories ORDER BY created_at").fetchall()
        return [_row_to_advisory(r) for r in rows]
    finally:
        conn.close()


# ── Executive summary rollup ────────────────────────────────────────────────

_PRIORITY_RANK = {
    "unknown": -1,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def compute_mean_days_to_remediate(now: dt.datetime | None = None) -> float | None:
    """Mean days between created_at and closed_at for advisories closed in
    the trailing 90 days. None if none were closed in that window."""
    now = now or dt.datetime.now(dt.UTC)
    cutoff = now - dt.timedelta(days=_MEAN_REMEDIATION_WINDOW_DAYS)
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT created_at, closed_at FROM advisories WHERE closed_at IS NOT NULL"
        ).fetchall()
    finally:
        conn.close()

    days: list[float] = []
    for row in rows:
        try:
            closed = dt.datetime.fromisoformat(row["closed_at"])
            created = dt.datetime.fromisoformat(row["created_at"])
        except (TypeError, ValueError):
            continue
        if closed < cutoff:
            continue
        days.append((closed - created).total_seconds() / 86400)

    if not days:
        return None
    return round(sum(days) / len(days), 1)


_MAX_TOP_ADVISORY_DEVICES = 50


def _top_advisory_devices(devices_affected: list[dict]) -> list[dict]:
    """Capped, most-urgent-first device list for psirt.top_advisory.devices.

    Devices without the workaround applied sort first (still fully
    exposed), tie-broken by adom then device name.
    """
    entries = [
        {
            "device": d.get("name", ""),
            "adom": d.get("adom", ""),
            "version": d.get("version", ""),
            "workaround_applied": bool(d.get("workaround_applied")),
        }
        for d in devices_affected
    ]
    entries.sort(key=lambda d: (d["workaround_applied"], d["adom"], d["device"]))
    return entries[:_MAX_TOP_ADVISORY_DEVICES]


def compute_psirt_rollup(now: dt.datetime | None = None) -> dict:
    """Fleet PSIRT exposure for the executive summary payload's "psirt" key.

    devices_critical / devices_high / devices_medium count every affected
    device (devices_affected, regardless of workaround status) on OPEN
    advisories whose priority falls in that band. devices_critical_mitigated
    is a SEPARATE, half-weighted count of critical-band devices that already
    have the workaround applied — it is never silently subtracted from
    devices_critical, per the spec's "never silently" requirement.
    """
    now = now or dt.datetime.now(dt.UTC)
    open_advisories = get_open_advisories()

    devices_critical = 0
    devices_high = 0
    devices_medium = 0
    critical_mitigated_count = 0
    kev_devices: set[tuple[str, str]] = set()

    top_advisory: dict | None = None
    top_rank = -2
    top_cvss = -1.0
    top_device_count = -1

    for adv in open_advisories:
        latest = get_latest_assessment(adv["advisory_id"])
        if latest is None:
            continue
        devices_affected = latest["devices_affected"]
        priority = latest["summary"].get("priority", "")
        rank = _PRIORITY_RANK.get(priority, -1)

        if priority == "critical":
            devices_critical += len(devices_affected)
            critical_mitigated_count += sum(
                1 for d in devices_affected if d.get("workaround_applied")
            )
        elif priority == "high":
            devices_high += len(devices_affected)
        elif priority == "medium":
            devices_medium += len(devices_affected)

        if adv["kev"]:
            for d in devices_affected:
                kev_devices.add((d.get("name", ""), d.get("adom", "")))

        cvss = adv["cvss"] if adv["cvss"] is not None else -1.0
        device_count = len(devices_affected)
        is_better = (
            rank > top_rank
            or (rank == top_rank and cvss > top_cvss)
            or (
                rank == top_rank
                and cvss == top_cvss
                and device_count > top_device_count
            )
        )
        if is_better:
            top_rank, top_cvss, top_device_count = rank, cvss, device_count
            top_advisory = {
                "advisory_id": adv["advisory_id"],
                "cvss": adv["cvss"],
                "kev": adv["kev"],
                "device_count": device_count,
                "devices": _top_advisory_devices(devices_affected),
            }

    return {
        "open_advisories": len(open_advisories),
        "devices_critical": devices_critical,
        "devices_high": devices_high,
        "devices_medium": devices_medium,
        "devices_critical_mitigated": round(critical_mitigated_count * 0.5, 1),
        "kev_exposed_devices": len(kev_devices),
        "top_advisory": top_advisory,
        "mean_days_to_remediate_90d": compute_mean_days_to_remediate(now),
        "collected_at": now.isoformat(),
    }
