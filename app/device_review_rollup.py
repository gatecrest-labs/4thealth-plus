"""Fleet-wide device-review rollup: aggregation + persisted history.

Aggregation mirrors app.device_review_scheduler._build_check_summary's
name-to-key lookup pattern (row["check"] holds the check's display NAME,
not its key -- unlike app.hygiene's findings, which key by check key
directly). Persistence follows the same JSON-file-at-project-root pattern
as app.hygiene_rollup / app.device_review_scheduler's device_review_jobs.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.atomic_io import atomic_write_json
from app.device_review import CHECKS_META
from app.device_review_severity import SEVERITY

_ROLLUP_PATH = Path(__file__).parent.parent / "device_review_rollup.json"
_MAX_RUNS = 30

_name_to_key: dict[str, str] = {c["name"]: c["key"] for c in CHECKS_META}


def _severity_for_key(key: str) -> str:
    return SEVERITY.get(key, "low")


_NON_FAILURE_RESULTS = {"PASS", "INFO"}


def build_rollup(results: list[dict]) -> dict:
    """Aggregate a bulk_device_review_adom()-shaped result list into fleet counts.

    results: list of {device, ip, rows, error} as returned by
    app.routes.device_review_routes.bulk_device_review_adom(). Devices with
    a non-None "error" contribute no rows and are excluded from
    devices_reviewed/devices_with_failures (they weren't actually reviewed).
    """
    reviewed = [d for d in results if not d.get("error")]
    devices_with_failures = 0
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    failing_check_counts: dict[str, int] = {}

    for dev in reviewed:
        device_failed = False
        for row in dev.get("rows", []):
            if row.get("result") in _NON_FAILURE_RESULTS:
                continue
            device_failed = True
            key = _name_to_key.get(row.get("check", ""))
            if key is None:
                continue
            findings_by_severity[_severity_for_key(key)] += 1
            failing_check_counts[key] = failing_check_counts.get(key, 0) + 1
        if device_failed:
            devices_with_failures += 1

    top_failing_checks = [
        {"check": key, "count": count}
        for key, count in sorted(
            failing_check_counts.items(), key=lambda kv: kv[1], reverse=True
        )[:3]
    ]

    return {
        "devices_reviewed": len(reviewed),
        "devices_with_failures": devices_with_failures,
        "findings_by_severity": findings_by_severity,
        "top_failing_checks": top_failing_checks,
    }


def get_history() -> list[dict]:
    """Return the rollup history, newest first, or [] if none exists yet."""
    if not _ROLLUP_PATH.exists():
        return []
    try:
        data = json.loads(_ROLLUP_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def get_latest() -> dict | None:
    """Return the most recent rollup record, or None if no history exists."""
    history = get_history()
    return history[0] if history else None


def append_run(record: dict) -> None:
    """Prepend a new rollup record, keeping at most _MAX_RUNS entries."""
    history = get_history()
    history.insert(0, record)
    atomic_write_json(_ROLLUP_PATH, history[:_MAX_RUNS])
