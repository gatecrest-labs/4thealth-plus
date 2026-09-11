"""Change-control metrics: FortiManager admin audit-log aggregation.

A light hourly background job calling FMGClient.get_audit_log(hours=24)
ONCE (the audit log is FortiManager-instance-wide, not per-ADOM — unlike
app.executive_summary_cache's device sweep), aggregating admin_changes_24h
(total entry count) and admin_changes_by_user (top 5, as [{user, count}]).

Persisted to change_control.json (gitignored, project root) after every
successful sweep so a restart doesn't blank the executive summary's
change_control fields until the next hourly run completes — same
JSON-file-at-project-root, atomic-write pattern as app.device_review_rollup
/ app.hygiene_rollup. Unlike those, only the single latest result is kept
(there's no history use case here yet), so this stores one record, not a
list.

A failed sweep (FMG unreachable, endpoint unsupported by the FMG version,
etc.) leaves the persisted file untouched — get_latest() keeps returning
the last successful result rather than surfacing a gap.

Field-name caveat: this repo has no vendored FortiManager /sys/audit-log
schema reference. aggregate_audit_log() reads each entry's "user" field,
which matches Fortinet's documented audit-log shape — if
admin_changes_by_user comes back empty on a real FMG despite other change
activity, verify the actual field name with a raw call and adjust here.
"""

from __future__ import annotations

import json
import logging
import threading
import time as _time
from datetime import UTC, datetime
from pathlib import Path

from app.atomic_io import atomic_write_json

logger = logging.getLogger(__name__)

_STORE_PATH = Path(__file__).parent.parent / "change_control.json"

_TOP_USERS = 5

_lock = threading.Lock()
_running = threading.Event()


# ── Pure aggregation (no I/O — unit-tested directly) ────────────────────────


def aggregate_audit_log(entries: list[dict]) -> dict:
    """admin_changes_24h (total entry count) and admin_changes_by_user (top
    5 as [{user, count}], ties broken by first-seen order for determinism).
    """
    counts: dict[str, int] = {}
    order: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        user = str(entry.get("user") or "unknown")
        if user not in counts:
            counts[user] = 0
            order.append(user)
        counts[user] += 1

    ranked = sorted(order, key=lambda u: (-counts[u], order.index(u)))
    top_users = [{"user": u, "count": counts[u]} for u in ranked[:_TOP_USERS]]

    return {
        "admin_changes_24h": len(entries),
        "admin_changes_by_user": top_users,
    }


# ── Persistence ──────────────────────────────────────────────────────────────


def get_latest() -> dict | None:
    """The last successfully persisted {admin_changes_24h,
    admin_changes_by_user, collected_at}, or None if no sweep has ever
    succeeded."""
    if not _STORE_PATH.exists():
        return None
    try:
        data = json.loads(_STORE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _save(record: dict) -> None:
    atomic_write_json(_STORE_PATH, record)


# ── Sweep ────────────────────────────────────────────────────────────────────


def _run_sweep(app) -> bool:
    """Fetch the last 24h of FMG admin audit-log entries once, aggregate,
    and persist. Returns True on success, False on error or overlap — on
    either failure mode the previously persisted result is left in place."""
    if _running.is_set():
        logger.info("change_control_cache: already running, skipping overlap")
        return False

    _running.set()
    t0 = _time.monotonic()
    try:
        from app.fmg_helpers import make_client

        with make_client() as client:
            entries = client.get_audit_log(hours=24)

        aggregated = aggregate_audit_log(entries)
        record = {**aggregated, "collected_at": datetime.now(UTC).isoformat()}

        with _lock:
            _save(record)

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "change_control_cache: sweep done in %ss — %d admin change(s) in 24h",
            elapsed,
            aggregated["admin_changes_24h"],
        )
        return True
    except Exception:
        logger.exception(
            "change_control_cache: sweep failed — keeping last persisted result"
        )
        return False
    finally:
        _running.clear()


def refresh_now(app) -> None:
    """Trigger an immediate background sweep (non-blocking)."""
    threading.Thread(
        target=_run_sweep,
        args=[app],
        name="change_control_cache_refresh",
        daemon=True,
    ).start()


def init_scheduler(app):
    """Start the hourly audit-log sweep and fire an immediate warm-up."""
    from apscheduler.schedulers.background import BackgroundScheduler

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_sweep,
        args=[app],
        trigger="interval",
        hours=1,
        id="change_control_audit_log_refresh",
        name="Change-control admin audit-log sweep",
    )
    scheduler.start()
    logger.info("change_control_cache: scheduler started — every 1 hour")

    threading.Thread(
        target=_run_sweep,
        args=[app],
        name="change_control_cache_startup",
        daemon=True,
    ).start()

    return scheduler
