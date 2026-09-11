"""Device configuration backup age: fleet-wide daily sweep.

One call per non-forti* ADOM to FMGClient.get_adom_revisions() (confirmed
live against the lab FMG, v7.6.7-build3737, on 2026-09-11 — see
docs/superpowers/specs/2026-09-10-device-backup-age-spike.md for the spike
history and app.fmg_client.FMGClient.get_adom_revisions() for the confirmed
endpoint shape) plus one client.get_devices(adom) call to get the device
roster for that ADOM — same "one lightweight call per ADOM" batching
discipline as app.summary_job and app.executive_summary_cache's device
sweep, not a per-device call.

For each device, the most recent revision (by created_time) is classified:
  - devices_backup_ok        — last revision within 7 days
  - devices_backup_stale_7d  — last revision older than 7 days
  - devices_backup_never     — no revision found at all (never backed up,
                                distinct from merely stale)

Runs once daily (DEVICE_BACKUP_REFRESH_HOUR/MINUTE, default 02:00 local —
staggered from summary_job's 01:00), since backup age changes slowly and
this is a new FMG call not already covered by any other sweep. Persisted to
device_backup.json (gitignored, project root) after every successful sweep
so a restart doesn't blank the executive summary's device_backup fields —
same atomic-write, single-latest-record pattern as app.change_control_cache.
A failed sweep leaves the persisted file untouched.
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

_STORE_PATH = Path(__file__).parent.parent / "device_backup.json"

_STALE_SECONDS = 7 * 24 * 3600

_lock = threading.Lock()
_running = threading.Event()


# ── Pure aggregation (no I/O — unit-tested directly) ────────────────────────


def _classify_devices(
    devices_by_adom: dict[str, list[dict]],
    revisions_by_adom: dict[str, list[dict]],
    now_epoch: float,
) -> dict:
    """Bucket every device across all ADOMs into ok/stale/never.

    devices_by_adom: {adom: [device dict with "name", ...]}
    revisions_by_adom: {adom: [revision dict with "name", "created_time"]}
    """
    ok = 0
    stale = 0
    never = 0

    for adom, devices in devices_by_adom.items():
        revisions = revisions_by_adom.get(adom, [])
        for device in devices:
            if not isinstance(device, dict):
                continue
            name = device.get("name", "")
            if not name:
                continue
            prefix = f"{name}-"
            matches = [
                r
                for r in revisions
                if isinstance(r, dict) and str(r.get("name", "")).startswith(prefix)
            ]
            if not matches:
                never += 1
                continue
            last = max(r.get("created_time") or 0 for r in matches)
            age_seconds = now_epoch - last
            if age_seconds <= _STALE_SECONDS:
                ok += 1
            else:
                stale += 1

    return {
        "devices_backup_ok": ok,
        "devices_backup_stale_7d": stale,
        "devices_backup_never": never,
    }


def _list_target_adoms(client) -> list[str]:
    """Return non-forti* ADOM names — same convention as every other
    ADOM-enumerating sweep in this codebase (see CLAUDE.md)."""
    adoms_raw = client.get_adoms()
    return [
        a.get("name", "")
        for a in adoms_raw
        if isinstance(a, dict)
        and a.get("name")
        and not a.get("name", "").lower().startswith("forti")
    ]


# ── Persistence ──────────────────────────────────────────────────────────────


def get_latest() -> dict | None:
    """The last successfully persisted {devices_backup_ok,
    devices_backup_stale_7d, devices_backup_never, collected_at}, or None
    if no sweep has ever succeeded."""
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
    """Fetch device rosters + revision history once per non-forti* ADOM,
    classify, and persist. Returns True on success, False on error or
    overlap — on either failure mode the previously persisted result is
    left in place."""
    if _running.is_set():
        logger.info("device_backup_cache: already running, skipping overlap")
        return False

    _running.set()
    t0 = _time.monotonic()
    try:
        from app.fmg_helpers import make_client

        devices_by_adom: dict[str, list[dict]] = {}
        revisions_by_adom: dict[str, list[dict]] = {}

        with make_client() as client:
            adom_names = _list_target_adoms(client)
            for adom in adom_names:
                try:
                    devices_by_adom[adom] = client.get_devices(adom) or []
                except Exception as exc:
                    logger.warning(
                        "device_backup_cache: get_devices(%s) failed: %s", adom, exc
                    )
                    devices_by_adom[adom] = []
                try:
                    revisions_by_adom[adom] = client.get_adom_revisions(adom) or []
                except Exception as exc:
                    logger.warning(
                        "device_backup_cache: get_adom_revisions(%s) failed: %s",
                        adom,
                        exc,
                    )
                    revisions_by_adom[adom] = []

        counts = _classify_devices(devices_by_adom, revisions_by_adom, _time.time())
        record = {**counts, "collected_at": datetime.now(UTC).isoformat()}

        with _lock:
            _save(record)

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "device_backup_cache: sweep done in %ss — ok=%d stale_7d=%d never=%d",
            elapsed,
            counts["devices_backup_ok"],
            counts["devices_backup_stale_7d"],
            counts["devices_backup_never"],
        )
        return True
    except Exception:
        logger.exception(
            "device_backup_cache: sweep failed — keeping last persisted result"
        )
        return False
    finally:
        _running.clear()


def refresh_now(app) -> None:
    """Trigger an immediate background sweep (non-blocking)."""
    threading.Thread(
        target=_run_sweep,
        args=[app],
        name="device_backup_cache_refresh",
        daemon=True,
    ).start()


def init_scheduler(app):
    """Register the daily sweep with APScheduler and fire it once immediately."""
    import os

    from apscheduler.schedulers.background import BackgroundScheduler

    refresh_hour = int(os.environ.get("DEVICE_BACKUP_REFRESH_HOUR", "2"))
    refresh_minute = int(os.environ.get("DEVICE_BACKUP_REFRESH_MINUTE", "0"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_sweep,
        args=[app],
        trigger="cron",
        hour=refresh_hour,
        minute=refresh_minute,
        id="device_backup_refresh",
        name="Daily device backup age sweep",
    )
    scheduler.start()
    logger.info(
        "device_backup_cache: scheduler started — daily at %02d:%02d local time",
        refresh_hour,
        refresh_minute,
    )

    threading.Thread(
        target=_run_sweep,
        args=[app],
        name="device_backup_cache_startup",
        daemon=True,
    ).start()

    return scheduler
