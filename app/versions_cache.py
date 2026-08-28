"""All-devices version cache — pre-warmed at startup, refreshed every 30 minutes.

Keeps the /api/devices/all result in memory so the Device Versions page loads
instantly instead of waiting for a live FMG sweep of all ADOMs.

State
-----
_store["devices"]      list[dict]  — cached device records
_store["last_updated"] str | None  — ISO-8601 UTC timestamp of last successful run
_store["status"]       str         — "pending" | "running" | "ok" | "error"
_store["error"]        str | None  — last error message, if any

The scheduler fires every 30 minutes (configurable via VERSIONS_CACHE_INTERVAL_MIN).
A manual refresh is triggered by calling refresh_now(app).
"""

import logging
import os
import threading
import time as _time
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

_store: dict = {
    "devices": [],
    "last_updated": None,
    "status": "pending",
    "error": None,
}

_lock = threading.Lock()
_running = threading.Event()


def get_cached() -> dict:
    """Return a copy of the cache store — safe to read from any thread."""
    with _lock:
        return dict(_store)


def _run_job(app):
    """Fetch all-ADOM device list and update the cache. Runs inside app context."""
    if _running.is_set():
        logger.info("versions_cache: already running, skipping overlap")
        return

    _running.set()
    with _lock:
        _store["status"] = "running"
        _store["error"] = None

    logger.info("versions_cache: starting refresh")
    t0 = _time.monotonic()

    try:
        from app.fmg_helpers import make_client

        result = []
        with make_client() as client:
            adoms_raw = client.get_adoms()
            adom_names = [
                a.get("name", "")
                for a in adoms_raw
                if isinstance(a, dict) and a.get("name")
            ]
            adom_names = [
                n for n in adom_names if n and not n.lower().startswith("forti")
            ]

            for adom in adom_names:
                try:
                    raw = client.get_devices(adom)
                    for d in raw:
                        if not isinstance(d, dict):
                            continue
                        os_ver = d.get("os_ver", 0)
                        mr = d.get("mr")
                        patch = d.get("patch")
                        major = (
                            int(os_ver) // 100
                            if str(os_ver).isdigit() and int(os_ver) >= 100
                            else os_ver
                        )
                        if mr is not None and patch is not None and int(patch) >= 0:
                            version = f"v{major}.{mr}.{patch}"
                        elif mr is not None:
                            version = f"v{major}.{mr}"
                        else:
                            version = "n/a"
                        conn_status = d.get(
                            "conn_status", d.get("connection_status", -1)
                        )
                        result.append(
                            {
                                "name": d.get("name", ""),
                                "version": version,
                                "adom": adom,
                                "status": "green" if conn_status == 1 else "offline",
                            }
                        )
                except Exception as exc:
                    logger.warning(
                        "versions_cache: get_devices(%s) failed: %s", adom, exc
                    )

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "versions_cache: done in %ss — %d devices across %d ADOMs",
            elapsed,
            len(result),
            len(adom_names),
        )

        with _lock:
            _store["devices"] = result
            _store["last_updated"] = datetime.now(UTC).isoformat()
            _store["status"] = "ok"
            _store["error"] = None

    except Exception as exc:
        logger.exception("versions_cache: unhandled error")
        with _lock:
            _store["status"] = "error"
            _store["error"] = str(exc)
    finally:
        _running.clear()


def refresh_now(app):
    """Trigger an immediate background refresh (non-blocking)."""
    t = threading.Thread(
        target=_run_job, args=[app], name="versions_cache_refresh", daemon=True
    )
    t.start()


def init_scheduler(app):
    """Start the 30-minute refresh scheduler and fire an initial warm-up immediately."""
    from apscheduler.schedulers.background import BackgroundScheduler

    interval_min = int(os.environ.get("VERSIONS_CACHE_INTERVAL_MIN", "30"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_job,
        args=[app],
        trigger="interval",
        minutes=interval_min,
        id="versions_cache_refresh",
        name="Versions cache refresh",
    )
    scheduler.start()
    logger.info("versions_cache: scheduler started — every %d minutes", interval_min)

    # Warm the cache immediately at startup
    t = threading.Thread(
        target=_run_job, args=[app], name="versions_cache_startup", daemon=True
    )
    t.start()

    return scheduler
