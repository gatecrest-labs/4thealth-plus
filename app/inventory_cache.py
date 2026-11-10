"""Collector-owned inventory refresh (F2).

One ``/dvmdb/adom`` call, then per non-``forti*`` ADOM one device list and one
ADOM-wide ``_package/status`` call, written to the shared store (see
``app.inventory_store``). Consumers read through ``app.inventory``; this module
is the only place that fetches the inventory from FortiManager when
``INVENTORY_CACHE`` is on.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from app import inventory_store
from app.config import Config

logger = logging.getLogger(__name__)

_running = threading.Lock()


def _make_client():
    from app.fmg_helpers import make_client

    return make_client()


def _make_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler

    return BackgroundScheduler()


def _refresh_adom(client, adom: str, counter: list) -> bool:
    """Refresh one ADOM; returns False (and marks it) when its device fetch fails."""
    try:
        devices = client.get_devices(adom) or []
        counter.append(1)
    except Exception as exc:
        logger.warning("inventory_cache: get_devices(%s) failed: %s", adom, exc)
        try:
            inventory_store.mark_adom_error(adom, str(exc))
        except Exception:
            logger.warning("inventory_cache: could not record error for %s", adom)
        return False
    pkg_rows = None  # None keeps the previous package rows if the bulk call fails
    try:
        pkg_rows = client.get_adom_package_status(adom)
        counter.append(1)
    except Exception as exc:
        logger.warning(
            "inventory_cache: package status for %s failed (keeping previous): %s",
            adom,
            exc,
        )
    inventory_store.replace_adom(adom, devices, pkg_rows, datetime.now(UTC).isoformat())
    return True


def _refresh(client) -> dict:
    started = time.monotonic()
    calls: list = []
    adoms = client.get_adoms() or []
    calls.append(1)
    inventory_store.write_adom_list(adoms)
    names = [
        a["name"]
        for a in adoms
        if isinstance(a, dict)
        and a.get("name")
        and not a["name"].lower().startswith("forti")
    ]
    workers = max(1, int(Config.INVENTORY_PARALLEL_ADOMS or 1))
    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for adom, ok in zip(
            names,
            pool.map(lambda a: _refresh_adom(client, a, calls), names),
            strict=True,
        ):
            if not ok:
                failed.append(adom)
    inventory_store.delete_missing_adoms(set(names))
    total = sum(
        (inventory_store.read_meta(a) or {}).get("device_count", 0) for a in names
    )
    return {
        "adoms": len(names),
        "devices": total,
        "failed": failed,
        "seconds": round(time.monotonic() - started, 2),
        "fmg_calls": len(calls),
    }


def refresh_once(client=None) -> dict:
    """Refresh the whole inventory once. Single-flight: a concurrent call is skipped."""
    if not _running.acquire(blocking=False):
        return {"skipped": True}
    try:
        if client is not None:
            result = _refresh(client)
        else:
            with _make_client() as live:
                result = _refresh(live)
        logger.info("inventory_cache: refreshed %s", result)
        return result
    finally:
        _running.release()


def _run_refresh(app=None) -> None:
    try:
        refresh_once()
    except Exception:
        logger.exception("inventory_cache: refresh failed")


def poll_refresh_request() -> None:
    """Run a refresh now if the web UI asked for one (Refresh button)."""
    try:
        if inventory_store.pop_refresh_request():
            _run_refresh()
    except Exception:
        logger.exception("inventory_cache: refresh-request poll failed")


def _first_refresh(app) -> None:
    try:
        _run_refresh(app)
    finally:
        from app import boot_warmup

        boot_warmup.mark_inventory_ready()


def _start_first_refresh(app) -> None:
    from app import boot_warmup

    boot_warmup.defer("inventory", lambda: _first_refresh(app), priority=0)


def init_scheduler(app) -> bool:
    """Register the refresh jobs (collector only, ``INVENTORY_CACHE`` on)."""
    if not Config.INVENTORY_CACHE:
        return False
    scheduler = _make_scheduler()
    scheduler.add_job(
        func=_run_refresh,
        args=[app],
        trigger="interval",
        seconds=max(30, int(Config.INVENTORY_REFRESH_SECS)),
        id="inventory_refresh",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        func=poll_refresh_request,
        trigger="interval",
        seconds=10,
        id="inventory_refresh_request_poll",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    _start_first_refresh(app)
    return True
