"""Background cache for DIFF-tab device list + pkg_status per ADOM.

Runs a 30-minute APScheduler interval job that fetches every non-forti
ADOM's device list (conf_status, db_status) and pkg_status in parallel
(10-worker ThreadPoolExecutor, matching the live route).  Results are
stored in a lock-guarded in-memory dict; the /api/pending-changes/adoms/
<adom>/devices route reads from this cache instead of blocking on FMG.

Thread-safety: a single RLock guards _cache and _state.  Callers receive
snapshot copies so the lock is held only briefly.
"""

from __future__ import annotations

import datetime
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask

logger = logging.getLogger(__name__)

_lock = threading.RLock()

# Keyed by ADOM name → {"devices": [...], "last_updated": ISO str}
_cache: dict[str, dict] = {}

_state: dict = {
    "status": "pending",  # "pending" | "running" | "ok" | "error"
    "last_updated": None,  # ISO-8601 string or None
    "error": None,
}

_REFRESH_MINUTES = 30


# ── Public API ────────────────────────────────────────────────────────────────


def get_cached_devices(adom: str) -> list[dict] | None:
    """Return a snapshot of cached devices for *adom*, or None if not cached."""
    with _lock:
        entry = _cache.get(adom)
        if entry is None:
            return None
        return list(entry["devices"])


def get_all_cached_devices() -> dict[str, list[dict]]:
    """Return a snapshot of every cached ADOM's device list, keyed by ADOM name."""
    with _lock:
        return {adom: list(entry["devices"]) for adom, entry in _cache.items()}


def get_cache_status() -> dict:
    """Return a snapshot of overall cache state."""
    with _lock:
        return {
            "status": _state["status"],
            "last_updated": _state["last_updated"],
            "adoms_cached": len(_cache),
            "error": _state.get("error"),
        }


# ── Refresh logic ─────────────────────────────────────────────────────────────


def _run_refresh(app: Flask) -> None:
    try:
        with app.app_context():
            with _lock:
                if _state["status"] == "running":
                    logger.info("pending_status_cache: already running, skipping")
                    return
                _state["status"] = "running"
                _state["error"] = None

            logger.info("pending_status_cache: refresh started")
            from app.fmg_helpers import make_client

            with make_client() as client:
                raw_adoms = client.get_adoms()
                adom_names = [
                    a.get("name", "")
                    for a in raw_adoms
                    if isinstance(a, dict)
                    and a.get("name")
                    and not a.get("name", "").lower().startswith("forti")
                ]

                for adom in adom_names:
                    try:
                        raw = client.get_devices_with_sync_status(adom)
                    except Exception as exc:
                        logger.warning(
                            "pending_status_cache: get_devices(%s) failed: %s",
                            adom,
                            exc,
                        )
                        continue

                    seen: set[str] = set()
                    base_devices = []
                    for d in raw:
                        if not isinstance(d, dict):
                            continue
                        name = d.get("name", "")
                        if not name or name in seen:
                            continue
                        seen.add(name)
                        os_ver = d.get("os_ver", 0)
                        mr = d.get("mr")
                        patch = d.get("patch")
                        major = (
                            int(os_ver) // 100
                            if str(os_ver).isdigit() and int(os_ver) >= 100
                            else os_ver
                        )
                        if mr is not None and patch is not None:
                            version = f"v{major}.{mr}.{patch}"
                        elif mr is not None:
                            version = f"v{major}.{mr}"
                        else:
                            version = "n/a"
                        embedded_vdoms = d.get("vdom") or []
                        vdom_list = (
                            [
                                v.get("name", "root")
                                for v in embedded_vdoms
                                if isinstance(v, dict) and v.get("name")
                            ]
                            if embedded_vdoms
                            else ["root"]
                        )
                        base_devices.append(
                            {
                                "name": name,
                                "ip": d.get("ip", d.get("mgmt_ip", "")),
                                "platform": d.get(
                                    "platform_str", d.get("platform", "")
                                ),
                                "version": version,
                                "conf_status": d.get("conf_status", "unknown"),
                                "db_status": d.get("db_status", "unknown"),
                                "serial": d.get("sn", d.get("serial", "")),
                                "_vdom_list": vdom_list,
                            }
                        )

                    def _fetch_pkg(entry: dict, _adom: str = adom) -> tuple[str, str]:
                        try:
                            return entry["name"], client.get_device_pkg_status(
                                _adom, entry["name"], entry["_vdom_list"]
                            )
                        except Exception:
                            return entry["name"], ""

                    pkg_map: dict[str, str] = {}
                    with ThreadPoolExecutor(max_workers=10) as pool:
                        futures = {
                            pool.submit(_fetch_pkg, e): e["name"] for e in base_devices
                        }
                        for fut in as_completed(futures):
                            dname, status = fut.result()
                            pkg_map[dname] = status

                    devices = [
                        {k: v for k, v in d.items() if k != "_vdom_list"}
                        | {"pkg_status": pkg_map.get(d["name"], "")}
                        for d in base_devices
                    ]

                    ts = datetime.datetime.now(datetime.UTC).isoformat(
                        timespec="seconds"
                    )
                    with _lock:
                        _cache[adom] = {"devices": devices, "last_updated": ts}
                    logger.info(
                        "pending_status_cache: cached %d devices for ADOM %s",
                        len(devices),
                        adom,
                    )

            ts_done = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
            with _lock:
                _state["status"] = "ok"
                _state["last_updated"] = ts_done
                _state["error"] = None
            logger.info("pending_status_cache: refresh complete")

    except Exception as exc:
        logger.exception("pending_status_cache: refresh failed")
        with _lock:
            _state["status"] = "error"
            _state["error"] = str(exc)


def refresh_now(app: Flask) -> None:
    """Kick off a non-blocking refresh in a daemon thread."""
    t = threading.Thread(
        target=_run_refresh,
        args=[app],
        name="pending_status_cache_refresh",
        daemon=True,
    )
    t.start()


# ── Scheduler init ────────────────────────────────────────────────────────────


def init_scheduler(app: Flask) -> None:
    """Register a recurring APScheduler job and run the first fetch immediately."""
    from apscheduler.schedulers.background import BackgroundScheduler

    refresh_now(app)

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=_run_refresh,
        args=[app],
        trigger="interval",
        minutes=_REFRESH_MINUTES,
        id="pending_status_cache_refresh",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
