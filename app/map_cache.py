"""Device location cache — collects lat/lon for all devices at startup and daily.

Each cached record contains: name, adom, latitude, longitude, platform,
version, status, desc.  Devices with 0.0/0.0 or missing coords are excluded.

State
-----
_store["devices"]      list[dict]  — cached records with valid coordinates
_store["last_updated"] str | None  — ISO-8601 UTC timestamp of last successful run
_store["status"]       str         — "pending" | "running" | "ok" | "error"
_store["error"]        str | None  — last error message
_store["adom_progress"] dict       — {adom: "ok"|"running"|"pending"}
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
    "adom_progress": {},
}

_lock = threading.Lock()
_running = threading.Event()


def get_cached() -> dict:
    """Return a copy of the cache store.

    Read-through: if THIS process has never completed its own run
    (RUN_SCHEDULERS != "inline", i.e. a web worker in the split
    deployment — or a process that just restarted), fall back to the
    latest snapshot the collector process persisted to SQLite. Once
    this process's own run completes, its own in-memory value wins.
    """
    with _lock:
        local = dict(_store)

    if local.get("status") == "pending":
        from app import collector_store

        snapshot = collector_store.read_snapshot("map_cache")
        if snapshot:
            local.update(snapshot)

    return local


def _run_job(app):
    if _running.is_set():
        logger.info("map_cache: already running, skipping overlap")
        return

    _running.set()
    with _lock:
        _store["status"] = "running"
        _store["error"] = None
        _store["adom_progress"] = {}

    logger.info("map_cache: starting refresh")
    t0 = _time.monotonic()

    try:
        from app.fmg_helpers import make_client

        result = []
        # Keyed by device name alone — the same physical device can appear in
        # multiple ADOMs and also as one row per VDOM within each ADOM.
        seen: dict = {}
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

            with _lock:
                _store["adom_progress"] = {n: "pending" for n in adom_names}

            for adom in adom_names:
                with _lock:
                    _store["adom_progress"][adom] = "running"
                try:
                    raw = client.get_devices(adom)
                    for d in raw:
                        if not isinstance(d, dict):
                            continue
                        name = d.get("name", "")
                        if not name:
                            continue

                        vdom_raw = d.get("vdom")
                        # vdom field can be: a string name, a list of dicts
                        # [{"name": "root"}, ...], a list of strings, or a
                        # single dict — handle all forms.
                        if isinstance(vdom_raw, str) and vdom_raw.strip():
                            vdom_names_here = [vdom_raw.strip()]
                        elif isinstance(vdom_raw, list):
                            vdom_names_here = [
                                (v.get("name") or v if isinstance(v, dict) else v)
                                for v in vdom_raw
                                if v
                            ]
                            vdom_names_here = [
                                str(v).strip() for v in vdom_names_here if v
                            ]
                        else:
                            vdom_names_here = []

                        # If we've already placed this device, merge any new VDOMs
                        if name in seen:
                            for vn in vdom_names_here:
                                if vn and vn not in seen[name]["vdoms"]:
                                    seen[name]["vdoms"].append(vn)
                            continue

                        lat_str = d.get("latitude", "")
                        lon_str = d.get("longitude", "")
                        try:
                            lat = float(lat_str)
                            lon = float(lon_str)
                        except (TypeError, ValueError):
                            continue
                        # Skip devices at 0,0 — those have no location configured
                        if lat == 0.0 and lon == 0.0:
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
                        status = "green" if conn_status == 1 else "offline"

                        record = {
                            "name": name,
                            "adom": adom,
                            "lat": lat,
                            "lon": lon,
                            "platform": d.get("platform_str", d.get("platform", "n/a")),
                            "version": version,
                            "status": status,
                            "desc": (d.get("desc") or "").strip(),
                            "vdoms": vdom_names_here,
                        }
                        seen[name] = record
                        result.append(record)
                    with _lock:
                        _store["adom_progress"][adom] = "ok"
                except Exception as exc:
                    logger.warning("map_cache: get_devices(%s) failed: %s", adom, exc)
                    with _lock:
                        _store["adom_progress"][adom] = "error"

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "map_cache: done in %ss — %d devices with coords across %d ADOMs",
            elapsed,
            len(result),
            len(adom_names),
        )

        with _lock:
            _store["devices"] = result
            _store["last_updated"] = datetime.now(UTC).isoformat()
            _store["status"] = "ok"
            _store["error"] = None
            snapshot = dict(_store)

        try:
            from app import collector_store

            collector_store.write_snapshot(
                "map_cache", snapshot, collected_at=snapshot.get("last_updated")
            )
        except Exception as exc:
            logger.warning(
                "map_cache: SQLite snapshot write failed (in-memory cache "
                "update still succeeded): %s",
                exc,
            )

    except Exception as exc:
        logger.exception("map_cache: unhandled error")
        with _lock:
            _store["status"] = "error"
            _store["error"] = str(exc)
    finally:
        _running.clear()


def refresh_now(app):
    """Trigger an immediate background refresh (non-blocking)."""
    t = threading.Thread(
        target=_run_job, args=[app], name="map_cache_refresh", daemon=True
    )
    t.start()


def init_scheduler(app):
    """Start the daily refresh scheduler and fire an initial warm-up at startup."""
    from apscheduler.schedulers.background import BackgroundScheduler

    interval_hours = int(os.environ.get("MAP_CACHE_INTERVAL_HOURS", "24"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_job,
        args=[app],
        trigger="interval",
        hours=interval_hours,
        id="map_cache_refresh",
        name="Map cache refresh",
    )
    scheduler.start()
    logger.info("map_cache: scheduler started — every %d hours", interval_hours)

    # One retry after 15 s handles transient FMG connectivity at container startup.
    def _startup(app=app):
        _run_job(app)
        with _lock:
            if _store["status"] != "ok":
                logger.info("map_cache: startup run failed, retrying in 15s")
                _time.sleep(15)
                _run_job(app)

    t = threading.Thread(target=_startup, name="map_cache_startup", daemon=True)
    t.start()

    return scheduler
