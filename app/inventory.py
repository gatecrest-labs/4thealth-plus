"""Facade over the inventory cache (F2): the one place consumers get ADOMs/devices.

With ``INVENTORY_CACHE`` off every function is a straight call on the FMG client
(legacy behaviour, no store access). With it on, data is served from the store
the collector fills, and an ADOM that is missing, older than
``INVENTORY_MAX_AGE_SECS`` or unreadable fails open to a live FMG call (counted).
Results are always fresh copies, so a consumer may mutate them freely.
"""

from __future__ import annotations

import logging
import threading

from app import inventory_store
from app.config import Config
from app.fmg_client import normalize_sync_status, pkg_status_for

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_counters = {"hits": 0, "fallbacks": 0, "store_errors": 0}


def _bump(name: str) -> None:
    with _lock:
        _counters[name] += 1


def counters() -> dict:
    with _lock:
        return dict(_counters)


def reset_counters() -> None:
    with _lock:
        for k in _counters:
            _counters[k] = 0


def _enabled() -> bool:
    return bool(Config.INVENTORY_CACHE)


def _is_system_adom(adom: str) -> bool:
    """``forti*`` ADOMs are FortiManager system ADOMs the collector never inventories."""
    return adom.lower().startswith("forti")


def _cached_devices(adom: str) -> list[dict] | None:
    """Fresh cached devices for *adom*, or None (never collected / stale / store error)."""
    try:
        meta = inventory_store.read_meta(adom)
        if meta is None or meta["age_seconds"] is None:
            return None
        if meta["age_seconds"] > inventory_store.max_age_seconds():
            return None
        return inventory_store.read_devices(adom)
    except inventory_store.InventoryStoreError as exc:
        _bump("store_errors")
        logger.warning("inventory: store unreadable, going live: %s", exc)
        return None


def _pkg_fresh(adom: str) -> bool:
    """Package status collected, and recently: it is refreshed by its own call, which
    can keep failing (e.g. no /pm permission) while the device list stays current."""
    age = inventory_store.pkg_status_age_seconds(adom)
    return age is not None and age <= inventory_store.max_age_seconds()


def adoms(client) -> list[dict]:
    if not _enabled():
        return client.get_adoms()
    try:
        lst = inventory_store.read_adom_list()
        age = inventory_store.adom_list_age_seconds()
        if (
            lst is not None
            and age is not None
            and age <= inventory_store.max_age_seconds()
        ):
            _bump("hits")
            return lst
    except inventory_store.InventoryStoreError as exc:
        _bump("store_errors")
        logger.warning("inventory: store unreadable, going live: %s", exc)
    _bump("fallbacks")
    return client.get_adoms()


def devices(client, adom: str) -> list[dict]:
    if not _enabled():
        return client.get_devices(adom)
    if _is_system_adom(adom):
        return []
    cached = _cached_devices(adom)
    if cached is not None:
        _bump("hits")
        return cached
    _bump("fallbacks")
    return client.get_devices(adom)


def devices_with_sync_status(client, adom: str) -> list[dict]:
    if not _enabled():
        return client.get_devices_with_sync_status(adom)
    if _is_system_adom(adom):
        return []
    cached = _cached_devices(adom)
    if cached is not None:
        _bump("hits")
        return normalize_sync_status(cached)
    _bump("fallbacks")
    return client.get_devices_with_sync_status(adom)


def pkg_status(client, adom: str, device: str, vdom_names: list) -> str:
    """``"modified"`` / ``"nomod"`` / ``""`` like ``FMGClient.get_device_pkg_status``."""
    if not _enabled():
        return client.get_device_pkg_status(adom, device, vdom_names)
    if _is_system_adom(adom):
        return ""
    try:
        meta = inventory_store.read_meta(adom)
        fresh = (
            meta is not None
            and meta["age_seconds"] is not None
            and meta["age_seconds"] <= inventory_store.max_age_seconds()
            and _pkg_fresh(adom)
        )
        if fresh:
            _bump("hits")
            return pkg_status_for(
                inventory_store.read_pkg_status(adom), device, vdom_names
            )
    except inventory_store.InventoryStoreError as exc:
        _bump("store_errors")
        logger.warning("inventory: store unreadable, going live: %s", exc)
    _bump("fallbacks")
    return client.get_device_pkg_status(adom, device, vdom_names)


def pkg_status_lookup(client, adom: str):
    """A ``lookup(device, vdom_names) -> str`` for one ADOM, loading the rows once.

    For sweeps that need every device's package status: the store is read a
    single time and indexed by device (O(rows) instead of O(devices x rows)).
    Falls back to per-device live calls when the cache is off, stale or has no
    package rows yet.
    """
    live = lambda device, vdoms: client.get_device_pkg_status(adom, device, vdoms)
    if not _enabled():
        return live
    if _is_system_adom(adom):
        return lambda device, vdoms: ""
    try:
        meta = inventory_store.read_meta(adom)
        fresh = (
            meta is not None
            and meta["age_seconds"] is not None
            and meta["age_seconds"] <= inventory_store.max_age_seconds()
            and _pkg_fresh(adom)
        )
        if fresh:
            by_dev: dict[str, list] = {}
            for row in inventory_store.read_pkg_status(adom):
                by_dev.setdefault(row.get("dev", ""), []).append(row)

            def cached(device, vdoms):
                _bump("hits")
                return pkg_status_for(by_dev.get(device, []), device, vdoms)

            return cached
    except inventory_store.InventoryStoreError as exc:
        _bump("store_errors")
        logger.warning("inventory: store unreadable, going live: %s", exc)

    def fallback(device, vdoms):
        _bump("fallbacks")
        return live(device, vdoms)

    return fallback


def freshness() -> list[dict]:
    """Per-ADOM cache state for the UI; empty when the layer is off or unreadable."""
    if not _enabled():
        return []
    try:
        limit = inventory_store.max_age_seconds()
        rows = inventory_store.read_meta() or []
        pkg_ages = inventory_store.pkg_status_ages()
    except inventory_store.InventoryStoreError:
        return []
    return [
        {
            "adom": m["adom"],
            "collected_at": m["collected_at"],
            "age_seconds": m["age_seconds"],
            "status": m["status"],
            "device_count": m["device_count"],
            "stale": m["age_seconds"] is None
            or m["age_seconds"] > limit
            or pkg_ages.get(m["adom"], 0.0) > limit,
        }
        for m in rows
    ]
