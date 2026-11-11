"""Facade over device configuration snapshots (F4): where Device Review and PSIRT
get per-device data.

With ``AUDIT_SNAPSHOTS`` off, or ``live=True``, every key is fetched from the
device through FortiManager exactly as before. With it on, each key is served
from the collector's snapshot when one exists and is younger than
``snapshot_store.max_age_seconds()``; any other key is fetched live for that read
(counted). Every result says where each key came from and when it was collected,
and ``collected_at`` is the OLDEST of them, so a verdict is never shown without
the age of the data behind it. ``live=True`` never writes to the store.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app import device_data as device_data_mod
from app import snapshot_store
from app.config import Config

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_counters = {"hits": 0, "fallbacks": 0, "store_errors": 0, "live_requests": 0}


def _bump(name: str, n: int = 1) -> None:
    with _lock:
        _counters[name] += n


def counters() -> dict:
    with _lock:
        return dict(_counters)


def reset_counters() -> None:
    with _lock:
        for key in _counters:
            _counters[key] = 0


@dataclass
class DeviceData:
    """Device data blobs plus where each came from.

    ``source`` is ``snapshot``, ``live`` or ``mixed`` (``inventory`` when only the
    device record was needed); ``collected_at`` is the oldest key's capture time.
    """

    data: dict
    collected_at: str | None
    source: str
    per_key: dict[str, dict] = field(default_factory=dict)


def _summarise(per_key: dict[str, dict]) -> tuple[str | None, str]:
    if not per_key:
        return None, "inventory"
    sources = {v["source"] for v in per_key.values()}
    source = sources.pop() if len(sources) == 1 else "mixed"
    return min(v["collected_at"] for v in per_key.values()), source


def device_data(
    client,
    adom: str,
    device: str,
    keys: set[str],
    device_meta: dict | None = None,
    live: bool = False,
    device_meta_as_of: str | None = None,
) -> DeviceData:
    """Device data for the requested keys, from snapshots where fresh, else live."""
    proxy_keys = {k for k in keys if k in device_data_mod.DATA_KEYS}
    data: dict = {}
    per_key: dict[str, dict] = {}
    snapshots: dict[str, dict] = {}
    if live:
        _bump("live_requests")
    elif Config.AUDIT_SNAPSHOTS and proxy_keys:
        try:
            snapshots = snapshot_store.get_keys(adom, device, proxy_keys)
        except snapshot_store.SnapshotStoreError as exc:
            _bump("store_errors")
            logger.warning("audit_data: snapshot store unreadable, going live: %s", exc)
    limit = snapshot_store.max_age_seconds()
    missing: set[str] = set()
    for key in proxy_keys:
        row = snapshots.get(key)
        if (
            row is not None
            and row["age_seconds"] is not None
            and row["age_seconds"] <= limit
        ):
            data[key] = row["value"]
            per_key[key] = {"source": "snapshot", "collected_at": row["collected_at"]}
            _bump("hits")
        else:
            missing.add(key)
    if missing:
        fetched_at = datetime.now(UTC).isoformat()
        data.update(device_data_mod.fetch_device_data(client, adom, device, missing))
        for key in missing:
            per_key[key] = {"source": "live", "collected_at": fetched_at}
        if Config.AUDIT_SNAPSHOTS and not live:
            _bump("fallbacks", len(missing))
    if "device_meta" in keys:
        data["device_meta"] = device_meta or {}
    collected_at, source = _summarise(per_key)
    if not per_key:
        collected_at = device_meta_as_of
    return DeviceData(
        data=data, collected_at=collected_at, source=source, per_key=per_key
    )
