"""FortiManager client look-alike for the PSIRT engine that serves device reads
from configuration snapshots (F4).

The vendored ``app/psirt`` package only ever calls a handful of methods on its
``fmg_client``; this adapter implements exactly those. ADOM and device lists come
from the inventory facade, the two per-device reads (interfaces, admins) from
``audit_data`` (snapshot when fresh, live otherwise), and the system status is
delegated. Anything else raises ``AttributeError`` so a new engine call can never
silently get a stub. ``provenance(device)`` says how old the data behind a
device's workaround verdict is.
"""

from __future__ import annotations

import threading

from app import audit_data, inventory


class SnapshotFMGAdapter:
    def __init__(self, client, live: bool = False):
        self._client = client
        self._live = live
        self._lock = threading.Lock()
        self._prov: dict[str, dict] = {}

    # -- lists (inventory facade) ------------------------------------------------
    def get_adoms(self):
        return inventory.adoms(self._client)

    def get_devices(self, adom: str):
        return inventory.devices(self._client, adom)

    def get_system_status(self):
        return self._client.get_system_status()

    # -- per-device reads --------------------------------------------------------
    def _read(self, adom: str, device: str, key: str):
        dd = audit_data.device_data(self._client, adom, device, {key}, live=self._live)
        with self._lock:
            old = self._prov.get(device)
            new = {"collected_at": dd.collected_at, "source": dd.source}
            if old is not None and old["collected_at"] and new["collected_at"]:
                # several reads for one device: report the oldest, and "mixed"
                # when their origins differ
                new = {
                    "collected_at": min(old["collected_at"], new["collected_at"]),
                    "source": old["source"]
                    if old["source"] == new["source"]
                    else "mixed",
                }
            self._prov[device] = new
        return dd.data.get(key)

    def get_device_interfaces_all_vdoms(self, adom: str, device: str):
        return self._read(adom, device, "interfaces")

    def get_device_admins(self, adom: str, device: str):
        return self._read(adom, device, "admins")

    def provenance(self, device: str) -> dict | None:
        with self._lock:
            row = self._prov.get(device)
            return dict(row) if row else None

    def __getattr__(self, name: str):
        raise AttributeError(
            f"SnapshotFMGAdapter does not implement {name!r}; add it deliberately"
        )
