"""Config-Delta preview gating (F5).

A scheduled Config-Delta run used to stage and preview every device of an ADOM
(four FMG calls each, serialised per ADOM). With the inventory cache on, a device
whose cached conf/db/package status is all clean is skipped; anything pending,
unknown, missing or stale is previewed (fail open). A full sweep (every device)
still runs every ``CONFIG_DELTA_FULL_SWEEP_HOURS`` because ``conf_status`` can lag
the real device state, so gating is a load saver with a bounded blind window.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app import inventory, inventory_store
from app.config import Config

logger = logging.getLogger(__name__)

_PENDING = {"conf": {"outofsync"}, "db": {"modified"}, "pkg": {"modified"}}
_UNKNOWN = (None, "", "unknown")


@dataclass
class GateResult:
    preview: list[dict] = field(default_factory=list)
    gated: list[dict] = field(default_factory=list)
    full_sweep: bool = False
    status_age_s: float | None = None


def gating_enabled() -> bool:
    return bool(Config.INVENTORY_CACHE and Config.CONFIG_DELTA_GATING)


def decide_device(
    conf_status, db_status, pkg_status, status_age_s: float | None, max_age_s: float
) -> tuple[bool, str]:
    """``(preview?, reason)`` for one device; reason is pending/stale/unknown/in_sync."""
    if (
        conf_status in _PENDING["conf"]
        or db_status in _PENDING["db"]
        or pkg_status in _PENDING["pkg"]
    ):
        return True, "pending"
    if status_age_s is None or status_age_s > max_age_s:
        return True, "stale"
    if any(v in _UNKNOWN for v in (conf_status, db_status, pkg_status)):
        return True, "unknown"
    return False, "in_sync"


def mark_full_sweep_done(adom: str) -> None:
    """Record a completed full sweep (call after every device was previewed)."""
    try:
        inventory_store.mark_full_sweep(adom)
    except inventory_store.InventoryStoreError as exc:
        logger.warning(
            "config_delta_gate: could not record full sweep for %s: %s", adom, exc
        )


def _full_sweep_due(adom: str) -> bool:
    age = inventory_store.last_full_sweep_age_seconds(adom)
    return age is None or age >= Config.CONFIG_DELTA_FULL_SWEEP_HOURS * 3600.0


def select_devices(client, adom: str, devices: list[dict]) -> GateResult:
    """Split *devices* (``{"name","ip"}``) into those to preview and those gated out."""
    everything = GateResult(preview=list(devices))
    if not gating_enabled():
        return everything
    try:
        meta = inventory_store.read_meta(adom)
        age = meta["age_seconds"] if meta else None
        if _full_sweep_due(adom):
            return GateResult(preview=list(devices), full_sweep=True, status_age_s=age)
        # Never more lenient than the facade: past its own limit it would go live.
        max_age = min(
            2.0 * float(Config.INVENTORY_REFRESH_SECS),
            inventory_store.max_age_seconds(),
        )
        pkg_age = inventory_store.pkg_status_age_seconds(adom)
        if age is None or age > max_age or pkg_age is None or pkg_age > max_age:
            # Device list or package status stale / never collected: preview
            # everything, and do not let the facade make live FMG calls (one per
            # device for package status) just to make this decision.
            return GateResult(preview=list(devices), status_age_s=age)
        rows = {
            r.get("name"): r
            for r in inventory.devices_with_sync_status(client, adom)
            if isinstance(r, dict)
        }
        lookup = inventory.pkg_status_lookup(client, adom)
    except inventory_store.InventoryStoreError as exc:
        logger.warning("config_delta_gate: store unreadable, previewing all: %s", exc)
        return everything
    result = GateResult(status_age_s=age)
    for dev in devices:
        row = rows.get(dev["name"])
        if row is None:
            result.preview.append(dev)
            continue
        vdoms = [
            v.get("name", "root") for v in row.get("vdom") or [] if isinstance(v, dict)
        ] or ["root"]
        pkg = lookup(dev["name"], vdoms)
        preview, _reason = decide_device(
            row.get("conf_status"), row.get("db_status"), pkg, age, max_age
        )
        if preview:
            result.preview.append(dev)
        else:
            result.gated.append({**dev, "pkg_status": pkg})
    return result
