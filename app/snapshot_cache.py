"""Collector-owned device snapshot capture (F4).

Every ``AUDIT_SNAPSHOT_BATCH_MINUTES`` a small batch of devices is captured so
that the whole fleet is re-captured once per ``AUDIT_SNAPSHOT_WINDOW_DAYS``.
Devices are chosen in this order: never captured (ramped so a cold start
finishes within a day), devices whose FortiManager config revision is newer than
their snapshot, then the oldest snapshot. A device FortiManager cannot reach is
backed off (15 min doubling to 24 h) instead of being retried every batch.

The device getters swallow errors and return ``{}``/``[]``; a capture therefore
uses ``fetch_device_data_checked`` and only stores keys FortiManager really
answered, so "we could not ask" never replaces a real snapshot or reads as an
empty configuration.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from app import boot_warmup, device_data, inventory, snapshot_store
from app.config import Config

logger = logging.getLogger(__name__)

_running = threading.Lock()
_revision_flags: set[tuple[str, str]] = set()
_flags_lock = threading.Lock()


def _make_client():
    from app.fmg_helpers import make_client

    return make_client()


def _make_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler

    return BackgroundScheduler()


def batch_size(fleet_size: int, never_captured: int = 0) -> int:
    """Devices to capture per batch: enough to cover the fleet once per window,
    and enough to capture every never-captured device within a day."""
    per_day = max(1, (24 * 60) // max(1, int(Config.AUDIT_SNAPSHOT_BATCH_MINUTES)))
    batches_per_window = max(1, int(Config.AUDIT_SNAPSHOT_WINDOW_DAYS) * per_day)
    return max(
        1,
        math.ceil(fleet_size / batches_per_window),
        math.ceil(never_captured / per_day),
    )


def _fleet_checked(client) -> tuple[dict[str, list[str]], set[str]]:
    """``(fleet, failed_adoms)``: a denied/failing ADOM must not stop the others."""
    names: dict[str, list[str]] = {}
    failed: set[str] = set()
    for adom in inventory.adoms(client) or []:
        name = adom.get("name", "") if isinstance(adom, dict) else ""
        if not name or name.lower().startswith("forti"):
            continue
        try:
            devices = inventory.devices(client, name) or []
        except Exception as exc:
            logger.warning("snapshot_cache: device list for %s failed: %s", name, exc)
            failed.add(name)
            continue
        names[name] = sorted(
            {d["name"] for d in devices if isinstance(d, dict) and d.get("name")}
        )
    return names, failed


def _fleet(client) -> dict[str, list[str]]:
    return _fleet_checked(client)[0]


def capture_device(client, adom: str, device: str) -> dict:
    """Capture every proxy-backed key of one device and store what was answered."""
    checked = device_data.fetch_device_data_checked(
        client, adom, device, set(device_data.DATA_KEYS)
    )
    ok = {k: v for k, (v, err) in checked.items() if err is None}
    failed = {k: err for k, (_v, err) in checked.items() if err is not None}
    if ok:
        snapshot_store.put_keys(adom, device, ok)
    if failed:
        snapshot_store.mark_failed(
            adom, device, sorted(failed), "; ".join(dict.fromkeys(failed.values()))
        )
    else:
        snapshot_store.mark_ok(adom, device)
    if not failed:  # a failed capture keeps its priority for the next batch
        with _flags_lock:
            _revision_flags.discard((adom, device))
    return {"ok_keys": sorted(ok), "failed_keys": sorted(failed)}


def _refresh_batch(client, now: datetime) -> dict:
    started = time.monotonic()
    fleet, failed_adoms = _fleet_checked(client)
    total = sum(len(v) for v in fleet.values())
    for adom, names in fleet.items():
        snapshot_store.delete_missing_devices(adom, set(names))
    # an ADOM whose listing failed is unknown, not gone: keep its snapshots
    snapshot_store.delete_missing_adoms(set(fleet) | failed_adoms)

    now_iso = now.isoformat()
    candidates: list[tuple] = []
    skipped_backoff = never = 0
    with _flags_lock:
        flags = set(_revision_flags)
    for adom, names in fleet.items():
        meta = {r["device"]: r for r in snapshot_store.device_meta_rows(adom)}
        for name in names:
            m = meta.get(name)
            if m and m["next_attempt_at"] and m["next_attempt_at"] > now_iso:
                skipped_backoff += 1
                continue
            is_new = m is None or m["keys"] == 0
            never += is_new
            group = 0 if is_new else (1 if (adom, name) in flags else 2)
            oldest = "" if is_new else (m["oldest_key_at"] or "")
            candidates.append((group, oldest, adom, name))
    candidates.sort()
    selected = candidates[: batch_size(total, never)]

    def _one(item):
        _g, _o, adom, name = item
        try:
            return capture_device(client, adom, name)
        except Exception as exc:  # a store error must not stop the batch
            logger.warning("snapshot_cache: %s/%s failed: %s", adom, name, exc)
            return {"ok_keys": [], "failed_keys": ["*"]}

    workers = max(1, int(Config.AUDIT_SNAPSHOT_WORKERS or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(_one, selected))
    failed = sum(1 for o in outcomes if o["failed_keys"])
    return {
        "fleet": total,
        "selected": len(selected),
        "captured": len(outcomes) - failed,
        "failed": failed,
        "skipped_backoff": skipped_backoff,
        "seconds": round(time.monotonic() - started, 2),
    }


def refresh_batch(client=None, now: datetime | None = None) -> dict:
    """Capture one batch of devices. Single-flight: a concurrent call is skipped."""
    if not _running.acquire(blocking=False):
        return {"skipped": True}
    try:
        when = now or datetime.now(UTC)
        if client is not None:
            result = _refresh_batch(client, when)
        else:
            with _make_client() as live:
                result = _refresh_batch(live, when)
        logger.info("snapshot_cache: batch %s", result)
        return result
    finally:
        _running.release()


def _refresh_revisions(client) -> dict:
    flagged = 0
    for adom, names in _fleet(client).items():
        try:
            revisions = client.get_adom_revisions(adom) or []
        except Exception as exc:
            logger.warning("snapshot_cache: revisions for %s failed: %s", adom, exc)
            continue
        latest: dict[str, float] = {}
        for rev in revisions:
            if not isinstance(rev, dict):
                continue
            label = str(rev.get("name", ""))
            for name in names:
                if label.startswith(f"{name}-"):
                    latest[name] = max(
                        latest.get(name, 0.0), float(rev.get("created_time") or 0)
                    )
        meta = {r["device"]: r for r in snapshot_store.device_meta_rows(adom)}
        for name, created in latest.items():
            last_ok = (meta.get(name) or {}).get("last_ok_at")
            if last_ok and created > datetime.fromisoformat(last_ok).timestamp():
                with _flags_lock:
                    _revision_flags.add((adom, name))
                flagged += 1
    return {"flagged": flagged}


def refresh_revisions(client=None) -> dict:
    """Flag devices whose FortiManager config revision is newer than their snapshot
    (one revision-list call per ADOM) so the next batches capture them first."""
    if client is not None:
        return _refresh_revisions(client)
    with _make_client() as live:
        return _refresh_revisions(live)


def _guarded(fn, label: str) -> None:
    try:
        fn()
    except Exception:
        logger.exception("snapshot_cache: %s failed", label)


def _run_batch(app=None) -> None:
    _guarded(refresh_batch, "batch")


def _run_revisions(app=None) -> None:
    _guarded(refresh_revisions, "revision check")


def _first_run(app) -> None:
    _run_revisions(app)
    _run_batch(app)


def init_scheduler(app) -> bool:
    """Register the capture jobs (collector only, ``AUDIT_SNAPSHOTS`` on)."""
    if not Config.AUDIT_SNAPSHOTS:
        return False
    scheduler = _make_scheduler()
    scheduler.add_job(
        func=_run_batch,
        args=[app],
        trigger="interval",
        minutes=max(1, int(Config.AUDIT_SNAPSHOT_BATCH_MINUTES)),
        id="snapshot_batch",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        func=_run_revisions,
        args=[app],
        trigger="interval",
        minutes=max(1, int(Config.AUDIT_SNAPSHOT_REVISION_CHECK_MINUTES)),
        id="snapshot_revisions",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    boot_warmup.defer("snapshot_cache", lambda: _first_run(app), 3)
    return True
