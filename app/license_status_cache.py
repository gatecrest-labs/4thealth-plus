"""Fleet-wide FortiGate license status: daily sweep.

Unlike the cheap per-ADOM bulk device sweep (app.executive_summary_cache,
app.device_backup_cache), license status has no bulk/fleet-wide FMG
endpoint -- FortiOS only exposes it via /api/v2/monitor/license/status,
fetched one FMG proxy call per device (FMGClient.get_device_license_status()).
This is the same cost class as app.device_backup_cache's sweep, hence its
own daily cadence (DEVICE_LICENSE_REFRESH_HOUR/_MINUTE, default 03:00 local
-- staggered after device_backup's 02:00 and summary_job's 01:00) rather
than riding the 15-minute device sweep.

For each non-forti* ADOM, devices are fetched via client.get_devices(adom)
(device roster), then a ThreadPoolExecutor(max_workers=4) -- same
concurrency pattern as app.routes.audit_review_routes.bulk_device_review_adom()
-- calls get_device_license_status() per device and classifies the result
via app.license_status.parse_license_payload().

Persisted to license_status.json (gitignored, project root) via
atomic_write_json after every successful sweep -- same single-latest-record,
"a failed sweep leaves the prior result in place" convention as
app.device_backup_cache. Because this is a plain JSON file on shared disk
rather than an in-memory store, it needs no SQLite collector/web split
treatment.

Two consumers share this one sweep: app.routes.external_api_routes reads
the aggregate counts + "details" (expired/unknown only) for the executive
summary; the Device Versions tab's License Status section (routes in
app.routes.api_routes) reads "all_devices" (every device, every status,
with a "firmware" string) for its donut charts and per-device export. A
second, more-frequent sweep was deliberately NOT added for the interactive
tab -- it would double the FMG load of the one expensive (no-bulk-endpoint)
license call this module exists to amortize. The manual "Refresh" button on
the Versions page calls the same refresh_now() as everything else here.
"""

from __future__ import annotations

import json
import logging
import threading
import time as _time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.atomic_io import atomic_write_json
from app.license_status import parse_license_payload

logger = logging.getLogger(__name__)

_STORE_PATH = Path(__file__).parent.parent / "license_status.json"

_lock = threading.Lock()
_running = threading.Event()


# ── Pure aggregation (no I/O — unit-tested directly) ────────────────────────


def _build_firmware_version(device: dict) -> str:
    """Render a device roster dict's os_ver/mr/patch fields as "vX.Y.Z".

    Same shape as the inline logic in app.versions_cache._run_job — pulled
    out here so app.license_status_cache can attach a firmware string to
    every device record without duplicating that parsing untested.
    """
    os_ver = device.get("os_ver", 0)
    mr = device.get("mr")
    patch = device.get("patch")
    major = (
        int(os_ver) // 100 if str(os_ver).isdigit() and int(os_ver) >= 100 else os_ver
    )
    if mr is not None and patch is not None and int(patch) >= 0:
        return f"v{major}.{mr}.{patch}"
    if mr is not None:
        return f"v{major}.{mr}"
    return "n/a"


def _classify_devices(devices_by_adom_with_license: dict[str, list[dict]]) -> dict:
    """Bucket every device across all ADOMs into licensed/expired/unknown.

    devices_by_adom_with_license: {adom: [{"name": str, "license": {"status",
    "expires"}, "firmware": str}, ...]} — each device dict must already
    carry its parsed "license" sub-dict (see _run_sweep(), which attaches
    it before calling this function). "firmware" is optional — missing or
    absent devices are recorded as "n/a" in all_devices.

    Returns "details" (unchanged: only expired/unknown devices, no
    firmware — kept exactly as before for the executive-summary consumer)
    plus "all_devices" (every device regardless of status, WITH firmware —
    used by the Device Versions tab's License Status section).
    """
    licensed = 0
    expired = 0
    unknown = 0
    details: list[dict] = []
    all_devices: list[dict] = []

    for adom, devices in devices_by_adom_with_license.items():
        for device in devices:
            if not isinstance(device, dict):
                continue
            name = device.get("name", "")
            if not name:
                continue
            license_info = device.get("license") or {}
            status = license_info.get("status", "unknown")
            expires = license_info.get("expires")
            if status == "licensed":
                licensed += 1
            elif status == "expired":
                expired += 1
                details.append(
                    {
                        "device": name,
                        "adom": adom,
                        "status": "expired",
                        "expires": expires,
                    }
                )
            else:
                unknown += 1
                details.append(
                    {
                        "device": name,
                        "adom": adom,
                        "status": "unknown",
                        "expires": expires,
                    }
                )

            all_devices.append(
                {
                    "device": name,
                    "adom": adom,
                    "status": status,
                    "expires": expires,
                    "firmware": device.get("firmware", "n/a"),
                }
            )

    return {
        "devices_licensed": licensed,
        "devices_expired": expired,
        "devices_unknown": unknown,
        "details": details,
        "all_devices": all_devices,
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
    """The last successfully persisted {devices_licensed, devices_expired,
    devices_unknown, details, collected_at}, or None if no sweep has ever
    succeeded."""
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
    """Fetch device rosters + per-device license status once per non-forti*
    ADOM, classify, and persist. Returns True on success, False on error or
    overlap — on either failure mode the previously persisted result is
    left in place."""
    if _running.is_set():
        logger.info("license_status_cache: already running, skipping overlap")
        return False

    _running.set()
    t0 = _time.monotonic()
    try:
        import concurrent.futures

        from app.fmg_helpers import make_client

        devices_by_adom_with_license: dict[str, list[dict]] = {}

        with make_client() as client:
            adom_names = _list_target_adoms(client)
            for adom in adom_names:
                try:
                    devices = client.get_devices(adom) or []
                except Exception as exc:
                    logger.warning(
                        "license_status_cache: get_devices(%s) failed: %s", adom, exc
                    )
                    devices = []

                valid_devices = [
                    d for d in devices if isinstance(d, dict) and d.get("name")
                ]

                def _fetch_one(dev: dict, adom=adom) -> dict:
                    name = dev["name"]
                    try:
                        raw = client.get_device_license_status(adom, name)
                    except Exception as exc:
                        logger.warning(
                            "license_status_cache: get_device_license_status(%s, %s) failed: %s",
                            adom,
                            name,
                            exc,
                        )
                        raw = {}
                    if not raw:
                        logger.warning(
                            "license_status_cache: get_device_license_status(%s, %s) "
                            "returned no data — device will be classified 'unknown', "
                            "which may indicate a fetch failure rather than a genuine "
                            "unlicensed device",
                            adom,
                            name,
                        )
                    return {
                        "name": name,
                        "license": parse_license_payload(raw),
                        "firmware": _build_firmware_version(dev),
                    }

                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    devices_by_adom_with_license[adom] = list(
                        pool.map(_fetch_one, valid_devices)
                    )

        counts = _classify_devices(devices_by_adom_with_license)
        record = {**counts, "collected_at": datetime.now(UTC).isoformat()}

        with _lock:
            _save(record)

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "license_status_cache: sweep done in %ss — licensed=%d expired=%d unknown=%d",
            elapsed,
            counts["devices_licensed"],
            counts["devices_expired"],
            counts["devices_unknown"],
        )
        return True
    except Exception:
        logger.exception(
            "license_status_cache: sweep failed — keeping last persisted result"
        )
        return False
    finally:
        _running.clear()


_STARTUP_SWEEP_MIN_AGE = timedelta(hours=12)


def _should_skip_startup_sweep(latest: dict | None, now: datetime) -> bool:
    """True if the immediate startup sweep should be skipped because a
    sweep already succeeded recently (within _STARTUP_SWEEP_MIN_AGE).

    Guards against every gthread worker process re-running a full,
    per-device fleet sweep on every app restart/deploy. Returns False
    (i.e. run the startup sweep) whenever `latest` is None, missing
    "collected_at", or "collected_at" fails to parse — the safe default
    is to sweep, not to silently skip forever on bad data.
    """
    if not isinstance(latest, dict):
        return False
    collected_at = latest.get("collected_at")
    if not collected_at:
        return False
    try:
        collected_dt = datetime.fromisoformat(collected_at)
    except (TypeError, ValueError):
        return False
    if collected_dt.tzinfo is None:
        collected_dt = collected_dt.replace(tzinfo=UTC)
    return (now - collected_dt) < _STARTUP_SWEEP_MIN_AGE


def is_running() -> bool:
    """True while a sweep is in progress — used by the Device Versions
    tab's License Status section to show a "refreshing…" state."""
    return _running.is_set()


def refresh_now(app) -> None:
    """Trigger an immediate background sweep (non-blocking)."""
    threading.Thread(
        target=_run_sweep,
        args=[app],
        name="license_status_cache_refresh",
        daemon=True,
    ).start()


def init_scheduler(app):
    """Register the daily sweep with APScheduler and fire it once immediately."""
    import os

    from apscheduler.schedulers.background import BackgroundScheduler

    refresh_hour = int(os.environ.get("DEVICE_LICENSE_REFRESH_HOUR", "3"))
    refresh_minute = int(os.environ.get("DEVICE_LICENSE_REFRESH_MINUTE", "0"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_sweep,
        args=[app],
        trigger="cron",
        hour=refresh_hour,
        minute=refresh_minute,
        id="license_status_refresh",
        name="Daily license status sweep",
    )
    scheduler.start()
    logger.info(
        "license_status_cache: scheduler started — daily at %02d:%02d local time",
        refresh_hour,
        refresh_minute,
    )

    if _should_skip_startup_sweep(get_latest(), datetime.now(UTC)):
        logger.info(
            "license_status_cache: skipping startup sweep — last sweep is still fresh"
        )
    else:
        threading.Thread(
            target=_run_sweep,
            args=[app],
            name="license_status_cache_startup",
            daemon=True,
        ).start()

    return scheduler
