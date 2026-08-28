"""Background cache for the executive-summary external API endpoint.

Runs TWO independent periodic sweeps, on different cadences, both writing
into the same in-memory _store:

  - Device sweep (default every EXEC_SUMMARY_REFRESH_MINUTES=15 minutes):
    one get_devices() call per non-forti* ADOM, computing
      - firewall_online_count / firewalls_total  (device conn_status)
      - version_compliance_pct                   (device version vs. an
                                                    admin-configured target
                                                    list)
      - pending_config_diff_count                (aggregated from the
                                                    existing
                                                    pending_status_cache)
      - adom_count                                (len of the target ADOM
                                                    list itself)
    Cheap — one lightweight call per ADOM.

  - Hygiene sweep (default every EXEC_SUMMARY_HYGIENE_REFRESH_MINUTES=60
    minutes): downloads every policy in every package in every non-forti*
    ADOM to compute hygiene_score (findings-density across a restricted,
    cheap check set). This is the expensive half — a full fleet-wide
    policy-body download — so it runs on its own, much slower cadence,
    independent of the device sweep's tighter interval. In between
    hygiene-sweep runs, hygiene_score simply keeps its last computed value.

Each sweep only ever writes its own subset of _store's keys (plus the
shared status/error/last_updated, reflecting whichever sweep most recently
completed) — a sweep never resets the other sweep's fields, so a slow or
failing hygiene sweep never blanks out fresh device data and vice versa.

Results are served instantly by GET /external/api/executive/summary. See
docs/superpowers/specs/2026-08-24-executive-summary-api-design.md for the
original rationale, and the split-cadence follow-up discussion for why the
single-sweep design was split in two.
"""

from __future__ import annotations

import logging
import os
import threading
import time as _time
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# Only checks that need no live per-device/per-object lookups — see spec
# decision 5. "shadow" is deliberately excluded (needs addr/svc resolvers).
_HYGIENE_CHECKS = ["unnamed", "unlogged", "disabled", "expired", "unhit"]

_store: dict = {
    "hygiene_score": None,
    "version_compliance_pct": None,
    "pending_config_diff_count": None,
    "firewall_online_count": None,
    "firewalls_total": None,
    "adom_count": None,
    "rule_count_total": None,
    "rule_hygiene": None,
    "status": "pending",  # pending | running | ok | error
    "error": None,
    "last_updated": None,
}

_lock = threading.Lock()
_device_running = threading.Event()
_hygiene_running = threading.Event()


def get_summary() -> dict:
    """Return a copy of the current summary store (safe to serialise as JSON)."""
    with _lock:
        return dict(_store)


# ── Pure aggregation helpers (no I/O — unit-tested directly) ──────────────────


def _classify_online(devices: list[dict]) -> tuple[int, int]:
    """Return (online_count, total_count) from a flat device list."""
    total = len(devices)
    online = sum(1 for d in devices if d.get("conn_status") == 1)
    return online, total


def _version_compliance_pct(
    devices: list[dict], compliant_versions: list[str]
) -> float | None:
    if not compliant_versions or not devices:
        return None
    total = len(devices)
    compliant = sum(1 for d in devices if d.get("version") in compliant_versions)
    return round(100 * compliant / total, 1)


def _pending_diff_count(devices_by_adom: dict[str, list[dict]]) -> int:
    count = 0
    for devices in devices_by_adom.values():
        for d in devices:
            if (
                d.get("conf_status") == "outofsync"
                or d.get("db_status") == "modified"
                or d.get("pkg_status") == "modified"
            ):
                count += 1
    return count


def _hygiene_score(total_findings: int, total_policies: int) -> float | None:
    if total_policies == 0:
        return None
    score = 100 * (1 - total_findings / total_policies)
    return round(max(0.0, min(100.0, score)), 1)


def _device_version(d: dict) -> str:
    """Format a device's firmware version — mirrors versions_cache.py's inline logic."""
    os_ver = d.get("os_ver", 0)
    mr = d.get("mr")
    patch = d.get("patch")
    major = (
        int(os_ver) // 100 if str(os_ver).isdigit() and int(os_ver) >= 100 else os_ver
    )
    if mr is not None and patch is not None and int(patch) >= 0:
        return f"v{major}.{mr}.{patch}"
    if mr is not None:
        return f"v{major}.{mr}"
    return "n/a"


def _list_target_adoms(client) -> list[str]:
    """Return non-forti* ADOM names from a live FMG client."""
    adoms_raw = client.get_adoms()
    return [
        a.get("name", "")
        for a in adoms_raw
        if isinstance(a, dict)
        and a.get("name")
        and not a.get("name", "").lower().startswith("forti")
    ]


# ── Device sweep (cheap, frequent) ─────────────────────────────────────────────


def _run_device_sweep(app) -> bool:
    """Sweep device online/version data and pending-diff aggregation.

    Returns True if the store was updated with a fresh "ok" result, False on
    error or if a prior device sweep is still running (overlap skipped).
    """
    if _device_running.is_set():
        logger.info(
            "executive_summary_cache: device sweep already running, skipping overlap"
        )
        return False

    _device_running.set()
    with _lock:
        _store["status"] = "running"
        _store["error"] = None

    logger.info("executive_summary_cache: starting device sweep")
    t0 = _time.monotonic()

    try:
        from app.app_settings import get_setting
        from app.fmg_helpers import make_client
        from app.pending_status_cache import get_all_cached_devices, get_cache_status

        devices_flat: list[dict] = []

        with make_client() as client:
            adom_names = _list_target_adoms(client)

            for adom in adom_names:
                try:
                    raw = client.get_devices(adom)
                except Exception as exc:
                    logger.warning(
                        "executive_summary_cache: get_devices(%s) failed: %s", adom, exc
                    )
                    raw = []
                for d in raw:
                    if not isinstance(d, dict):
                        continue
                    devices_flat.append(
                        {
                            "name": d.get("name", ""),
                            "version": _device_version(d),
                            "conn_status": d.get("conn_status"),
                        }
                    )

        online, total = _classify_online(devices_flat)
        compliant_versions = get_setting("executive_compliant_versions", [])
        compliance_pct = _version_compliance_pct(devices_flat, compliant_versions)
        pending_cache_status = get_cache_status()
        pending_count = (
            _pending_diff_count(get_all_cached_devices())
            if pending_cache_status["status"] == "ok"
            else None
        )

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "executive_summary_cache: device sweep done in %ss — %d/%d online, "
            "compliance=%s, pending=%s",
            elapsed,
            online,
            total,
            compliance_pct,
            pending_count,
        )

        with _lock:
            _store.update(
                {
                    "version_compliance_pct": compliance_pct,
                    "pending_config_diff_count": pending_count,
                    "firewall_online_count": online,
                    "firewalls_total": total,
                    "adom_count": len(adom_names),
                    "status": "ok",
                    "error": None,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
        return True

    except Exception as exc:
        logger.exception("executive_summary_cache: device sweep unhandled error")
        with _lock:
            _store["status"] = "error"
            _store["error"] = str(exc)
        return False
    finally:
        _device_running.clear()


# ── Hygiene sweep (expensive, slow cadence) ────────────────────────────────────


def _run_hygiene_sweep(app) -> bool:
    """Sweep fleet-wide policy findings to compute hygiene_score.

    Downloads every policy in every package in every non-forti* ADOM — the
    expensive half of the executive summary, deliberately run on its own,
    much slower cadence than the device sweep. Returns True if the store
    was updated with a fresh "ok" result, False on error or overlap.
    """
    if _hygiene_running.is_set():
        logger.info(
            "executive_summary_cache: hygiene sweep already running, skipping overlap"
        )
        return False

    _hygiene_running.set()
    with _lock:
        _store["status"] = "running"
        _store["error"] = None

    logger.info("executive_summary_cache: starting hygiene sweep")
    t0 = _time.monotonic()

    try:
        from app.fmg_helpers import make_client
        from app.hygiene import CHECKS as HYGIENE_CHECK_TYPES
        from app.hygiene import find_unused_objects, run_checks

        total_findings = 0
        total_policies = 0
        by_type: dict[str, int] = dict.fromkeys(HYGIENE_CHECK_TYPES, 0)
        by_type["unused_objects"] = 0

        with make_client() as client:
            adom_names = _list_target_adoms(client)

            for adom in adom_names:
                try:
                    packages = client.get_policy_packages(adom)
                except Exception as exc:
                    logger.warning(
                        "executive_summary_cache: get_policy_packages(%s) failed: %s",
                        adom,
                        exc,
                    )
                    continue
                for pkg in packages:
                    pkg_path = pkg.get("path", pkg.get("name", ""))
                    if not pkg_path:
                        continue
                    try:
                        policies = client.get_policies(adom, pkg_path)
                    except Exception as exc:
                        logger.warning(
                            "executive_summary_cache: get_policies(%s, %s) failed: %s",
                            adom,
                            pkg_path,
                            exc,
                        )
                        continue
                    total_policies += len(policies)
                    total_findings += len(run_checks(policies, _HYGIENE_CHECKS))

                    all_findings = run_checks(policies, list(HYGIENE_CHECK_TYPES))
                    for f in all_findings:
                        by_type[f["check"]] = by_type.get(f["check"], 0) + 1

                    try:
                        addresses = client.get_address_objects(adom)
                        addr_groups = client.get_address_groups(adom)
                        services = client.get_service_objects(adom)
                        svc_groups = client.get_service_groups(adom)
                        unused = find_unused_objects(
                            policies, addresses, addr_groups, services, svc_groups
                        )
                        by_type["unused_objects"] += len(
                            unused["unused_addresses"]
                        ) + len(unused["unused_services"])
                    except Exception as exc:
                        logger.warning(
                            "executive_summary_cache: unused-object detection for "
                            "%s/%s failed: %s",
                            adom,
                            pkg_path,
                            exc,
                        )

        hygiene_score = _hygiene_score(total_findings, total_policies)

        rule_hygiene_record = {
            "ran_at": datetime.now(UTC).isoformat(),
            "rule_findings_total": sum(by_type.values()),
            "rule_findings_by_type": by_type,
        }
        from app.hygiene_rollup import append_run as _append_hygiene_rollup

        _append_hygiene_rollup(rule_hygiene_record)

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "executive_summary_cache: hygiene sweep done in %ss — hygiene=%s",
            elapsed,
            hygiene_score,
        )

        with _lock:
            _store.update(
                {
                    "hygiene_score": hygiene_score,
                    "rule_count_total": total_policies,
                    "rule_hygiene": {
                        "rule_findings_total": rule_hygiene_record[
                            "rule_findings_total"
                        ],
                        "rule_findings_by_type": by_type,
                        "collected_at": datetime.now(UTC).isoformat(),
                    },
                    "status": "ok",
                    "error": None,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
        return True

    except Exception as exc:
        logger.exception("executive_summary_cache: hygiene sweep unhandled error")
        with _lock:
            _store["status"] = "error"
            _store["error"] = str(exc)
        return False
    finally:
        _hygiene_running.clear()


def refresh_now(app) -> None:
    """Trigger an immediate background refresh of both sweeps (non-blocking)."""
    threading.Thread(
        target=_run_device_sweep,
        args=[app],
        name="executive_summary_cache_device_refresh",
        daemon=True,
    ).start()
    threading.Thread(
        target=_run_hygiene_sweep,
        args=[app],
        name="executive_summary_cache_hygiene_refresh",
        daemon=True,
    ).start()


def init_scheduler(app):
    """Start both refresh schedulers and fire initial warm-ups immediately."""
    from apscheduler.schedulers.background import BackgroundScheduler

    device_interval_min = int(os.environ.get("EXEC_SUMMARY_REFRESH_MINUTES", "15"))
    hygiene_interval_min = int(
        os.environ.get("EXEC_SUMMARY_HYGIENE_REFRESH_MINUTES", "60")
    )

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_device_sweep,
        args=[app],
        trigger="interval",
        minutes=device_interval_min,
        id="executive_summary_device_refresh",
        name="Executive summary device sweep",
    )
    scheduler.add_job(
        func=_run_hygiene_sweep,
        args=[app],
        trigger="interval",
        minutes=hygiene_interval_min,
        id="executive_summary_hygiene_refresh",
        name="Executive summary hygiene sweep",
    )
    scheduler.start()
    logger.info(
        "executive_summary_cache: scheduler started — device every %d min, "
        "hygiene every %d min",
        device_interval_min,
        hygiene_interval_min,
    )

    # Fire both sweeps immediately in background threads so the first page
    # load has data ASAP. One retry after 15 s each handles transient FMG
    # connectivity at container startup. Each sweep's own return value (not
    # a re-read of the shared _store["status"]) drives its own retry
    # decision, since the two sweeps can run concurrently and would
    # otherwise race on that shared field.
    def _startup_device(app=app):
        if not _run_device_sweep(app):
            logger.info(
                "executive_summary_cache: device startup run failed, retrying in 15s"
            )
            _time.sleep(15)
            _run_device_sweep(app)

    def _startup_hygiene(app=app):
        if not _run_hygiene_sweep(app):
            logger.info(
                "executive_summary_cache: hygiene startup run failed, retrying in 15s"
            )
            _time.sleep(15)
            _run_hygiene_sweep(app)

    threading.Thread(
        target=_startup_device,
        name="executive_summary_cache_device_startup",
        daemon=True,
    ).start()
    threading.Thread(
        target=_startup_hygiene,
        name="executive_summary_cache_hygiene_startup",
        daemon=True,
    ).start()

    return scheduler
