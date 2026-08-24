"""Background cache for the executive-summary external API endpoint.

Runs a periodic sweep (default every EXEC_SUMMARY_REFRESH_MINUTES=15 minutes)
across every non-forti* ADOM, computing four fleet-wide metrics from a
single per-ADOM device list plus a per-ADOM policy sweep:

  - firewall_online_count / firewalls_total  (device conn_status)
  - version_compliance_pct                   (device version vs. an admin-
                                                configured target list)
  - pending_config_diff_count                (aggregated from the existing
                                                pending_status_cache)
  - hygiene_score                            (findings-density across a
                                                restricted, cheap check set)

Results are held in _store and served instantly by
GET /external/api/executive/summary. See docs/superpowers/specs/
2026-08-24-executive-summary-api-design.md for the full rationale.
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
    "status": "pending",  # pending | running | ok | error
    "error": None,
    "last_updated": None,
}

_lock = threading.Lock()
_running = threading.Event()


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


# ── FMG sweep ───────────────────────────────────────────────────────────────


def _run_job(app) -> None:
    """Sweep every non-forti* ADOM and refresh the summary store."""
    if _running.is_set():
        logger.info("executive_summary_cache: already running, skipping overlap")
        return

    _running.set()
    with _lock:
        _store["status"] = "running"
        _store["error"] = None

    logger.info("executive_summary_cache: starting refresh")
    t0 = _time.monotonic()

    try:
        from app.app_settings import get_setting
        from app.fmg_helpers import make_client
        from app.hygiene import run_checks
        from app.pending_status_cache import get_all_cached_devices

        devices_flat: list[dict] = []
        total_findings = 0
        total_policies = 0

        with make_client() as client:
            adoms_raw = client.get_adoms()
            adom_names = [
                a.get("name", "")
                for a in adoms_raw
                if isinstance(a, dict)
                and a.get("name")
                and not a.get("name", "").lower().startswith("forti")
            ]

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

        online, total = _classify_online(devices_flat)
        compliant_versions = get_setting("executive_compliant_versions", [])
        compliance_pct = _version_compliance_pct(devices_flat, compliant_versions)
        pending_count = _pending_diff_count(get_all_cached_devices())
        hygiene_score = _hygiene_score(total_findings, total_policies)

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "executive_summary_cache: done in %ss — %d/%d online, "
            "compliance=%s, pending=%d, hygiene=%s",
            elapsed,
            online,
            total,
            compliance_pct,
            pending_count,
            hygiene_score,
        )

        with _lock:
            _store.update(
                {
                    "hygiene_score": hygiene_score,
                    "version_compliance_pct": compliance_pct,
                    "pending_config_diff_count": pending_count,
                    "firewall_online_count": online,
                    "firewalls_total": total,
                    "status": "ok",
                    "error": None,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )

    except Exception as exc:
        logger.exception("executive_summary_cache: unhandled error")
        with _lock:
            _store["status"] = "error"
            _store["error"] = str(exc)
    finally:
        _running.clear()


def refresh_now(app) -> None:
    """Trigger an immediate background refresh (non-blocking)."""
    t = threading.Thread(
        target=_run_job, args=[app], name="executive_summary_cache_refresh", daemon=True
    )
    t.start()


def init_scheduler(app):
    """Start the refresh scheduler and fire an initial warm-up immediately."""
    from apscheduler.schedulers.background import BackgroundScheduler

    interval_min = int(os.environ.get("EXEC_SUMMARY_REFRESH_MINUTES", "15"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_job,
        args=[app],
        trigger="interval",
        minutes=interval_min,
        id="executive_summary_refresh",
        name="Executive summary cache refresh",
    )
    scheduler.start()
    logger.info(
        "executive_summary_cache: scheduler started — every %d minutes", interval_min
    )

    t = threading.Thread(
        target=_run_job, args=[app], name="executive_summary_cache_startup", daemon=True
    )
    t.start()

    return scheduler
