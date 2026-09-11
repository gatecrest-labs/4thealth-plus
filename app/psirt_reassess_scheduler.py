"""Scheduled re-assessment of open PSIRT advisories against the fleet.

Runs app.psirt.engine.assess() for every advisory still open in psirt.db,
on the same cadence as the executive-summary device sweep
(EXEC_SUMMARY_REFRESH_MINUTES) — mirrors app.executive_summary_cache's
pattern (BackgroundScheduler interval job, an in-flight guard against
overlap, startup warm-up, "a failure keeps the last result").

Unlike an interactive Audit Review > PSIRT run, this does NOT make a fresh
FMG device-list call. It reuses the device sweep's already-cached
inventory (app.executive_summary_cache.get_devices_raw_by_adom()) via
_CachedDeviceClient below, which implements just the subset of FMGClient
that engine.assess() calls to enumerate devices and firmware:
get_adoms() and get_devices(adom).

Two things the cached client cannot do, both handled by degrading rather
than crashing (engine.assess() already treats both as recoverable):
  - get_system_status() (the FortiManager-itself finding, when an advisory
    names FortiManager as an affected product) — raises, which engine
    catches and reports as a warning + degraded=True. The FMG's own
    version isn't part of the device-sweep inventory.
  - Workaround verification (app.psirt.workaround_checks.check_workaround)
    needs live per-device config reads the cached inventory doesn't carry
    — the underlying real-client calls it tries will fail against
    _CachedDeviceClient, which engine.assess() already turns into
    workaround_status="manual_verification_required" per device rather
    than failing the whole assessment.

A per-advisory failure (exception, or the assessment coming back
degraded with no findings) skips saving for that advisory only — its
last successful result stays in psirt.db untouched — and the sweep moves
on to the next advisory.
"""

from __future__ import annotations

import logging
import os
import threading
import time as _time

logger = logging.getLogger(__name__)

_running = threading.Event()


class _CachedDeviceClient:
    """Minimal FMGClient stand-in backed by cached device inventory.

    Only the methods app.psirt.engine.assess() actually calls are
    implemented. Anything else (workaround checks, get_system_status)
    raises, which the engine already treats as a per-device or
    per-advisory degradation rather than a hard failure.
    """

    def __init__(self, devices_raw_by_adom: dict[str, list[dict]]):
        self._devices_raw_by_adom = devices_raw_by_adom

    def get_adoms(self) -> list[dict]:
        return [{"name": adom} for adom in self._devices_raw_by_adom]

    def get_devices(self, adom: str) -> list[dict]:
        return list(self._devices_raw_by_adom.get(adom, []))

    def get_system_status(self) -> dict:
        raise RuntimeError(
            "FortiManager's own version is not part of the cached device "
            "inventory used for scheduled PSIRT re-assessment"
        )

    def __getattr__(self, name):
        def _unsupported(*args, **kwargs):
            raise RuntimeError(
                f"{name} is not available from cached device inventory "
                "(scheduled PSIRT re-assessment does not make live FMG calls)"
            )

        return _unsupported


def _run_reassessment(app) -> bool:
    """Re-run assess() for every open advisory. Returns True if the sweep
    completed (even if individual advisories were skipped), False if a
    prior sweep is still running or the sweep itself failed outright."""
    if _running.is_set():
        logger.info("psirt_reassess_scheduler: already running, skipping overlap")
        return False

    _running.set()
    t0 = _time.monotonic()
    try:
        from app.config import Config
        from app import psirt_store
        from app.executive_summary_cache import get_devices_raw_by_adom
        from app.psirt.engine import assess as psirt_assess
        from app.psirt.models import Advisory, AffectedRange

        open_advisories = psirt_store.get_open_advisories()
        if not open_advisories:
            logger.info("psirt_reassess_scheduler: no open advisories, nothing to do")
            return True

        devices_raw_by_adom = get_devices_raw_by_adom()
        client = _CachedDeviceClient(devices_raw_by_adom)

        import requests

        succeeded = 0
        for adv in open_advisories:
            advisory_id = adv["advisory_id"]
            try:
                ranges = [
                    AffectedRange(**r) if isinstance(r, dict) else AffectedRange(product=str(r))
                    for r in adv["affected_ranges"]
                ]
                advisory = Advisory(
                    advisory_id=advisory_id,
                    cve_ids=list(adv["cves"]),
                    fortinet_severity=adv["severity"] or "",
                    cvss_score=adv["cvss"],
                    affected_ranges=ranges,
                    workaround_text=adv["workaround_text"] or "",
                )
                result = psirt_assess(
                    advisory,
                    client,
                    "*",
                    requests,
                    Config.PSIRT_KEV_URL if Config.PSIRT_ENRICHMENT_ENABLED else "",
                    enrichment_enabled=Config.PSIRT_ENRICHMENT_ENABLED,
                    fetch_timeout=Config.PSIRT_FETCH_TIMEOUT,
                )
                psirt_store.save_assessment_result(result.to_dict())
                succeeded += 1
            except Exception as exc:
                logger.warning(
                    "psirt_reassess_scheduler: re-assessment of %s failed, "
                    "keeping last result: %s",
                    advisory_id,
                    exc,
                )

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "psirt_reassess_scheduler: re-assessed %d/%d open advisories in %ss",
            succeeded,
            len(open_advisories),
            elapsed,
        )
        return True
    except Exception:
        logger.exception("psirt_reassess_scheduler: unhandled error")
        return False
    finally:
        _running.clear()


def refresh_now(app) -> None:
    """Trigger an immediate background re-assessment sweep (non-blocking)."""
    threading.Thread(
        target=_run_reassessment,
        args=[app],
        name="psirt_reassess_refresh",
        daemon=True,
    ).start()


def init_scheduler(app):
    """Start the re-assessment scheduler on the device-sweep cadence."""
    from apscheduler.schedulers.background import BackgroundScheduler

    interval_min = int(os.environ.get("EXEC_SUMMARY_REFRESH_MINUTES", "15"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_reassessment,
        args=[app],
        trigger="interval",
        minutes=interval_min,
        id="psirt_reassess_refresh",
        name="PSIRT advisory re-assessment",
    )
    scheduler.start()
    logger.info(
        "psirt_reassess_scheduler: scheduler started — every %d min", interval_min
    )
    return scheduler
