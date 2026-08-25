"""Background summary job — counts firewalls and policy rules across all ADOMs.

The job runs once on app startup, then on a configurable schedule (default: 01:00 daily).
Results are held in _store and served instantly by /api/summary.

Environment variables
---------------------
SUMMARY_REFRESH_HOUR   int  0-23   Hour (server local time) the daily job fires (default: 1)
SUMMARY_REFRESH_MINUTE int  0-59   Minute within that hour (default: 0)
"""

import logging
import os
import threading
import time as _time
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# ── Shared state ──────────────────────────────────────────────────────────────

_store: dict = {
    "firewalls_total": None,
    "rules_total": None,
    "last_updated": None,  # ISO-8601 UTC string
    "status": "pending",  # pending | running | ok | error
    "error": None,
}

_lock = threading.Lock()
_running = threading.Event()  # set while a job is executing; prevents overlaps


def get_summary() -> dict:
    """Return a copy of the current summary store (safe to serialise as JSON)."""
    with _lock:
        return dict(_store)


# ── Core calculation ──────────────────────────────────────────────────────────


def _run_job(app):
    """Calculate managed firewall and policy-rule totals."""
    if _running.is_set():
        logger.info("summary_job: already running, skipping overlap")
        return

    _running.set()
    with _lock:
        _store["status"] = "running"
        _store["error"] = None

    logger.info("summary_job: starting calculation")
    t0 = _time.monotonic()

    try:
        from app.fmg_helpers import make_client

        firewalls_total = 0
        rules_total = 0

        with make_client() as client:
            # ── Step 1: enumerate ADOMs ───────────────────────────────────
            adoms_raw = client.get_adoms()
            adom_names = [
                a.get("name", "")
                for a in adoms_raw
                if isinstance(a, dict)
                and a.get("name")
                and not a.get("name", "").lower().startswith("forti")
            ]
            logger.info("summary_job: %d ADOMs found: %s", len(adom_names), adom_names)

            # ── Step 2: count devices per ADOM; track which have devices ──
            adoms_with_devices = []
            for adom in adom_names:
                try:
                    devices = client.get_devices(adom)
                    count = len(devices) if isinstance(devices, list) else 0
                    firewalls_total += count
                    if count > 0:
                        adoms_with_devices.append(adom)
                except Exception as exc:
                    logger.warning("summary_job: get_devices(%s) failed: %s", adom, exc)

            logger.info(
                "summary_job: %d firewalls across %d ADOMs with devices: %s",
                firewalls_total,
                len(adoms_with_devices),
                adoms_with_devices,
            )

            # ── Step 3: count policy rules — only ADOMs that have devices ─
            for adom in adoms_with_devices:
                try:
                    packages = client.get_policy_packages(adom)
                    logger.info(
                        "summary_job: ADOM %s — %d packages to count",
                        adom,
                        len(packages),
                    )
                    for pkg in packages:
                        pkg_path = pkg.get("path", pkg.get("name", ""))
                        if not pkg_path:
                            continue
                        count = client.get_policy_count(adom, pkg_path)
                        rules_total += count
                except Exception as exc:
                    logger.warning(
                        "summary_job: policy count for ADOM %s failed: %s", adom, exc
                    )

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "summary_job: done in %ss — %d firewalls, %d rules",
            elapsed,
            firewalls_total,
            rules_total,
        )

        with _lock:
            _store.update(
                {
                    "firewalls_total": firewalls_total,
                    "rules_total": rules_total,
                    "last_updated": datetime.now(UTC).isoformat(),
                    "status": "ok",
                    "error": None,
                }
            )

        # Persist today's totals for the 30-day trend graphs.
        # record_today() is idempotent — safe to call on startup runs too.
        try:
            from app.summary_history import record_today

            record_today(firewalls_total, rules_total)
        except Exception as exc:
            logger.warning("summary_history: record_today failed: %s", exc)

    except Exception as exc:
        logger.exception("summary_job: unhandled error")
        with _lock:
            _store["status"] = "error"
            _store["error"] = str(exc)
    finally:
        _running.clear()


# ── Scheduler wiring ──────────────────────────────────────────────────────────


def init_scheduler(app):
    """Register the summary job with APScheduler and fire it once immediately.

    Call this once from the Flask app factory after all blueprints are registered.
    """
    from apscheduler.schedulers.background import BackgroundScheduler

    refresh_hour = int(os.environ.get("SUMMARY_REFRESH_HOUR", "1"))
    refresh_minute = int(os.environ.get("SUMMARY_REFRESH_MINUTE", "0"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_job,
        args=[app],
        trigger="cron",
        hour=refresh_hour,
        minute=refresh_minute,
        id="summary_refresh",
        name="Nightly summary refresh",
    )
    scheduler.start()
    logger.info(
        "summary_job: scheduler started — daily at %02d:%02d local time",
        refresh_hour,
        refresh_minute,
    )

    # Fire immediately in a background thread so the first page load has data ASAP.
    # One retry after 15 s handles transient FMG connectivity at container startup.
    def _startup(app=app):
        _run_job(app)
        with _lock:
            needs_retry = _store["status"] != "ok"
        if needs_retry:
            logger.info("summary_job: startup run failed, retrying in 15s")
            _time.sleep(15)
            _run_job(app)

    t = threading.Thread(target=_startup, name="summary_job_startup", daemon=True)
    t.start()

    return scheduler
