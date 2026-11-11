"""Collector-side executor for server-side jobs (F6).

A scheduler tick every couple of seconds claims queued jobs (oldest first) while
fewer than ``JOB_MAX_RUNNING`` are active and runs each in a worker thread. The
runner is the only thing that moves a job out of ``queued``. At start it fails any
job a previous process left ``running`` and prunes old finished jobs hourly. A
handler exception fails only that job, with a short message (the traceback goes to
the log, never to the user).
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app import boot_warmup, job_handlers, job_store
from app.config import Config

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_active = 0
_pool: ThreadPoolExecutor | None = None


def _make_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler

    return BackgroundScheduler()


def execute(job: dict) -> None:
    """Run one claimed job to a terminal state (never raises)."""
    jid = job["id"]
    try:
        result, cancelled = job_handlers.run(
            job["kind"],
            job["adom"],
            job["request"] or {},
            lambda done, total, message="": job_store.progress(
                jid, done, total, str(message)
            ),
            lambda: job_store.cancel_requested(jid),
        )
        job_store.finish(jid, result, cancelled=cancelled)
    except Exception as exc:
        logger.exception("job_runner: job %s (%s) failed", jid, job.get("kind"))
        try:
            job_store.fail(jid, f"job failed ({type(exc).__name__})")
        except Exception:
            logger.exception("job_runner: could not record failure of %s", jid)


def _run_and_release(job: dict) -> None:
    global _active
    try:
        execute(job)
    finally:
        with _lock:
            _active -= 1


def tick(submit=None) -> int:
    """Claim and start as many queued jobs as the cap allows; returns how many started."""
    global _active
    started = 0
    cap = max(1, int(Config.JOB_MAX_RUNNING))
    while True:
        with _lock:
            if _active >= cap:
                break
            _active += 1
        try:
            job = job_store.claim_next()
        except Exception:
            with _lock:
                _active -= 1
            logger.exception("job_runner: claim failed")
            break
        if job is None:
            with _lock:
                _active -= 1
            break
        started += 1
        (submit or _submit)(job)
    return started


def _submit(job: dict) -> None:
    global _pool
    if _pool is None:
        _pool = ThreadPoolExecutor(
            max_workers=max(1, int(Config.JOB_MAX_RUNNING)), thread_name_prefix="job"
        )
    _pool.submit(_run_and_release, job)


def _run_tick(app=None) -> None:
    try:
        tick()
    except Exception:
        logger.exception("job_runner: tick failed")


def _run_prune(app=None) -> None:
    try:
        n = job_store.prune()
        if n:
            logger.info("job_runner: pruned %d finished jobs", n)
    except Exception:
        logger.exception("job_runner: prune failed")


def _startup(app) -> None:
    try:
        n = job_store.recover_orphans()
        if n:
            logger.warning("job_runner: failed %d jobs left running by a restart", n)
    except Exception:
        logger.exception("job_runner: orphan recovery failed")
    _run_prune(app)


def init_scheduler(app) -> bool:
    """Register the job runner (collector only, ``JOB_QUEUE`` on)."""
    if not Config.JOB_QUEUE:
        return False
    _startup(app)  # before the first tick, so a restart never resumes half a job
    scheduler = _make_scheduler()
    scheduler.add_job(
        func=_run_tick,
        args=[app],
        trigger="interval",
        seconds=2,
        id="job_runner_tick",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        func=_run_prune,
        args=[app],
        trigger="interval",
        hours=1,
        id="job_runner_prune",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    boot_warmup.defer("job_runner", lambda: None, 3)
    return True
