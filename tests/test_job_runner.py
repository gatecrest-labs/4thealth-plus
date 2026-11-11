"""Collector job runner (Phase 6, Task 3)."""

import threading
import time

import pytest

from app import job_handlers, job_runner, job_store
from app.config import Config


@pytest.fixture(autouse=True)
def _cfg(monkeypatch):
    monkeypatch.setattr(Config, "JOB_MAX_RUNNING", 2)
    monkeypatch.setattr(Config, "JOB_MAX_QUEUED_PER_USER", 20)
    monkeypatch.setattr(Config, "JOB_MAX_RESULT_BYTES", 1_000_000)
    monkeypatch.setattr(job_runner, "_active", 0)


def _enq(kind="device_review", owner="alice", adom="A"):
    return job_store.enqueue(kind, owner, adom, {"x": 1})


def _wait(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


def test_tick_runs_a_job_to_done_with_progress_and_the_stored_adom(monkeypatch):
    seen = {}

    def fake_run(kind, adom, request, progress, should_cancel):
        seen.update(kind=kind, adom=adom, request=request)
        progress(1, 2, "half")
        return {"ok": True}, False

    monkeypatch.setattr(job_handlers, "run", fake_run)
    jid = _enq(adom="Ent-1")
    job_runner.tick(submit=lambda j: job_runner._run_and_release(j))
    j = job_store.get(jid)
    assert j["status"] == "done" and j["result"] == {"ok": True} and j["done"] == 1
    assert seen["adom"] == "Ent-1" and seen["request"] == {"x": 1}


def test_cap_is_respected_and_remaining_jobs_stay_queued(monkeypatch):
    release = threading.Event()
    started = []

    def slow(kind, adom, request, progress, should_cancel):
        started.append(1)
        release.wait(5)
        return {}, False

    monkeypatch.setattr(job_handlers, "run", slow)
    ids = [_enq() for _ in range(4)]
    threads = []

    def submit(job):
        t = threading.Thread(target=job_runner._run_and_release, args=(job,))
        threads.append(t)
        t.start()

    assert job_runner.tick(submit=submit) == 2
    assert _wait(lambda: len(started) == 2)
    assert job_runner.tick(submit=submit) == 0  # still at the cap
    assert sum(job_store.get(i)["status"] == "queued" for i in ids) == 2
    release.set()
    [t.join() for t in threads]
    assert job_runner.tick(submit=submit) == 2  # slots freed
    [t.join() for t in threads]
    assert all(job_store.get(i)["status"] == "done" for i in ids)


def test_handler_exception_fails_only_that_job_with_a_short_message(monkeypatch):
    def boom(kind, adom, request, progress, should_cancel):
        raise RuntimeError("secret internals /etc/passwd")

    monkeypatch.setattr(job_handlers, "run", boom)
    a, b = _enq(), _enq()
    job_runner.tick(submit=lambda j: job_runner._run_and_release(j))
    for i in (a, b):
        j = job_store.get(i)
        assert (
            j["status"] == "failed"
            and "RuntimeError" in j["error"]
            and "passwd" not in j["error"]
        )
    assert job_runner._active == 0


def test_cancel_between_items(monkeypatch):
    def loop(kind, adom, request, progress, should_cancel):
        done = 0
        for _ in range(100):
            if should_cancel():
                return {"partial": done}, True
            done += 1  # noqa: SIM113
            progress(done, 100, "")
            if done == 3:
                job_store.request_cancel(jid)
        return {}, False

    monkeypatch.setattr(job_handlers, "run", loop)
    jid = _enq()
    job_runner.tick(submit=lambda j: job_runner._run_and_release(j))
    j = job_store.get(jid)
    assert j["status"] == "cancelled" and j["result"] == {"partial": 3}


def test_startup_recovers_orphans_and_prunes(monkeypatch):
    jid = _enq()
    job_store.claim_next()
    job_runner._startup(None)
    assert job_store.get(jid)["status"] == "failed"


def test_init_scheduler_is_a_noop_when_flag_off(monkeypatch):
    monkeypatch.setattr(Config, "JOB_QUEUE", False)
    assert job_runner.init_scheduler(None) is False


def test_init_scheduler_registers_jobs_when_on(monkeypatch):
    monkeypatch.setattr(Config, "JOB_QUEUE", True)
    added = []

    class FakeSched:
        def add_job(self, **kw):
            added.append(kw["id"])

        def start(self):
            pass

    monkeypatch.setattr(job_runner, "_make_scheduler", FakeSched)
    monkeypatch.setattr(job_runner.boot_warmup, "defer", lambda *a, **k: None)
    assert job_runner.init_scheduler(None) is True
    assert added == ["job_runner_tick", "job_runner_prune"]


def test_a_failing_submit_fails_the_job_and_frees_the_slot():
    jid = _enq()

    def bad_submit(job):
        raise RuntimeError("pool is shut down")

    job_runner.tick(submit=bad_submit)
    j = job_store.get(jid)
    assert j["status"] == "failed" and job_runner._active == 0
    assert job_store.running_count() == 0
