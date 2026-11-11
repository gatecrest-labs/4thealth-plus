"""Job store (Phase 6, Task 1)."""

import os
import threading
from datetime import UTC, datetime, timedelta

import pytest

from app import job_store
from app.config import Config


@pytest.fixture(autouse=True)
def _limits(monkeypatch):
    monkeypatch.setattr(Config, "JOB_MAX_QUEUED_PER_USER", 3)
    monkeypatch.setattr(Config, "JOB_MAX_RESULT_BYTES", 1000)
    monkeypatch.setattr(Config, "JOB_RETENTION_DAYS", 7)


def _enq(owner="alice", adom="A", kind="device_review", **req):
    return job_store.enqueue(kind, owner, adom, {"x": 1, **req})


def test_enqueue_and_get_roundtrip():
    jid = _enq()
    j = job_store.get(jid)
    assert j["status"] == "queued" and j["owner"] == "alice" and j["adom"] == "A"
    assert j["request"]["x"] == 1 and j["done"] == 0 and j["result"] is None


def test_per_user_queue_cap():
    for _ in range(3):
        _enq()
    with pytest.raises(job_store.JobLimitError):
        _enq()
    assert _enq(owner="bob")  # other users unaffected


def test_claim_is_atomic_across_threads(monkeypatch):
    monkeypatch.setattr(Config, "JOB_MAX_QUEUED_PER_USER", 10)
    for _ in range(5):
        _enq()
    got, lock = [], threading.Lock()

    def worker():
        while (j := job_store.claim_next()) is not None:
            with lock:
                got.append(j["id"])

    threads = [threading.Thread(target=worker) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(got) == 5 and len(set(got)) == 5
    assert job_store.get(got[0])["status"] == "running"


def test_claim_oldest_first_and_none_when_empty():
    a, b = _enq(), _enq()
    assert job_store.claim_next()["id"] == a
    assert job_store.claim_next()["id"] == b
    assert job_store.claim_next() is None


def test_progress_finish_and_result():
    jid = _enq()
    job_store.claim_next()
    job_store.progress(jid, 2, 10, "dev2")
    j = job_store.get(jid)
    assert (j["done"], j["total"], j["message"]) == (2, 10, "dev2")
    job_store.finish(jid, {"rows": [1, 2]})
    j = job_store.get(jid)
    assert (
        j["status"] == "done" and j["result"] == {"rows": [1, 2]} and j["finished_at"]
    )


def test_oversized_result_fails_the_job_with_a_clear_message():
    jid = _enq()
    job_store.claim_next()
    job_store.finish(jid, {"blob": os.urandom(2000).hex()})
    j = job_store.get(jid)
    assert j["status"] == "failed" and "too large" in j["error"] and j["result"] is None


def test_fail_records_short_error():
    jid = _enq()
    job_store.claim_next()
    job_store.fail(jid, "boom")
    assert job_store.get(jid)["status"] == "failed"


def test_cancel_queued_is_immediate_running_is_cooperative():
    q = _enq()
    assert job_store.request_cancel(q) == "cancelled"
    assert job_store.get(q)["status"] == "cancelled"
    r = _enq()
    job_store.claim_next()
    assert job_store.request_cancel(r) == "requested"
    assert job_store.cancel_requested(r) is True
    job_store.finish(r, {"partial": True}, cancelled=True)
    assert job_store.get(r)["status"] == "cancelled" and job_store.get(r)["result"] == {
        "partial": True
    }


def test_cancel_after_completion_is_a_noop_and_double_cancel_safe():
    jid = _enq()
    job_store.claim_next()
    job_store.finish(jid, {})
    assert job_store.request_cancel(jid) == "finished"
    assert job_store.get(jid)["status"] == "done"
    q = _enq()
    job_store.request_cancel(q)
    assert job_store.request_cancel(q) == "finished"
    assert job_store.request_cancel("nope") == "missing"


def test_finish_does_not_overwrite_a_cancelled_queued_job():
    jid = _enq()
    job_store.request_cancel(jid)
    job_store.finish(jid, {"late": 1})
    assert job_store.get(jid)["status"] == "cancelled"


def test_list_for_owner_hides_blobs_and_scopes():
    a = _enq(owner="alice", adom="A")
    _enq(owner="bob", adom="B")
    job_store.claim_next()
    job_store.finish(a, {"big": "r"})
    rows = job_store.list_for("alice")
    assert (
        [r["id"] for r in rows] == [a]
        and "result" not in rows[0]
        and "request" not in rows[0]
    )
    assert len(job_store.list_for(None)) == 2  # admin
    assert job_store.list_for("carol") == []


def test_recover_orphans_marks_running_jobs_failed():
    jid = _enq()
    job_store.claim_next()
    assert job_store.recover_orphans() == 1
    j = job_store.get(jid)
    assert j["status"] == "failed" and "restarted" in j["error"]
    assert job_store.recover_orphans() == 0


def test_prune_removes_old_finished_jobs_only():
    old, new, live = _enq(), _enq(), _enq()
    for j in (old, new):
        job_store.claim_next()
        job_store.finish(j, {})
    job_store._set_finished_for_test(
        old, (datetime.now(UTC) - timedelta(days=8)).isoformat()
    )
    assert job_store.prune() == 1
    assert job_store.get(old) is None and job_store.get(new) and job_store.get(live)


def test_running_count():
    _enq()
    _enq()
    assert job_store.running_count() == 0
    job_store.claim_next()
    assert job_store.running_count() == 1
