"""FMG call metrics: counts, errors and latency per normalized URL."""

import threading

import pytest
import requests


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "m.db"))
    from app import fmg_metrics

    fmg_metrics.reset()
    yield
    fmg_metrics.reset()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/dvmdb/adom/Ent/device", "/dvmdb/adom/{adom}/device"),
        (
            "/pm/config/adom/Ent/pkg/Pk/firewall/policy",
            "/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
        ),
        (
            "/pm/config/device/FG-1/global/system/ntp",
            "/pm/config/device/{device}/global/system/ntp",
        ),
        ("/task/task/1234", "/task/task/{id}"),
        ("/pm/pkg/adom/Ent-1", "/pm/pkg/adom/{adom}"),
        ("/pm/pkg/adom/Ent-1/Pkg-0-001", "/pm/pkg/adom/{adom}/{pkg}"),
        ("/pm/pkg/adom/Ent-1/Folder/Pkg-9", "/pm/pkg/adom/{adom}/{pkg}"),
        (
            "/pm/config/adom/Ent-1/_package/status/FW-1/root",
            "/pm/config/adom/{adom}/_package/status/{device}/{vdom}",
        ),
        (
            "/dvmdb/adom/Ent-1/device/FW-1/vdom",
            "/dvmdb/adom/{adom}/device/{device}/vdom",
        ),
        ("/sys/proxy/json", "/sys/proxy/json"),
    ],
)
def test_normalize_url_examples(raw, expected):
    from app.fmg_metrics import normalize_url

    assert normalize_url(raw) == expected


def test_record_and_snapshot_counts_and_percentiles():
    from app import fmg_metrics

    for s in (0.1, 0.2, 0.3, 0.4, 1.0):
        fmg_metrics.record("get", "/dvmdb/adom/A/device", s, True)
    fmg_metrics.record("get", "/dvmdb/adom/B/device", 0.5, False)

    snap = fmg_metrics.snapshot()
    entry = snap["by_url"]["get /dvmdb/adom/{adom}/device"]
    assert snap["total"] == 6
    assert snap["errors"] == 1
    assert entry["count"] == 6
    assert entry["errors"] == 1
    assert entry["p50_s"] == pytest.approx(0.35, abs=0.2)
    assert entry["p95_s"] >= 0.5
    assert entry["total_s"] == pytest.approx(2.5)


def test_record_is_thread_safe():
    from app import fmg_metrics

    def work():
        for _ in range(1000):
            fmg_metrics.record("get", "/sys/status", 0.001, True)

    threads = [threading.Thread(target=work) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert fmg_metrics.snapshot()["total"] == 16000


def test_record_failure_never_raises(monkeypatch):
    from app import collector_store, fmg_metrics

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(collector_store, "write_snapshot", boom)
    fmg_metrics.record("get", "/sys/status", 0.01, True)
    fmg_metrics.flush(force=True)  # must not raise


def test_flush_writes_role_keyed_snapshot():
    from app import collector_store, fmg_metrics

    fmg_metrics.record("get", "/sys/status", 0.01, True)
    fmg_metrics.flush(force=True)
    stored = collector_store.read_snapshot(fmg_metrics.snapshot_key())
    assert stored["total"] == 1


class _Resp:
    def raise_for_status(self):
        pass

    def json(self):
        return {"result": [{"status": {"code": 0}, "data": []}]}


def _client():
    from app.fmg_client import FMGClient

    return FMGClient(host="fmg.invalid", token="t")


def test_post_records_metric():
    from app import fmg_metrics

    c = _client()
    c._http.post = lambda *a, **k: _Resp()
    c._post({"id": 1, "method": "get", "params": [{"url": "/dvmdb/adom"}]})
    assert fmg_metrics.snapshot()["by_url"]["get /dvmdb/adom"]["count"] == 1


def test_post_records_error_and_reraises():
    from app import fmg_metrics

    c = _client()

    def fail(*a, **k):
        raise requests.ConnectionError("down")

    c._http.post = fail
    with pytest.raises(requests.ConnectionError):
        c._post({"id": 1, "method": "get", "params": [{"url": "/dvmdb/adom"}]})
    entry = fmg_metrics.snapshot()["by_url"]["get /dvmdb/adom"]
    assert entry["errors"] == 1


def test_get_paged_goes_through_post_with_long_timeout():
    """_get_paged must use _post so catalogs are metered/recorded, and keep its 120 s timeout."""
    from app import fmg_metrics

    class Page:
        def raise_for_status(self):
            pass

        def json(self):
            return {"result": [{"status": {"code": 0}, "data": [{"name": "a"}]}]}

    calls = []
    c = _client()

    def fake_post(*args, **kwargs):
        calls.append(kwargs)
        return Page()

    c._http.post = fake_post
    assert c._get_paged("/pm/config/adom/E/obj/firewall/address") == [{"name": "a"}]
    assert calls[0]["timeout"] == 120
    key = "get /pm/config/adom/{adom}/obj/firewall/address"
    assert fmg_metrics.snapshot()["by_url"][key]["count"] == 1


# ---- review fix pass -------------------------------------------------------


def _ok_post(c):
    c._http.post = lambda *a, **k: _Resp()
    return lambda: c._post(
        {"id": 1, "method": "get", "params": [{"url": "/dvmdb/adom"}]}
    )


def test_post_does_not_wait_for_slow_store(monkeypatch):
    """I1: the metrics write must not run on the FMG call path."""
    import time

    from app import collector_store, fmg_metrics

    monkeypatch.setattr(fmg_metrics, "_flush_async", True)
    started, release = threading.Event(), threading.Event()

    def slow(*a, **k):
        started.set()
        release.wait(5)

    monkeypatch.setattr(collector_store, "write_snapshot", slow)
    call = _ok_post(_client_obj := _client())
    t0 = time.monotonic()
    call()
    assert time.monotonic() - t0 < 1.0
    assert started.wait(2), "the snapshot is still written, in the background"
    release.set()
    for (
        t
    ) in threading.enumerate():  # don't leak the in-flight writer into the next test
        if t.name == "fmg-metrics-flush":
            t.join(5)


def test_flush_is_single_flight(monkeypatch):
    """I1: many threads reaching flush() at once produce one write."""
    from app import collector_store, fmg_metrics

    monkeypatch.setattr(fmg_metrics, "_flush_async", True)
    calls, gate = [], threading.Event()

    def slow(*a, **k):
        calls.append(1)
        gate.wait(2)

    monkeypatch.setattr(collector_store, "write_snapshot", slow)
    fmg_metrics.record("get", "/sys/status", 0.01, True)
    threads = [threading.Thread(target=fmg_metrics.flush) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    import time

    deadline = time.monotonic() + 2
    while not calls and time.monotonic() < deadline:
        time.sleep(0.01)  # the single background write starts shortly after
    time.sleep(0.1)  # a second writer (the bug) would have started by now
    gate.set()
    for t in threading.enumerate():
        if t.name == "fmg-metrics-flush":
            t.join(5)
    assert len(calls) == 1


def test_web_snapshot_key_includes_pid_and_collector_does_not(monkeypatch):
    """I2: two gunicorn workers must not overwrite each other's key."""
    import os

    from app import fmg_metrics

    monkeypatch.setattr(fmg_metrics, "role", lambda: "web")
    assert fmg_metrics.snapshot_key() == f"fmg_metrics:web:{os.getpid()}"
    monkeypatch.setattr(fmg_metrics, "role", lambda: "collector")
    assert fmg_metrics.snapshot_key() == "fmg_metrics:collector"


def test_merge_sums_counts_and_keeps_worst_p95():
    from app import fmg_metrics

    def snap(count, errors, p95):
        return {
            "role": "web",
            "since": "x",
            "total": count,
            "errors": errors,
            "by_url": {
                "get /sys/status": {
                    "count": count,
                    "errors": errors,
                    "total_s": count * 0.1,
                    "p50_s": 0.1,
                    "p95_s": p95,
                }
            },
        }

    merged = fmg_metrics.merge([snap(3, 1, 0.2), snap(5, 0, 0.9)])
    assert merged["total"] == 8 and merged["errors"] == 1 and merged["workers"] == 2
    e = merged["by_url"]["get /sys/status"]
    assert e["count"] == 8 and e["errors"] == 1
    assert e["p95_s"] == 0.9
    assert e["p50_s"] == pytest.approx(0.1)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "/pm/config/adom/E/pkg/Folder/Pkg/firewall/policy",
            "/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
        ),
        (
            "/pm/config/adom/E/pblock/BLK-9/firewall/policy",
            "/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy",
        ),
        ("/dvmdb/adom/E/group/GRP-1", "/dvmdb/adom/{adom}/group/{group}"),
        (
            "/pm/config/adom/E/obj/firewall/address/host-1",
            "/pm/config/adom/{adom}/obj/firewall/address/{name}",
        ),
        (
            "/pm/config/adom/E/obj/firewall/service/custom/https2",
            "/pm/config/adom/{adom}/obj/firewall/service/custom/{name}",
        ),
        (
            "/pm/config/adom/E/obj/firewall/address",
            "/pm/config/adom/{adom}/obj/firewall/address",
        ),
    ],
)
def test_normalize_url_collapses_remaining_name_families(raw, expected):
    from app.fmg_metrics import normalize_url

    assert normalize_url(raw) == expected


def test_distinct_keys_are_capped():
    from app import fmg_metrics

    for i in range(fmg_metrics._MAX_KEYS + 100):
        fmg_metrics.record("get", f"/odd/family{i}/x", 0.01, True)
    snap = fmg_metrics.snapshot()
    assert len(snap["by_url"]) <= fmg_metrics._MAX_KEYS + 1
    assert snap["by_url"]["get <other>"]["count"] == 100
    assert snap["total"] == fmg_metrics._MAX_KEYS + 100


def test_metrics_can_be_switched_off(monkeypatch):
    """I4: an off switch so the layer is inert if wanted."""
    from app import collector_store, fmg_metrics

    monkeypatch.setenv("FMG_METRICS", "off")
    fmg_metrics.record("get", "/sys/status", 0.01, True)
    fmg_metrics.flush(force=True)
    assert fmg_metrics.snapshot()["total"] == 0
    assert collector_store.read_snapshot(fmg_metrics.snapshot_key()) is None


def test_fmg_level_error_counts_as_error_without_raising():
    """M1: a -11 inside an HTTP 200 body is an error, not a success."""
    from app import fmg_metrics

    class Denied(_Resp):
        def json(self):
            return {"result": [{"status": {"code": -11, "message": "No permission"}}]}

    c = _client()
    c._http.post = lambda *a, **k: Denied()
    c._post({"id": 1, "method": "get", "params": [{"url": "/dvmdb/adom"}]})
    assert fmg_metrics.snapshot()["by_url"]["get /dvmdb/adom"]["errors"] == 1
