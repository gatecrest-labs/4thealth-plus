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
    stored = collector_store.read_snapshot(f"fmg_metrics:{fmg_metrics.role()}")
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
