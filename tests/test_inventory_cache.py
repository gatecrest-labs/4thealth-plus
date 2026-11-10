"""Collector inventory refresh job (Phase 2, Task 3)."""

import threading
import time

import pytest

from app import inventory_cache, inventory_store
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG


def _client(synth):
    c = FMGClient(host="fmg.example", token="t")
    c._post = synth.post
    return c


def _non_forti(c):
    return [
        a["name"] for a in c.get_adoms() if not a["name"].lower().startswith("forti")
    ]


def test_refresh_once_makes_one_adom_list_call_and_two_calls_per_adom():
    synth = SyntheticFMG(adoms=5, devices=200)
    c = _client(synth)
    n = len(_non_forti(c))
    synth.calls.clear()
    result = inventory_cache.refresh_once(c)
    assert sum(synth.calls.values()) == 1 + 2 * n
    assert result["adoms"] == n and result["failed"] == []
    assert result["devices"] == 200
    assert result["fmg_calls"] == 1 + 2 * n
    for adom in _non_forti(c):
        assert inventory_store.read_devices(adom)
        assert inventory_store.read_pkg_status(adom)


def test_adom_list_stored_whole_devices_only_for_non_forti():
    synth = SyntheticFMG(adoms=2, devices=10)
    c = _client(synth)
    inventory_cache.refresh_once(c)
    stored = {a["name"] for a in inventory_store.read_adom_list()}
    assert stored == {a["name"] for a in c.get_adoms()}
    assert all(
        not m["adom"].lower().startswith("forti") for m in inventory_store.read_meta()
    )


def test_failed_adom_keeps_previous_rows_and_marks_error_others_updated():
    synth = SyntheticFMG(adoms=3, devices=30)
    c = _client(synth)
    inventory_cache.refresh_once(c)
    names = _non_forti(c)
    bad, good = names[0], names[1]
    before_bad = inventory_store.read_devices(bad)
    real = c.get_devices

    def flaky(adom):
        if adom == bad:
            raise RuntimeError("fmg exploded")
        return real(adom)

    c.get_devices = flaky
    result = inventory_cache.refresh_once(c)
    assert result["failed"] == [bad]
    assert inventory_store.read_devices(bad) == before_bad
    assert inventory_store.read_meta(bad)["status"] == "error"
    assert inventory_store.read_meta(good)["status"] == "ok"


def test_adom_removed_in_fmg_is_deleted():
    synth = SyntheticFMG(adoms=3, devices=30)
    c = _client(synth)
    inventory_cache.refresh_once(c)
    names = _non_forti(c)
    gone = names[-1]
    real = c.get_adoms
    c.get_adoms = lambda: [a for a in real() if a["name"] != gone]
    inventory_cache.refresh_once(c)
    assert inventory_store.read_devices(gone) is None
    assert inventory_store.read_meta(gone) is None


def test_adom_list_failure_changes_nothing():
    synth = SyntheticFMG(adoms=2, devices=10)
    c = _client(synth)
    inventory_cache.refresh_once(c)
    c.get_adoms = lambda: (_ for _ in ()).throw(RuntimeError("down"))
    with pytest.raises(RuntimeError):
        inventory_cache.refresh_once(c)
    assert inventory_store.read_devices(_non_forti(_client(synth))[0])


def test_parallel_fetch_respects_parallel_cap(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_PARALLEL_ADOMS", 2)
    synth = SyntheticFMG(adoms=6, devices=12)
    c = _client(synth)
    lock = threading.Lock()
    state = {"now": 0, "peak": 0}
    real = c.get_devices

    def slow(adom):
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.03)
        try:
            return real(adom)
        finally:
            with lock:
                state["now"] -= 1

    c.get_devices = slow
    inventory_cache.refresh_once(c)
    assert 1 <= state["peak"] <= 2


def test_refresh_is_single_flight():
    synth = SyntheticFMG(adoms=2, devices=10)
    c = _client(synth)
    gate, entered = threading.Event(), threading.Event()
    real = c.get_devices

    def blocking(adom):
        entered.set()
        gate.wait(2)
        return real(adom)

    c.get_devices = blocking
    out = []
    t = threading.Thread(target=lambda: out.append(inventory_cache.refresh_once(c)))
    t.start()
    entered.wait(2)
    assert inventory_cache.refresh_once(c) == {"skipped": True}
    gate.set()
    t.join()
    assert "skipped" not in out[0]


def test_bulk_pkg_status_failure_keeps_old_pkg_rows():
    synth = SyntheticFMG(adoms=1, devices=20)
    c = _client(synth)
    inventory_cache.refresh_once(c)
    adom = _non_forti(c)[0]
    before = inventory_store.read_pkg_status(adom)
    assert before
    c.get_adom_package_status = lambda a: (_ for _ in ()).throw(RuntimeError("no"))
    result = inventory_cache.refresh_once(c)
    assert result["failed"] == []  # devices refreshed fine
    assert inventory_store.read_pkg_status(adom) == before
    assert inventory_store.read_meta(adom)["status"] == "ok"


def test_scheduler_not_registered_when_flag_off(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    assert inventory_cache.init_scheduler(object()) is False


def test_scheduler_registers_refresh_and_request_poll_when_flag_on(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    added = []

    class FakeSched:
        def add_job(self, **kw):
            added.append(kw["id"])

        def start(self):
            pass

    monkeypatch.setattr(inventory_cache, "_make_scheduler", lambda: FakeSched())
    monkeypatch.setattr(inventory_cache, "_start_first_refresh", lambda app: None)
    assert inventory_cache.init_scheduler(object()) is True
    assert set(added) == {"inventory_refresh", "inventory_refresh_request_poll"}


def test_request_poll_triggers_refresh_once(monkeypatch):
    calls = []
    monkeypatch.setattr(
        inventory_cache, "refresh_once", lambda client=None: calls.append(1) or {}
    )
    inventory_cache.poll_refresh_request()
    assert calls == []
    assert inventory_store.request_refresh(0)
    inventory_cache.poll_refresh_request()
    inventory_cache.poll_refresh_request()
    assert calls == [1]
