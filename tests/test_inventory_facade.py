"""Inventory facade (Phase 2, Task 4)."""

from datetime import UTC, datetime, timedelta

import pytest

from app import inventory, inventory_cache, inventory_store
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG


class Spy:
    """Stands in for an FMGClient; records which methods were called."""

    def __init__(self, real=None, boom=False):
        self.real, self.boom, self.calls = real, boom, []

    def _do(self, name, *a):
        self.calls.append(name)
        if self.boom or self.real is None:
            raise AssertionError(f"unexpected live FMG call: {name}")
        return getattr(self.real, name)(*a)

    def get_adoms(self):
        return self._do("get_adoms")

    def get_devices(self, adom):
        return self._do("get_devices", adom)

    def get_devices_with_sync_status(self, adom):
        return self._do("get_devices_with_sync_status", adom)

    def get_device_pkg_status(self, adom, device, vdoms):
        return self._do("get_device_pkg_status", adom, device, vdoms)


@pytest.fixture
def fleet(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    monkeypatch.setattr(Config, "INVENTORY_MAX_AGE_SECS", 900)
    inventory.reset_counters()
    synth = SyntheticFMG(adoms=2, devices=60, multi_vdom_fraction=0.5, seed=5)
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    inventory_cache.refresh_once(real)
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    return real, adom


def _old(seconds):
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()


def test_flag_off_calls_client_and_never_touches_store(monkeypatch, fleet):
    real, adom = fleet
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)

    def nope(*a, **k):
        raise AssertionError("store touched with flag off")

    for fn in ("read_devices", "read_adom_list", "read_meta", "read_pkg_status"):
        monkeypatch.setattr(inventory_store, fn, nope)
    spy = Spy(real)
    assert inventory.devices(spy, adom) == real.get_devices(adom)
    assert inventory.adoms(spy) == real.get_adoms()
    assert spy.calls == ["get_devices", "get_adoms"]
    assert inventory.counters() == {"hits": 0, "fallbacks": 0, "store_errors": 0}


def test_flag_on_fresh_serves_from_store_zero_fmg_calls(fleet):
    real, adom = fleet
    spy = Spy(boom=True)
    assert inventory.devices(spy, adom) == real.get_devices(adom)
    assert inventory.adoms(spy) == real.get_adoms()
    assert spy.calls == []
    assert inventory.counters()["hits"] == 2


def test_stale_adom_falls_back_live_and_counts(fleet):
    real, adom = fleet
    inventory_store.replace_adom(adom, real.get_devices(adom), None, _old(5000))
    spy = Spy(real)
    assert inventory.devices(spy, adom) == real.get_devices(adom)
    assert spy.calls == ["get_devices"]
    assert inventory.counters()["fallbacks"] == 1


def test_never_collected_falls_back_live(fleet):
    class OnlyDevices:
        calls = 0

        def get_devices(self, adom):
            OnlyDevices.calls += 1
            return []

    assert inventory.devices(OnlyDevices(), "Unknown ADOM") == []
    assert OnlyDevices.calls == 1
    assert inventory.counters()["fallbacks"] == 1


def test_error_status_within_max_age_still_served(fleet):
    real, adom = fleet
    inventory_store.mark_adom_error(adom, "boom")
    spy = Spy(boom=True)
    assert inventory.devices(spy, adom) == real.get_devices(adom)
    assert spy.calls == []


def test_store_error_falls_back_live(monkeypatch, fleet):
    real, adom = fleet

    def broken(*a, **k):
        raise inventory_store.InventoryStoreError("io")

    monkeypatch.setattr(inventory_store, "read_meta", broken)
    spy = Spy(real)
    assert inventory.devices(spy, adom) == real.get_devices(adom)
    assert inventory.counters()["store_errors"] == 1


def test_devices_returns_copies(fleet):
    _, adom = fleet
    first = inventory.devices(Spy(boom=True), adom)
    first[0]["name"] = "MUTATED"
    first.clear()
    again = inventory.devices(Spy(boom=True), adom)
    assert again and again[0]["name"] != "MUTATED"


def test_sync_status_equals_legacy_output(fleet):
    real, adom = fleet
    assert inventory.devices_with_sync_status(
        Spy(boom=True), adom
    ) == real.get_devices_with_sync_status(adom)
    raw = inventory.devices(Spy(boom=True), adom)
    assert isinstance(raw[0]["conf_status"], int)  # stored rows stay raw


def test_pkg_status_equals_legacy_for_multi_vdom(fleet):
    real, adom = fleet
    seen = set()
    for d in real.get_devices(adom):
        vdoms = [v["name"] for v in d.get("vdom") or []] or ["root"]
        got = inventory.pkg_status(Spy(boom=True), adom, d["name"], vdoms)
        want = real.get_device_pkg_status(adom, d["name"], vdoms)
        seen.add(want)
        assert got == want, d["name"]
    assert {"modified", "nomod"} <= seen


def test_pkg_status_collected_but_empty_is_valid_answer(fleet):
    real, adom = fleet
    inventory_store.replace_adom(
        adom, real.get_devices(adom), [], datetime.now(UTC).isoformat()
    )
    spy = Spy(boom=True)
    assert inventory.pkg_status(spy, adom, "anything", ["root"]) == ""
    assert spy.calls == []


def test_pkg_status_falls_back_live_when_never_collected(fleet):
    real, adom = fleet
    inventory_store.replace_adom(
        adom, real.get_devices(adom), None, datetime.now(UTC).isoformat()
    )
    inventory_store.delete_missing_adoms({adom})  # drops other ADOMs only
    # replace_adom(None) kept earlier rows, so force the never-collected state
    inventory_store.delete_missing_adoms(set())
    inventory_store.replace_adom(
        adom, real.get_devices(adom), None, datetime.now(UTC).isoformat()
    )
    d = real.get_devices(adom)[0]
    vd = [v["name"] for v in d.get("vdom") or []] or ["root"]
    spy = Spy(real)
    assert inventory.pkg_status(spy, adom, d["name"], vd) == real.get_device_pkg_status(
        adom, d["name"], vd
    )
    assert spy.calls == ["get_device_pkg_status"]


def test_fresh_empty_adom_is_valid_not_fallback(fleet):
    inventory_store.replace_adom("Empty", [], [], datetime.now(UTC).isoformat())
    spy = Spy(boom=True)
    assert inventory.devices(spy, "Empty") == []
    assert spy.calls == []


def test_freshness_marks_stale(fleet):
    real, adom = fleet
    inventory_store.replace_adom(adom, real.get_devices(adom), None, _old(5000))
    rows = {r["adom"]: r for r in inventory.freshness()}
    assert rows[adom]["stale"] is True
    others = [r for a, r in rows.items() if a != adom]
    assert others and all(r["stale"] is False for r in others)


def test_freshness_empty_when_flag_off(monkeypatch, fleet):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    assert inventory.freshness() == []
