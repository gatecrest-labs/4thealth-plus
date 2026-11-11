"""Audit data facade (Phase 5, Task 4)."""
# ruff: noqa: RUF059

from datetime import UTC, datetime, timedelta

import pytest

from app import (
    audit_data,
    device_data,
    inventory,
    inventory_cache,
    snapshot_cache,
    snapshot_store,
)
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

ALL = set(device_data.DATA_KEYS)


class GuardClient(FMGClient):
    """Fails the test on any proxy (per-device) read; counts them."""

    def __init__(self, synth):
        super().__init__(host="fmg.example", token="t")
        self.proxy_reads = 0

        def post(body, timeout=None):
            if body["params"][0].get("url") == "/sys/proxy/json":
                self.proxy_reads += 1
                raise AssertionError("unexpected live device read")
            return synth.post(body, timeout)

        self._post = post


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 7)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_MAX_AGE_HOURS", 0)
    snapshot_cache._revision_flags.clear()
    audit_data.reset_counters()
    synth = SyntheticFMG(adoms=1, devices=6, seed=3)
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    name = min(d["name"] for d in real.get_devices(adom))
    snapshot_cache.capture_device(real, adom, name)
    return synth, real, adom, name


def _old(hours):
    return (datetime.now(UTC) - timedelta(hours=hours)).isoformat()


def test_flag_off_is_live_and_never_touches_the_store(monkeypatch, rig):
    synth, real, adom, name = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)

    def nope(*a, **k):
        raise AssertionError("snapshot store touched with the flag off")

    monkeypatch.setattr(snapshot_store, "get_keys", nope)
    out = audit_data.device_data(real, adom, name, {"ntp", "dns"})
    assert out.source == "live" and out.data == device_data.fetch_device_data(
        real, adom, name, {"ntp", "dns"}
    )
    assert audit_data.counters() == {
        "hits": 0,
        "fallbacks": 0,
        "store_errors": 0,
        "live_requests": 0,
    }


def test_live_true_bypasses_a_fresh_snapshot_and_writes_nothing(rig):
    synth, real, adom, name = rig
    snapshot_store.put_keys(adom, name, {"ntp": {"marker": "stored"}})
    out = audit_data.device_data(real, adom, name, {"ntp"}, live=True)
    assert out.source == "live" and out.data["ntp"] != {"marker": "stored"}
    assert snapshot_store.get_keys(adom, name, {"ntp"})["ntp"]["value"] == {
        "marker": "stored"
    }
    assert audit_data.counters()["live_requests"] == 1


def test_fresh_snapshot_zero_fmg_calls_and_provenance(rig):
    synth, real, adom, name = rig
    guard = GuardClient(synth)
    out = audit_data.device_data(guard, adom, name, ALL)
    assert guard.proxy_reads == 0 and out.source == "snapshot"
    assert out.collected_at and set(out.per_key) == ALL
    assert all(v["source"] == "snapshot" for v in out.per_key.values())
    assert audit_data.counters()["hits"] == len(ALL)


def test_data_equals_a_live_fetch_for_the_same_device(rig):
    synth, real, adom, name = rig
    out = audit_data.device_data(
        GuardClient(synth), adom, name, ALL | {"device_meta"}, {"os_ver": 7}
    )
    live = device_data.fetch_device_data(
        real, adom, name, ALL | {"device_meta"}, {"os_ver": 7}
    )
    assert out.data == live


def test_stale_key_goes_live_others_stay_snapshot_source_mixed(rig):
    synth, real, adom, name = rig
    snapshot_store._set_collected_at_for_test(adom, name, "ntp", _old(200))  # > 8 days
    out = audit_data.device_data(real, adom, name, {"ntp", "dns"})
    assert out.source == "mixed"
    assert (
        out.per_key["ntp"]["source"] == "live"
        and out.per_key["dns"]["source"] == "snapshot"
    )
    assert audit_data.counters()["fallbacks"] == 1


def test_missing_device_goes_live_for_every_key(rig):
    synth, real, adom, _ = rig
    other = sorted(d["name"] for d in real.get_devices(adom))[1]
    out = audit_data.device_data(real, adom, other, {"ntp", "dns"})
    assert out.source == "live" and audit_data.counters()["fallbacks"] == 2


def test_unreachable_status_with_data_within_max_age_is_served_with_its_own_timestamp(
    rig,
):
    synth, real, adom, name = rig
    snapshot_store.mark_failed(adom, name, ["ntp"], "No tunnel 80")
    ts = snapshot_store.get_keys(adom, name, {"ntp"})["ntp"]["collected_at"]
    out = audit_data.device_data(GuardClient(synth), adom, name, {"ntp"})
    assert out.source == "snapshot" and out.per_key["ntp"]["collected_at"] == ts


def test_store_error_goes_live(monkeypatch, rig):
    synth, real, adom, name = rig

    def broken(*a, **k):
        raise snapshot_store.SnapshotStoreError("io")

    monkeypatch.setattr(snapshot_store, "get_keys", broken)
    out = audit_data.device_data(real, adom, name, {"ntp"})
    assert out.source == "live" and audit_data.counters()["store_errors"] == 1


def test_collected_at_is_the_oldest_key(rig):
    synth, real, adom, name = rig
    snapshot_store._set_collected_at_for_test(adom, name, "dns", _old(30))
    out = audit_data.device_data(
        GuardClient(synth), adom, name, {"ntp", "dns", "admins"}
    )
    assert (
        out.collected_at
        == out.per_key["dns"]["collected_at"]
        < out.per_key["ntp"]["collected_at"]
    )


def test_device_meta_is_never_snapshotted(rig):
    synth, real, adom, name = rig
    out = audit_data.device_data(
        GuardClient(synth), adom, name, {"device_meta"}, {"os_ver": 7}
    )
    assert out.data == {"device_meta": {"os_ver": 7}}
    assert out.source == "inventory" and out.collected_at is None and out.per_key == {}
    out2 = audit_data.device_data(
        GuardClient(synth),
        adom,
        name,
        {"device_meta"},
        None,
        device_meta_as_of="2026-11-11T00:00:00+00:00",
    )
    assert out2.collected_at == "2026-11-11T00:00:00+00:00"


def test_inventory_device_lookup_from_store_and_live(monkeypatch, rig):
    synth, real, adom, name = rig
    live = inventory.device(real, adom, name)
    assert live and live["name"] == name
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    inventory_cache.refresh_once(real)

    class NoDvmdb(FMGClient):
        def __init__(self):
            super().__init__(host="fmg.example", token="t")

            def post(body, timeout=None):
                raise AssertionError("unexpected FMG call")

            self._post = post

    assert inventory.device(NoDvmdb(), adom, name)["name"] == name
    assert inventory.device(NoDvmdb(), adom, "nope") == {}
