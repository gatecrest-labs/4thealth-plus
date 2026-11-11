"""Collector device snapshot job (Phase 5, Task 3)."""
# ruff: noqa: RUF059

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from app import boot_warmup, device_data, snapshot_cache, snapshot_store
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG


def _make(devices=12, **kw):
    synth = SyntheticFMG(adoms=1, devices=devices, seed=5, **kw)
    client = FMGClient(host="fmg.example", token="t")
    client._post = synth.post
    adom = next(
        a["name"]
        for a in client.get_adoms()
        if not a["name"].lower().startswith("forti")
    )
    return synth, client, adom


@pytest.fixture(autouse=True)
def _cfg(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 7)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_BATCH_MINUTES", 10)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WORKERS", 2)
    snapshot_cache._revision_flags.clear()


def _captured(adom):
    return {r["device"] for r in snapshot_store.device_meta_rows(adom) if r["keys"] > 0}


def test_batch_size_formula_and_minimum_of_one(monkeypatch):
    assert snapshot_cache.batch_size(1000) == 1  # 1000 / (7 d x 144 batches/day)
    assert snapshot_cache.batch_size(3) == 1
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 1)
    assert snapshot_cache.batch_size(1000) == 7
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_BATCH_MINUTES", 1440)
    assert snapshot_cache.batch_size(1000) == 1000
    assert snapshot_cache.batch_size(0) == 1


def test_never_captured_devices_ramp_up_within_a_day(monkeypatch):
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 7)
    # 1,000 uncaptured devices with 10-minute batches: all captured within 24 h = 144 batches
    assert snapshot_cache.batch_size(1000, never_captured=1000) == 7
    assert snapshot_cache.batch_size(1000, never_captured=0) == 1


def test_first_batches_cover_every_device_once(monkeypatch):
    synth, client, adom = _make(devices=15)
    seen = []
    for tick in range(1, 16):
        result = snapshot_cache.refresh_batch(client)
        assert result["captured"] == 1 and result["failed"] == 0
        seen.append(_captured(adom))
        assert len(seen[-1]) == tick  # one new device per tick, none twice
    assert len(_captured(adom)) == 15


def test_captures_all_proxy_keys_with_provenance(monkeypatch):
    synth, client, adom = _make(devices=3)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_BATCH_MINUTES", 1440)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 1)
    snapshot_cache.refresh_batch(client)
    name = next(iter(_captured(adom)))
    got = snapshot_store.get_keys(adom, name, set(device_data.DATA_KEYS))
    assert set(got) == set(device_data.DATA_KEYS)
    assert got["ntp"]["value"] and all(v["status"] == "ok" for v in got.values())


def test_priority_never_then_newer_revision_then_oldest(monkeypatch):
    synth, client, adom = _make(devices=4)
    names = sorted(d["name"] for d in client.get_devices(adom))
    a, b, c, d = names
    # b, c, d captured with different ages; a never captured
    for dev in (b, c, d):
        snapshot_store.put_keys(adom, dev, {"ntp": {"v": 1}})
        snapshot_store.mark_ok(adom, dev)
    now = datetime.now(UTC)
    for dev, hours in ((b, 10), (c, 100), (d, 50)):
        snapshot_store._set_collected_at_for_test(
            adom, dev, "ntp", (now - timedelta(hours=hours)).isoformat()
        )
    snapshot_cache._revision_flags.add((adom, b))
    order = []
    for _ in range(4):
        before = {
            r["device"]: r["last_ok_at"] for r in snapshot_store.device_meta_rows(adom)
        }
        snapshot_cache.refresh_batch(client)
        after = {
            r["device"]: r["last_ok_at"] for r in snapshot_store.device_meta_rows(adom)
        }
        order.append(next(dv for dv in names if after[dv] != before.get(dv)))
    assert order[0] == a  # never captured first
    assert order[1] == b  # then the device whose config revision is newer
    assert order[2:] == [c, d]  # then oldest first (c is 100 h old, d 50 h)


def test_unreachable_device_keeps_old_snapshot_backs_off_and_is_retried_when_due():
    synth, client, adom = _make(devices=1)
    name = next(d["name"] for d in client.get_devices(adom))
    snapshot_cache.capture_device(client, adom, name)
    before = snapshot_store.get_keys(adom, name, {"ntp"})["ntp"]["value"]
    synth.down_devices.add(name)
    outcome = snapshot_cache.capture_device(client, adom, name)
    assert outcome["failed_keys"] and not outcome["ok_keys"]
    got = snapshot_store.get_keys(adom, name, {"ntp"})["ntp"]
    assert got["value"] == before and got["status"] == "unreachable"
    row = snapshot_store.device_meta_rows(adom)[0]
    assert row["fail_count"] == 1 and row["next_attempt_at"]
    # not retried while in backoff
    synth.proxy_calls.clear()
    result = snapshot_cache.refresh_batch(client)
    assert (
        result["skipped_backoff"] == 1
        and result["selected"] == 0
        and not synth.proxy_calls
    )
    # retried once due
    later = datetime.now(UTC) + timedelta(minutes=16)
    synth.down_devices.clear()
    result = snapshot_cache.refresh_batch(client, now=later)
    assert result["captured"] == 1
    row = snapshot_store.device_meta_rows(adom)[0]
    assert (
        row["fail_count"] == 0
        and snapshot_store.get_keys(adom, name, {"ntp"})["ntp"]["status"] == "ok"
    )


def test_partial_key_failure_keeps_the_other_keys():
    synth, client, adom = _make(devices=1)
    name = next(d["name"] for d in client.get_devices(adom))

    def post(body, timeout=None):
        if (
            body["params"][0].get("url") == "/sys/proxy/json"
            and "system/ntp" in body["params"][0]["data"]["resource"]
        ):
            return {"result": [{"status": {"code": -11, "message": "no permission"}}]}
        return synth.post(body, timeout)

    client._post = post
    outcome = snapshot_cache.capture_device(client, adom, name)
    assert outcome["failed_keys"] == ["ntp"] and "dns" in outcome["ok_keys"]
    got = snapshot_store.get_keys(adom, name, set(device_data.DATA_KEYS))
    assert "ntp" not in got and got["dns"]["status"] == "ok"
    assert snapshot_store.device_meta_rows(adom)[0]["fail_count"] == 1


def test_404_ha_answer_is_stored_as_empty_not_a_failure():
    synth, client, adom = _make(devices=20)
    non_ha = next(d["name"] for d in client.get_devices(adom) if not d.get("ha_mode"))
    outcome = snapshot_cache.capture_device(client, adom, non_ha)
    assert outcome["failed_keys"] == []
    got = snapshot_store.get_keys(adom, non_ha, {"ha_status"})["ha_status"]
    assert got["status"] == "ok" and got["value"] in ({}, [])
    assert snapshot_store.device_meta_rows(adom)[0]["fail_count"] == 0


def test_removed_device_is_deleted():
    synth, client, adom = _make(devices=3)
    names = sorted(d["name"] for d in client.get_devices(adom))
    for n in names:
        snapshot_cache.capture_device(client, adom, n)
    real = client.get_devices
    client.get_devices = lambda a: [d for d in real(a) if d["name"] != names[0]]
    snapshot_cache.refresh_batch(client)
    assert names[0] not in {r["device"] for r in snapshot_store.device_meta_rows(adom)}


def test_workers_cap_respected(monkeypatch):
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WORKERS", 2)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_BATCH_MINUTES", 1440)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 1)
    synth, client, adom = _make(devices=10)
    lock = threading.Lock()
    state = {"now": 0, "peak": 0}
    real = client.get_device_ntp

    def slow(a, d):
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.03)
        try:
            return real(a, d)
        finally:
            with lock:
                state["now"] -= 1

    client.get_device_ntp = slow
    result = snapshot_cache.refresh_batch(client)
    assert result["captured"] == 10 and 1 <= state["peak"] <= 2


def test_single_flight(monkeypatch):
    synth, client, adom = _make(devices=2)
    gate, entered = threading.Event(), threading.Event()
    real = client.get_device_ntp

    def blocking(a, d):
        entered.set()
        gate.wait(2)
        return real(a, d)

    client.get_device_ntp = blocking
    out = []
    t = threading.Thread(
        target=lambda: out.append(snapshot_cache.refresh_batch(client))
    )
    t.start()
    entered.wait(2)
    assert snapshot_cache.refresh_batch(client) == {"skipped": True}
    gate.set()
    t.join()
    assert "skipped" not in out[0]


def test_revision_check_makes_one_call_per_adom_and_flags_changed_devices():
    synth, client, adom = _make(devices=4)
    names = sorted(d["name"] for d in client.get_devices(adom))
    for n in names:
        snapshot_cache.capture_device(client, adom, n)
    snapshot_store._set_last_ok_for_test(
        adom, names[0], "2026-01-01T00:00:00+00:00"
    )  # captured before its revision
    synth.calls.clear()
    result = snapshot_cache.refresh_revisions(client)
    assert sum(n for k, n in synth.calls.items() if "/revision" in k) == 1
    assert result["flagged"] == 1 and snapshot_cache._revision_flags == {
        (adom, names[0])
    }


def test_calls_per_captured_device_stay_modest():
    synth, client, adom = _make(devices=6)
    for d in client.get_devices(adom):
        snapshot_cache.capture_device(client, adom, d["name"])
    assert sum(synth.proxy_calls.values()) / 6 <= 20


def test_scheduler_not_registered_when_flag_off(monkeypatch):
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)
    assert snapshot_cache.init_scheduler(object()) is False


def test_registered_jobs_and_boot_priority(monkeypatch):
    added, deferred = [], []

    class FakeSched:
        def add_job(self, **kw):
            added.append(kw["id"])

        def start(self):
            pass

    monkeypatch.setattr(snapshot_cache, "_make_scheduler", lambda: FakeSched())
    monkeypatch.setattr(
        boot_warmup,
        "defer",
        lambda name, fn, priority: deferred.append((name, priority)),
    )
    assert snapshot_cache.init_scheduler(object()) is True
    assert set(added) == {"snapshot_batch", "snapshot_revisions"}
    assert deferred == [("snapshot_cache", 3)]


def test_one_failing_adom_does_not_stop_captures_in_other_adoms(monkeypatch):
    from app import inventory, snapshot_cache as sc
    from app.fmg_client import FMGError

    monkeypatch.setattr(inventory, "adoms", lambda c: [{"name": "Good"}, {"name": "Bad"}])

    def devices(c, adom):
        if adom == "Bad":
            raise FMGError("denied", code=-11)
        return [{"name": "fw1"}]

    monkeypatch.setattr(inventory, "devices", devices)
    fleet, failed = sc._fleet_checked(None)
    assert fleet == {"Good": ["fw1"]} and failed == {"Bad"}
    assert sc._fleet(None) == {"Good": ["fw1"]}
