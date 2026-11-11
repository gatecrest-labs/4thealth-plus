"""Device snapshot store (Phase 5, Task 2)."""

import json
import threading
import zlib
from datetime import UTC, datetime, timedelta

import pytest

from app import device_data
from app import snapshot_store as ss
from app.config import Config


def _values(tag="a"):
    return {
        key: ({"k": f"{tag}-{key}"} if empty is dict else [{"k": f"{tag}-{key}"}])
        for key, (_g, empty) in device_data.DATA_KEYS.items()
    }


def test_round_trip_of_all_keys():
    ss.put_keys("A", "fw1", _values())
    got = ss.get_keys("A", "fw1", set(device_data.DATA_KEYS))
    assert set(got) == set(device_data.DATA_KEYS)
    assert got["ntp"]["value"] == {"k": "a-ntp"} and got["interfaces"]["value"] == [
        {"k": "a-interfaces"}
    ]
    assert got["ntp"]["status"] == "ok" and 0 <= got["ntp"]["age_seconds"] < 5


def test_get_keys_returns_only_requested_and_only_collected_keys():
    ss.put_keys("A", "fw1", {"ntp": {"a": 1}})
    assert set(ss.get_keys("A", "fw1", {"ntp", "dns"})) == {"ntp"}
    assert ss.get_keys("A", "nope", {"ntp"}) == {}


def test_collected_empty_is_distinct_from_never_collected():
    ss.put_keys("A", "fw1", {"ha_status": {}, "syslog": []})
    got = ss.get_keys("A", "fw1", {"ha_status", "syslog", "dns"})
    assert (
        got["ha_status"]["value"] == {}
        and got["syslog"]["value"] == []
        and "dns" not in got
    )


def test_put_replaces_a_key():
    ss.put_keys("A", "fw1", {"ntp": {"v": 1}})
    ss.put_keys("A", "fw1", {"ntp": {"v": 2}})
    assert ss.get_keys("A", "fw1", {"ntp"})["ntp"]["value"] == {"v": 2}


def test_failed_keys_keep_previous_blob_and_flag_status():
    ss.put_keys("A", "fw1", {"ntp": {"v": 1}, "dns": {"v": 1}})
    ss.mark_failed("A", "fw1", ["ntp"], "No tunnel 80")
    got = ss.get_keys("A", "fw1", {"ntp", "dns"})
    assert got["ntp"]["value"] == {"v": 1} and got["ntp"]["status"] == "unreachable"
    assert got["dns"]["status"] == "ok"


def test_failure_on_a_never_collected_key_stays_invisible_to_get_keys():
    ss.mark_failed("A", "fw1", ["ntp"], "No tunnel 80")
    assert ss.get_keys("A", "fw1", {"ntp"}) == {}
    row = ss.device_meta_rows("A")[0]
    assert row["device"] == "fw1" and row["has_unreachable"] is True


def test_backoff_doubles_then_caps_at_24h_and_resets_on_ok():
    assert [ss.backoff_seconds(n) for n in range(1, 10)] == [
        900,
        1800,
        3600,
        7200,
        14400,
        28800,
        57600,
        86400,
        86400,
    ]
    for n in range(1, 4):
        ss.mark_failed("A", "fw1", ["ntp"], f"fail {n}")
    row = ss.device_meta_rows("A")[0]
    assert row["fail_count"] == 3
    wait = (
        datetime.fromisoformat(row["next_attempt_at"])
        - datetime.fromisoformat(row["last_attempt_at"])
    ).total_seconds()
    assert 3590 <= wait <= 3610
    ss.mark_ok("A", "fw1")
    row = ss.device_meta_rows("A")[0]
    assert (
        row["fail_count"] == 0 and row["next_attempt_at"] is None and row["last_ok_at"]
    )


def test_put_is_atomic_for_readers():
    ss.put_keys("A", "fw1", {k: {"gen": 0} for k in ("ntp", "dns", "log_disk")})
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            got = ss.get_keys("A", "fw1", {"ntp", "dns", "log_disk"})
            gens = {v["value"]["gen"] for v in got.values()}
            if len(gens) > 1:
                bad.append(gens)

    t = threading.Thread(target=reader)
    t.start()
    try:
        for gen in range(1, 25):
            ss.put_keys(
                "A", "fw1", {k: {"gen": gen} for k in ("ntp", "dns", "log_disk")}
            )
    finally:
        stop.set()
        t.join()
    assert bad == []


def test_delete_missing_devices_and_adoms():
    ss.put_keys("A", "keep", {"ntp": {}})
    ss.put_keys("A", "drop", {"ntp": {}})
    ss.mark_failed("A", "ghost", ["ntp"], "x")
    ss.put_keys("B", "other", {"ntp": {}})
    assert ss.delete_missing_devices("A", {"keep"}) == 2
    assert {r["device"] for r in ss.device_meta_rows("A")} == {"keep"}
    ss.delete_missing_adoms({"A"})
    assert ss.device_meta_rows("B") == [] and ss.device_meta_rows("A")


def test_device_meta_rows_reports_oldest_key_without_decompressing(monkeypatch):
    ss.put_keys("A", "fw1", {"ntp": {"v": 1}, "dns": {"v": 1}})
    ss._set_collected_at_for_test(
        "A", "fw1", "ntp", (datetime.now(UTC) - timedelta(hours=30)).isoformat()
    )
    monkeypatch.setattr(
        zlib,
        "decompress",
        lambda *_: (_ for _ in ()).throw(AssertionError("blob loaded")),
    )
    row = ss.device_meta_rows("A")[0]
    assert (
        row["keys"] == 2
        and row["oldest_key_at"] < (datetime.now(UTC) - timedelta(hours=29)).isoformat()
    )


def test_reads_do_not_wait_for_the_write_lock():
    from app import collector_store

    ss.put_keys("A", "fw1", {"ntp": {"v": 1}})
    done = threading.Event()

    def reader():
        ss.get_keys("A", "fw1", {"ntp"})
        ss.device_meta_rows("A")
        done.set()

    with collector_store._lock:
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        assert done.wait(2.0)
    t.join()


def test_unreadable_store_raises(monkeypatch):
    import sqlite3

    from app import collector_store

    def boom():
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(collector_store, "_connect", boom)
    with pytest.raises(ss.SnapshotStoreError):
        ss.get_keys("A", "fw1", {"ntp"})


def test_blob_size_for_a_realistic_device_is_small():
    ifaces = [
        {
            "name": f"port{i}",
            "vdom": "root",
            "ip": f"10.0.{i}.1 255.255.255.0",
            "allowaccess": "ping https ssh snmp",
            "type": "physical",
            "status": "up",
            "mtu": 1500,
            "alias": "",
            "role": "lan",
        }
        for i in range(40)
    ]
    admins = [
        {
            "name": f"admin{i}",
            "trusthost1": "10.0.0.0 255.0.0.0",
            "accprofile": "super_admin",
            "two-factor": "fortitoken",
        }
        for i in range(8)
    ]
    values = _values()
    values["interfaces"], values["admins"] = ifaces, admins
    ss.put_keys("A", "fw1", values)
    with ss._conn() as conn:
        total = conn.execute(
            "SELECT sum(length(blob)) FROM device_snapshot"
        ).fetchone()[0]
    assert total < 8 * 1024
    assert len(json.dumps(values)) > total


def test_max_age_default_derives_from_window(monkeypatch):
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 7)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_MAX_AGE_HOURS", 0)
    assert ss.max_age_seconds() == (7 * 24 + 24) * 3600
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 1)
    assert ss.max_age_seconds() == 48 * 3600
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_MAX_AGE_HOURS", 24)
    assert ss.max_age_seconds() == 24 * 3600


def test_coexists_with_other_store_tables():
    from app import inventory_store, policy_store

    inventory_store.replace_adom(
        "A", [{"name": "d"}], None, datetime.now(UTC).isoformat()
    )
    policy_store.put_policies("A", "p", [], "f")
    ss.put_keys("A", "fw1", {"ntp": {}})
    assert (
        inventory_store.read_devices("A")
        and policy_store.get_policies("A", "p")
        and ss.get_keys("A", "fw1", {"ntp"})
    )
