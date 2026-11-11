"""Inventory store tables (Phase 2, Task 2). tests/conftest.py gives each test its own DB."""

import threading
from datetime import UTC, datetime, timedelta

import pytest

from app import inventory_store as inv


def _devs(prefix, n):
    return [
        {"name": f"{prefix}{i}", "conf_status": 1, "vdom": [{"name": "root"}]}
        for i in range(n)
    ]


def _now():
    return datetime.now(UTC).isoformat()


def test_round_trip_devices_and_pkg_rows():
    pkg = [{"dev": "a0", "vdom": "root", "pkg": "p", "status": "installed"}]
    inv.replace_adom("A", _devs("a", 3), pkg, _now())
    got = inv.read_devices("A")
    assert [d["name"] for d in got] == ["a0", "a1", "a2"]
    assert got[0]["vdom"] == [{"name": "root"}]
    assert inv.read_pkg_status("A") == pkg
    meta = inv.read_meta("A")
    assert meta["status"] == "ok" and meta["device_count"] == 3


def test_read_returns_none_when_never_collected():
    assert inv.read_devices("nope") is None
    assert inv.read_meta("nope") is None
    assert inv.read_adom_list() is None
    assert inv.adom_list_age_seconds() is None
    assert inv.read_pkg_status("nope") == []


def test_deleted_device_disappears_on_replace():
    inv.replace_adom("A", _devs("a", 3), None, _now())
    inv.replace_adom("A", _devs("a", 2), None, _now())
    assert [d["name"] for d in inv.read_devices("A")] == ["a0", "a1"]


def test_pkg_rows_none_keeps_existing_pkg_rows():
    pkg = [{"dev": "a0", "vdom": "root", "pkg": "p", "status": "modified"}]
    inv.replace_adom("A", _devs("a", 1), pkg, _now())
    inv.replace_adom("A", _devs("a", 1), None, _now())
    assert inv.read_pkg_status("A") == pkg
    inv.replace_adom("A", _devs("a", 1), [], _now())
    assert inv.read_pkg_status("A") == []


def test_crash_mid_replace_keeps_previous_rows():
    inv.replace_adom("A", _devs("a", 3), None, _now())
    bad = _devs("b", 3) + [{"name": "boom", "x": {1, 2}}]  # a set is not JSON
    with pytest.raises(TypeError):
        inv.replace_adom("A", bad, None, _now())
    assert [d["name"] for d in inv.read_devices("A")] == ["a0", "a1", "a2"]
    assert inv.read_meta("A")["device_count"] == 3


def test_replace_is_atomic_for_readers():
    inv.replace_adom("A", _devs("g0-", 300), None, _now())
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            names = {d["name"].split("-")[0] for d in inv.read_devices("A")}
            sizes = len(inv.read_devices("A"))
            if len(names) != 1 or sizes not in (300, 301):
                bad.append((names, sizes))

    t = threading.Thread(target=reader)
    t.start()
    try:
        for gen in range(1, 15):
            inv.replace_adom("A", _devs(f"g{gen}-", 300 + gen % 2), None, _now())
    finally:
        stop.set()
        t.join()
    assert bad == []


def test_delete_missing_adoms_removes_all_their_rows():
    inv.replace_adom(
        "A",
        _devs("a", 2),
        [{"dev": "a0", "vdom": "root", "pkg": "p", "status": "installed"}],
        _now(),
    )
    inv.replace_adom("B", _devs("b", 2), None, _now())
    inv.delete_missing_adoms({"A"})
    assert inv.read_devices("B") is None
    assert inv.read_meta("B") is None
    assert inv.read_devices("A") is not None


def test_mark_adom_error_keeps_rows_and_sets_status():
    inv.replace_adom("A", _devs("a", 2), None, _now())
    inv.mark_adom_error("A", "boom")
    meta = inv.read_meta("A")
    assert meta["status"] == "error" and meta["error"] == "boom"
    assert meta["device_count"] == 2
    assert len(inv.read_devices("A")) == 2


def test_mark_error_on_never_collected_adom_is_still_none_for_devices():
    inv.mark_adom_error("Z", "boom")
    assert inv.read_devices("Z") is None
    assert inv.read_meta("Z")["status"] == "error"


def test_age_seconds_computed():
    old = (datetime.now(UTC) - timedelta(seconds=120)).isoformat()
    inv.replace_adom("A", _devs("a", 1), None, old)
    assert 115 <= inv.read_meta("A")["age_seconds"] <= 130
    assert {m["adom"] for m in inv.read_meta()} == {"A"}


def test_adom_list_round_trip_and_order():
    inv.write_adom_list([{"name": "z"}, {"name": "a"}])
    assert [a["name"] for a in inv.read_adom_list()] == ["z", "a"]
    assert inv.adom_list_age_seconds() < 5


def test_request_refresh_throttles_and_pop_clears():
    assert inv.request_refresh(60) is True
    assert inv.request_refresh(60) is False  # throttled
    assert inv.pop_refresh_request() is True
    assert inv.pop_refresh_request() is False
    assert inv.request_refresh(60) is False  # still inside the interval after pop
    assert inv.request_refresh(0) is True


def test_unreadable_store_raises_store_error_not_empty(monkeypatch):
    import sqlite3

    from app import collector_store

    def boom():
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(collector_store, "_connect", boom)
    with pytest.raises(inv.InventoryStoreError):
        inv.read_devices("A")
    with pytest.raises(inv.InventoryStoreError):
        inv.read_meta()


def test_has_pkg_status_distinguishes_never_collected_from_empty():
    inv.replace_adom("A", _devs("a", 1), None, _now())
    assert inv.has_pkg_status("A") is False
    inv.replace_adom("A", _devs("a", 1), [], _now())  # collected, nothing assigned
    assert inv.has_pkg_status("A") is True
    inv.delete_missing_adoms(set())
    assert inv.has_pkg_status("A") is False


def test_pkg_status_ages_track_the_package_collection_time_not_the_meta_time():
    old = (datetime.now(UTC) - timedelta(seconds=500)).isoformat()
    inv.replace_adom("A", _devs("a", 1), [], old)
    inv.replace_adom(
        "A", _devs("a", 1), None, _now()
    )  # devices refreshed, packages not
    assert inv.read_meta("A")["age_seconds"] < 5
    assert 495 <= inv.pkg_status_ages()["A"] <= 510


def test_reads_do_not_wait_for_the_process_write_lock():
    from app import collector_store

    inv.replace_adom("A", _devs("a", 3), None, _now())
    done = threading.Event()

    def reader():
        inv.read_devices("A")
        inv.read_meta("A")
        done.set()

    with collector_store._lock:  # a long write elsewhere in this process
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        assert done.wait(2.0)
    t.join()


def test_schema_is_created_once_per_database(monkeypatch):
    calls = []
    real = inv._create_schema
    monkeypatch.setattr(
        inv, "_create_schema", lambda conn: (calls.append(1), real(conn))
    )
    inv.replace_adom("A", _devs("a", 1), None, _now())
    inv.read_devices("A")
    inv.read_meta("A")
    inv.read_pkg_status("A")
    assert len(calls) == 1
