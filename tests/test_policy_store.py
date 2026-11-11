"""Policy and object store tables (Phase 4, Task 2)."""

import json
import threading
import zlib
from datetime import UTC, datetime, timedelta

import pytest

from app import policy_store as ps
from app.config import Config
from app.synthetic_fmg import SyntheticFMG


def _rules(prefix, n):
    return [
        {
            "policyid": i,
            "name": f"{prefix}-{i}",
            "srcaddr": ["a"],
            "dstaddr": ["b"],
            "service": ["HTTPS"],
        }
        for i in range(n)
    ]


def test_packages_round_trip():
    entries = [
        {
            "name": "p",
            "path": "F/p",
            "scope member": [{"name": "fw", "vdom": "root"}],
            "package settings": {"x": 1},
        }
    ]
    assert ps.get_packages("A") is None
    ps.put_packages("A", entries)
    got = ps.get_packages("A")
    assert got["entries"] == entries and 0 <= got["age_seconds"] < 5


def test_policies_round_trip_and_replace():
    ps.put_policies("A", "p", _rules("r", 3), "f1")
    got = ps.get_policies("A", "p")
    assert got["policies"] == _rules("r", 3) and got["fingerprint"] == "f1"
    assert got["policy_count"] == 3 and got["status"] == "ok" and got["error"] is None
    ps.put_policies("A", "p", _rules("s", 2), "f2")
    got = ps.get_policies("A", "p")
    assert got["policies"] == _rules("s", 2) and got["policy_count"] == 2


def test_never_collected_is_none_but_collected_empty_is_empty():
    assert ps.get_policies("A", "none") is None
    ps.put_policies("A", "empty", [], "f")
    assert ps.get_policies("A", "empty")["policies"] == []


def test_error_keeps_previous_blob_and_flags_status():
    ps.put_policies("A", "p", _rules("r", 3), "f1")
    ps.mark_policies_error("A", "p", "fmg down")
    got = ps.get_policies("A", "p")
    assert got["policies"] == _rules("r", 3)
    assert got["status"] == "error" and got["error"] == "fmg down"
    ps.put_policies("A", "p", _rules("r", 3), "f1")  # a later good fetch clears it
    assert ps.get_policies("A", "p")["status"] == "ok"


def test_error_on_never_collected_row_still_reads_as_none():
    ps.mark_policies_error("A", "ghost", "boom")
    assert ps.get_policies("A", "ghost") is None
    assert {m["pkg"]: m["status"] for m in ps.package_meta("A")}["ghost"] == "error"


def test_touch_resets_age_keeps_content():
    ps.put_policies("A", "p", _rules("r", 2), "f1")
    ps._set_fetched_at_for_test(
        "policy_pkg",
        ("A", "p"),
        (datetime.now(UTC) - timedelta(seconds=9000)).isoformat(),
    )
    assert ps.get_policies("A", "p")["age_seconds"] > 8900
    ps.touch_policies("A", "p")
    got = ps.get_policies("A", "p")
    assert got["age_seconds"] < 5 and got["policies"] == _rules("r", 2)


def test_blocks_and_objects_round_trip():
    ps.put_block("A", "blk", _rules("b", 2), "fb")
    assert ps.get_block("A", "blk")["policies"] == _rules("b", 2)
    ps.put_objects("A", "address", [{"name": "x"}], "fo")
    ps.put_objects("global", "address", [{"name": "g"}], "fg")
    assert ps.get_objects("A", "address")["objects"] == [{"name": "x"}]
    assert ps.get_objects("global", "address")["objects"] == [{"name": "g"}]
    assert ps.get_objects("A", "vip") is None
    ps.mark_objects_error("A", "address", "x")
    assert ps.get_objects("A", "address")["status"] == "error"


def test_put_replaces_atomically_for_readers():
    ps.put_policies("A", "p", _rules("g0", 200), "f")
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            got = ps.get_policies("A", "p")
            names = {r["name"].split("-")[0] for r in got["policies"]}
            if len(names) != 1:
                bad.append(names)

    t = threading.Thread(target=reader)
    t.start()
    try:
        for gen in range(1, 12):
            ps.put_policies("A", "p", _rules(f"g{gen}", 200), f"f{gen}")
    finally:
        stop.set()
        t.join()
    assert bad == []


def test_delete_missing_packages_and_blocks():
    for p in ("keep", "drop"):
        ps.put_policies("A", p, [], "f")
        ps.put_block("A", p, [], "f")
    ps.put_policies("B", "other", [], "f")
    assert ps.delete_missing_packages("A", {"keep"}) == 1
    assert ps.delete_missing_blocks("A", {"keep"}) == 1
    assert (
        ps.get_policies("A", "drop") is None
        and ps.get_policies("A", "keep") is not None
    )
    assert (
        ps.get_block("A", "drop") is None and ps.get_policies("B", "other") is not None
    )


def test_delete_missing_adoms_removes_everything_but_global_and_kept():
    ps.put_packages("A", [{"name": "p", "path": "p"}])
    ps.put_policies("A", "p", [], "f")
    ps.put_objects("A", "address", [], "f")
    ps.put_objects("global", "address", [], "f")
    ps.put_packages("B", [{"name": "p", "path": "p"}])
    ps.delete_missing_adoms({"B"})
    assert ps.get_packages("A") is None and ps.get_policies("A", "p") is None
    assert ps.get_objects("A", "address") is None
    assert (
        ps.get_objects("global", "address") is not None
        and ps.get_packages("B") is not None
    )


def test_package_meta_does_not_load_blobs(monkeypatch):
    ps.put_policies("A", "p", _rules("r", 50), "f")
    monkeypatch.setattr(
        zlib,
        "decompress",
        lambda *_: (_ for _ in ()).throw(AssertionError("blob loaded")),
    )
    meta = ps.package_meta("A")
    assert (
        meta[0]["pkg"] == "p"
        and meta[0]["policy_count"] == 50
        and meta[0]["status"] == "ok"
    )


def test_reads_do_not_wait_for_write_lock():
    from app import collector_store

    ps.put_policies("A", "p", _rules("r", 3), "f")
    done = threading.Event()

    def reader():
        ps.get_policies("A", "p")
        ps.package_meta("A")
        done.set()

    with collector_store._lock:
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        assert done.wait(2.0)
    t.join()


def test_refresh_request_throttle_per_package_and_pop_limit():
    assert ps.request_package_refresh("A", "p1", 30) is True
    assert ps.request_package_refresh("A", "p1", 30) is False  # throttled
    assert ps.request_package_refresh("A", "p2", 30) is True  # independent
    assert ps.request_package_refresh("A", "p3", 30) is True
    first = ps.pop_refresh_requests(2)
    assert len(first) == 2
    rest = ps.pop_refresh_requests(10)
    assert len(rest) == 1
    assert {tuple(x) for x in first + rest} == {("A", "p1"), ("A", "p2"), ("A", "p3")}
    assert ps.pop_refresh_requests(10) == []
    assert (
        ps.request_package_refresh("A", "p1", 30) is False
    )  # still inside the interval
    assert ps.request_package_refresh("A", "p1", 0) is True


def test_unreadable_store_raises_policy_store_error(monkeypatch):
    import sqlite3

    from app import collector_store

    def boom():
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(collector_store, "_connect", boom)
    with pytest.raises(ps.PolicyStoreError):
        ps.get_policies("A", "p")


def test_five_hundred_rule_package_blob_is_compressed_below_a_quarter():
    synth = SyntheticFMG(adoms=1, devices=5, packages_per_adom=1, rules_per_package=500)
    adom = next(iter(synth._adoms))
    pkg = synth._pkg_names(adom)[0]
    rules = synth._policies(adom, pkg)
    ps.put_policies(adom, pkg, rules, "f")
    with ps._conn() as conn:
        size = conn.execute(
            "SELECT length(blob) FROM policy_pkg WHERE adom=? AND pkg=?", (adom, pkg)
        ).fetchone()[0]
    assert size < 0.25 * len(json.dumps(rules))


def test_ttl_config_falls_back_to_the_hygiene_env(monkeypatch):
    from app.config import _policy_ttl_hours

    monkeypatch.delenv("POLICY_PACKAGE_TTL_HOURS", raising=False)
    monkeypatch.delenv("HYGIENE_PACKAGE_TTL_HOURS", raising=False)
    assert _policy_ttl_hours() == 6
    monkeypatch.setenv("HYGIENE_PACKAGE_TTL_HOURS", "4")
    assert _policy_ttl_hours() == 4
    monkeypatch.setenv("POLICY_PACKAGE_TTL_HOURS", "9")
    assert _policy_ttl_hours() == 9


def test_effective_ttl_and_max_age(monkeypatch):
    monkeypatch.setattr(Config, "POLICY_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_MAX_AGE_SECS", 0)
    base = 6 * 3600.0
    vals = [ps.effective_ttl_seconds("A", f"p{i}") for i in range(500)]
    assert all(0.75 * base <= v <= 1.25 * base for v in vals)
    assert ps.max_age_seconds() == pytest.approx(2 * 1.25 * base)
    monkeypatch.setattr(Config, "POLICY_MAX_AGE_SECS", 100)
    assert ps.max_age_seconds() == 100


def test_coexists_with_inventory_and_hygiene_tables():
    from app import hygiene_pkg_store, inventory_store

    inventory_store.replace_adom(
        "A", [{"name": "d"}], None, datetime.now(UTC).isoformat()
    )
    hygiene_pkg_store.put(
        "A",
        "p",
        fingerprint="f",
        policy_count=1,
        score_findings=0,
        findings=[],
        addr_refs=[],
        svc_refs=[],
    )
    ps.put_policies("A", "p", _rules("r", 1), "f")
    assert (
        inventory_store.read_devices("A")
        and hygiene_pkg_store.get("A", "p")
        and ps.get_policies("A", "p")
    )
