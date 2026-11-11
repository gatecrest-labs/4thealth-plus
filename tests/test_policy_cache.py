"""Collector policy and object refresh (Phase 4, Task 3)."""
# ruff: noqa: RUF059, FURB192

import copy
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from app import boot_warmup, policy_cache, policy_store
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

BASE = 6 * 3600.0


def _make(adoms=2, packages=3, blocks=0, rules=10, **kw):
    synth = SyntheticFMG(
        adoms=adoms,
        devices=10,
        packages_per_adom=packages,
        rules_per_package=rules,
        blocks_per_package=blocks,
        seed=3,
        **kw,
    )
    client = FMGClient(host="fmg.example", token="t")
    client._post = synth.post
    return synth, client


@pytest.fixture(autouse=True)
def _cfg(monkeypatch):
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    monkeypatch.setattr(Config, "POLICY_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_PARALLEL_FETCH", 4)
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    policy_cache._empty_list_seen.clear()


def _adoms(client):
    return [
        a["name"]
        for a in client.get_adoms()
        if not a["name"].lower().startswith("forti")
    ]


PKG = "/pkg/{pkg}/firewall/policy"
LIST = "get /pm/pkg/adom/{adom}"


def _fetches(synth, needle=PKG):
    return sum(n for k, n in synth.calls.items() if needle in k)


def _age_all(seconds):
    for adom in ("Ent-1", "Ent-2"):
        for m in policy_store.package_meta(adom):
            policy_store._set_fetched_at_for_test(
                "policy_pkg",
                (adom, m["pkg"]),
                (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat(),
            )


def test_first_cycle_fetches_everything_once():
    synth, client = _make()
    synth.calls.clear()
    result = policy_cache.refresh_once(client)
    assert (
        result["adoms"] == 2
        and result["packages"] == 6
        and result["fetched"] == 6
        and result["failed"] == []
    )
    assert _fetches(synth, PKG) == 6  # one policy read per package
    assert _fetches(synth, LIST) == 2  # one package listing per ADOM
    for adom in _adoms(client):
        assert len(policy_store.package_meta(adom)) == 3
        assert policy_store.get_packages(adom)["entries"]


def test_second_cycle_inside_ttl_makes_only_list_calls():
    synth, client = _make()
    policy_cache.refresh_once(client)
    synth.calls.clear()
    result = policy_cache.refresh_once(client)
    assert (
        _fetches(synth, PKG) == 0 and result["reused"] == 6 and result["fetched"] == 0
    )


def test_changed_package_is_replaced_unchanged_is_touched():
    synth, client = _make()
    policy_cache.refresh_once(client)
    adom = _adoms(client)[0]
    meta = {m["pkg"]: m for m in policy_store.package_meta(adom)}
    _age_all(BASE * 1.3)
    real = synth._policies

    def changed(a, pkg):
        ps = copy.deepcopy(real(a, pkg))
        if a == adom and pkg == sorted(meta)[0]:
            ps[0]["name"] = "renamed"
        return ps

    synth._policies = changed
    result = policy_cache.refresh_once(client)
    assert result["fetched"] == 6
    after = {m["pkg"]: m for m in policy_store.package_meta(adom)}
    first = sorted(meta)[0]
    assert after[first]["fingerprint"] != meta[first]["fingerprint"]
    assert policy_store.get_policies(adom, first)["policies"][0]["name"] == "renamed"
    other = sorted(meta)[1]
    assert (
        after[other]["fingerprint"] == meta[other]["fingerprint"]
        and after[other]["age_seconds"] < 60
    )


def test_failed_package_fetch_keeps_previous_rows_and_marks_error():
    synth, client = _make()
    policy_cache.refresh_once(client)
    adom = _adoms(client)[0]
    victim = policy_store.package_meta(adom)[0]["pkg"]
    before = policy_store.get_policies(adom, victim)["policies"]
    _age_all(BASE * 1.3)
    real = client.get_policies

    def flaky(a, p):
        if (a, p) == (adom, victim):
            raise RuntimeError("fmg down")
        return real(a, p)

    client.get_policies = flaky
    result = policy_cache.refresh_once(client)
    assert result["failed"] == [f"{adom}/{victim}"]
    got = policy_store.get_policies(adom, victim)
    assert got["policies"] == before and got["status"] == "error"


def test_failed_package_list_never_deletes_cached_packages():
    synth, client = _make()
    policy_cache.refresh_once(client)
    adom = _adoms(client)[0]
    before = policy_store.get_packages(adom)["entries"]
    real = client.get_policy_packages

    def failing(a, strict=False):
        if a == adom:
            raise RuntimeError("down")
        return real(a, strict=strict)

    client.get_policy_packages = failing
    result = policy_cache.refresh_once(client)
    assert adom in "".join(result["failed"])
    assert policy_store.get_packages(adom)["entries"] == before
    assert len(policy_store.package_meta(adom)) == 3


def test_empty_package_list_needs_two_cycles_before_it_wipes_anything():
    synth, client = _make()
    policy_cache.refresh_once(client)
    adom = _adoms(client)[0]
    real = client.get_policy_packages
    client.get_policy_packages = lambda a, strict=False: (
        [] if a == adom else real(a, strict=strict)
    )
    first = policy_cache.refresh_once(client)
    assert (
        adom in "".join(first["failed"]) and len(policy_store.package_meta(adom)) == 3
    )
    policy_cache.refresh_once(
        client
    )  # confirmed on the second consecutive empty answer
    assert policy_store.package_meta(adom) == []


def test_removed_package_deleted_only_after_successful_listing():
    synth, client = _make()
    policy_cache.refresh_once(client)
    adom = _adoms(client)[0]
    dropped = policy_store.package_meta(adom)[0]["pkg"]
    real = client.get_policy_packages
    client.get_policy_packages = lambda a, strict=False: [
        p for p in real(a, strict=strict) if not (a == adom and p["path"] == dropped)
    ]
    policy_cache.refresh_once(client)
    assert dropped not in {m["pkg"] for m in policy_store.package_meta(adom)}
    assert len(policy_store.package_meta(adom)) == 2


def test_removed_adom_is_deleted():
    synth, client = _make(adoms=3)
    policy_cache.refresh_once(client)
    names = _adoms(client)
    real = client.get_adoms
    client.get_adoms = lambda: [a for a in real() if a["name"] != names[-1]]
    policy_cache.refresh_once(client)
    assert (
        policy_store.package_meta(names[-1]) == []
        and policy_store.get_packages(names[-1]) is None
    )


def test_adom_list_empty_does_not_wipe_a_populated_store():
    synth, client = _make()
    policy_cache.refresh_once(client)
    client.get_adoms = list
    with pytest.raises(RuntimeError, match="empty ADOM list"):
        policy_cache.refresh_once(client)
    assert policy_store.package_meta(_adoms(_make()[1])[0])


def test_policy_blocks_fetched_once_for_many_referencing_packages():
    synth, client = _make(packages=4, blocks=2)
    synth.calls.clear()
    policy_cache.refresh_once(client)
    adom = _adoms(client)[0]
    assert _fetches(synth, "/pblock/") == 2 * 2  # 2 blocks x 2 ADOMs, not x 4 packages
    got = policy_store.get_block(adom, "blk-0")
    assert len(got["policies"]) == 3 and got["status"] == "ok"


def test_block_failure_is_recorded_not_silent():
    synth, client = _make(packages=2, blocks=1)
    real = client.get_pblock_policies

    def failing(adom, block, strict=False):
        raise RuntimeError("block gone")

    client.get_pblock_policies = failing
    result = policy_cache.refresh_once(client)
    adom = _adoms(client)[0]
    assert any("blk-0" in f for f in result["failed"])
    assert policy_store.package_meta(adom)  # packages themselves are fine
    client.get_pblock_policies = real


def test_objects_global_once_local_per_adom():
    synth, client = _make(adoms=3)
    synth.calls.clear()
    result = policy_cache.refresh_objects(client)
    global_calls = sum(n for k, n in synth.calls.items() if "/global/" in k)
    assert global_calls == 4  # address, addrgrp, vip, ippool once, not per ADOM
    for adom in _adoms(client):
        for kind in policy_store.KINDS:
            assert policy_store.get_objects(adom, kind) is not None, (adom, kind)
    assert result["failed"] == []
    assert policy_store.get_objects("global", "address")["objects"]
    assert policy_store.get_objects(_adoms(client)[0], "service")["objects"]


def test_object_failure_keeps_previous_and_empty_answer_needs_confirmation():
    synth, client = _make(adoms=1)
    policy_cache.refresh_objects(client)
    adom = _adoms(client)[0]
    before = policy_store.get_objects(adom, "address")["objects"]
    real = client.get_objects

    def flaky(a, kind, scope="all", strict=False):
        if kind == "address" and scope == "local":
            return []  # empty answer replacing a non-empty table
        return real(a, kind, scope, strict)

    client.get_objects = flaky
    policy_cache.refresh_objects(client)
    got = policy_store.get_objects(adom, "address")
    assert got["objects"] == before and got["status"] == "error"
    policy_cache.refresh_objects(client)  # second consecutive empty answer is accepted
    assert policy_store.get_objects(adom, "address")["objects"] == []


def test_parallel_fetch_respects_cap(monkeypatch):
    monkeypatch.setattr(Config, "POLICY_PARALLEL_FETCH", 2)
    synth, client = _make(adoms=1, packages=8)
    lock = threading.Lock()
    state = {"now": 0, "peak": 0}
    real = client.get_policies

    def slow(a, p):
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.03)
        try:
            return real(a, p)
        finally:
            with lock:
                state["now"] -= 1

    client.get_policies = slow
    policy_cache.refresh_once(client)
    assert 1 <= state["peak"] <= 2


def test_single_flight():
    synth, client = _make(adoms=1, packages=2)
    gate, entered = threading.Event(), threading.Event()
    real = client.get_policies

    def blocking(a, p):
        entered.set()
        gate.wait(2)
        return real(a, p)

    client.get_policies = blocking
    out = []
    t = threading.Thread(target=lambda: out.append(policy_cache.refresh_once(client)))
    t.start()
    entered.wait(2)
    assert policy_cache.refresh_once(client) == {"skipped": True}
    gate.set()
    t.join()
    assert "skipped" not in out[0]


def test_request_row_fetches_that_package_now_and_clears():
    synth, client = _make(adoms=1, packages=2)
    policy_cache.refresh_once(client)
    adom = _adoms(client)[0]
    pkg = policy_store.package_meta(adom)[0]["pkg"]
    real = synth._policies
    synth._policies = lambda a, p: (
        [{**r, "name": "fresh"} for r in real(a, p)] if p == pkg else real(a, p)
    )
    assert policy_store.request_package_refresh(adom, pkg, 30)
    synth.calls.clear()
    assert policy_cache.process_refresh_requests(client) == 1
    assert policy_store.get_policies(adom, pkg)["policies"][0]["name"] == "fresh"
    assert _fetches(synth, PKG) == 1
    assert policy_cache.process_refresh_requests(client) == 0


def test_scheduler_not_registered_when_flag_off(monkeypatch):
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    assert policy_cache.init_scheduler(object()) is False


def test_registered_jobs_and_boot_priority(monkeypatch):
    added = []

    class FakeSched:
        def add_job(self, **kw):
            added.append(kw["id"])

        def start(self):
            pass

    deferred = []
    monkeypatch.setattr(policy_cache, "_make_scheduler", lambda: FakeSched())
    monkeypatch.setattr(
        boot_warmup,
        "defer",
        lambda name, fn, priority: deferred.append((name, priority)),
    )
    assert policy_cache.init_scheduler(object()) is True
    assert set(added) == {
        "policy_refresh",
        "policy_objects_refresh",
        "policy_refresh_request_poll",
    }
    assert deferred == [("policy_cache", 3)]


def test_first_empty_answer_for_a_never_collected_package_is_held_once():
    synth, client = _make(adoms=1, packages=2)
    adom = _adoms(client)[0]
    real_get = client.get_policies
    victim = client.get_policy_packages(adom)[0]["path"]
    client.get_policies = lambda a, p: [] if p == victim else real_get(a, p)
    first = policy_cache.refresh_once(client)
    assert any(victim in f and "pending confirmation" in f for f in first["failed"])
    assert (
        policy_store.get_policies(adom, victim) is None
    )  # not served as "collected, empty"
    policy_cache.refresh_once(client)
    assert (
        policy_store.get_policies(adom, victim)["policies"] == []
    )  # second answer agrees


def test_first_empty_object_table_is_held_once():
    synth, client = _make(adoms=1)
    adom = _adoms(client)[0]
    real = client.get_objects
    client.get_objects = lambda a, kind, scope="all", strict=False: (
        [] if (kind == "service" and scope == "local") else real(a, kind, scope, strict)
    )
    first = policy_cache.refresh_objects(client)
    assert any("service" in f for f in first["failed"])
    assert policy_store.get_objects(adom, "service") is None
    policy_cache.refresh_objects(client)
    assert policy_store.get_objects(adom, "service")["objects"] == []


def test_first_empty_policy_block_and_empty_block_replacing_data_are_held_once():
    synth, client = _make(adoms=1, packages=2, blocks=1)
    adom = _adoms(client)[0]
    real = client.get_pblock_policies
    client.get_pblock_policies = lambda a, b, strict=False: []
    first = policy_cache.refresh_once(client)
    assert any("blk-0" in f and "pending confirmation" in f for f in first["failed"])
    assert policy_store.get_block(adom, "blk-0") is None
    client.get_pblock_policies = real
    policy_cache.refresh_once(client)  # a good answer arrives
    assert len(policy_store.get_block(adom, "blk-0")["policies"]) == 3
    client.get_pblock_policies = lambda a, b, strict=False: []
    for m in policy_store.block_meta(adom):
        policy_store._set_fetched_at_for_test(
            "policy_block",
            (adom, m["block"]),
            (datetime.now(UTC) - timedelta(hours=9)).isoformat(),
        )
    policy_cache.refresh_once(client)  # empty over non-empty: held, data kept
    assert len(policy_store.get_block(adom, "blk-0")["policies"]) == 3
    assert policy_store.get_block(adom, "blk-0")["status"] == "error"


def test_first_empty_package_list_for_a_new_adom_is_held_once():
    synth, client = _make(adoms=1)
    adom = _adoms(client)[0]
    real = client.get_policy_packages
    client.get_policy_packages = lambda a, strict=False: []
    first = policy_cache.refresh_once(client)
    assert adom in "".join(first["failed"]) and policy_store.get_packages(adom) is None
    policy_cache.refresh_once(client)
    assert policy_store.get_packages(adom)["entries"] == []
    client.get_policy_packages = real


def test_global_objects_permission_denied_becomes_an_empty_flagged_table_not_a_forever_fallback():
    from app import policies
    from app.fmg_client import FMGError

    synth, client = _make(adoms=1)
    adom = _adoms(client)[0]
    real = client.get_objects

    def denied(a, kind, scope="all", strict=False):
        if scope == "global":
            raise FMGError("No permission", code=-11)
        return real(a, kind, scope, strict)

    client.get_objects = denied
    result = policy_cache.refresh_objects(client)
    assert (
        result["failed"] == []
    )  # a known, permanent condition, not a failure to retry hard
    row = policy_store.get_objects("global", "address")
    assert (
        row["objects"] == []
        and row["status"] == "error"
        and "permission" in row["error"].lower()
    )

    class Boom:
        def __getattr__(self, name):
            def call(*a, **k):
                raise AssertionError(f"live call {name}")

            return call

    Config.POLICY_MAX_AGE_SECS = 0
    got = policies.objects(Boom(), adom, "address", "all")
    assert (
        got == policy_store.get_objects(adom, "address")["objects"]
    )  # local only, from the store
