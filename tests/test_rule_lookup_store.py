"""Rule Lookup index built from the policy store (Phase 4, Task 6)."""
# ruff: noqa: RUF059

import json
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import psutil
import pytest

from app import policies, policy_cache, policy_store, rule_lookup, rule_lookup_cache
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


class NoPmClient(FMGClient):
    """Fails the test on any ``/pm/`` read (policies, packages, objects, blocks)."""

    def __init__(self, synth):
        super().__init__(host="fmg.example", token="t")
        self.pm_calls: list[str] = []

        def post(body, timeout=None):
            url = body["params"][0]["url"]
            if url.startswith("/pm/"):
                self.pm_calls.append(url)
                raise AssertionError(f"unexpected FMG policy read: {url}")
            return synth.post(body, timeout)

        self._post = post


def _quiesce(timeout: float = 10.0) -> None:
    """Wait for background Rule Lookup builds to finish, then reset the module state."""
    deadline = time.time() + timeout
    while rule_lookup_cache._building and time.time() < deadline:
        time.sleep(0.02)
    rule_lookup_cache._building.clear()
    rule_lookup_cache._store.clear()


@pytest.fixture
def rig(monkeypatch):
    _quiesce()
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    monkeypatch.setattr(Config, "POLICY_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_MAX_AGE_SECS", 0)
    policy_cache._empty_list_seen.clear()
    policies.reset_counters()
    rule_lookup_cache._store.clear()
    synth = SyntheticFMG(
        adoms=1,
        devices=10,
        packages_per_adom=4,
        rules_per_package=25,
        blocks_per_package=1,
        seed=8,
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    monkeypatch.setattr(rule_lookup_cache, "make_client", lambda: real)
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    yield synth, real, adom
    _quiesce()  # an async rebuild must not outlive its test (it would hit the next one)


def _prime(monkeypatch, real):
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    policy_cache.refresh_objects(real)
    policy_cache.refresh_once(real)


@pytest.fixture
def http(monkeypatch):
    from app import create_app

    app = create_app()
    with app.test_client() as c, patch("app.auth._load_users", return_value=_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "t"
            sess["login_at"] = int(time.time())
        yield c


def _post(c, url, payload=None):
    return c.post(
        url,
        data=json.dumps(payload or {}),
        content_type="application/json",
        headers={"X-CSRF-Token": "t"},
    )


def _search(c, adom, **q):
    return _post(c, f"/api/hygiene/adoms/{adom}/rule-lookup", q)


def test_first_search_builds_from_store_with_zero_fmg_calls(monkeypatch, rig, http):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    guard = NoPmClient(synth)
    monkeypatch.setattr(rule_lookup_cache, "make_client", lambda: guard)
    resp = _search(http, adom, src="10.0.0.0/8")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()["total"] > 0
    assert guard.pm_calls == []


def _rules_key(rules):
    return sorted(json.dumps(r, sort_keys=True) for r in rules)


def test_results_equal_live_build(monkeypatch, rig):
    synth, real, adom = rig
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    rule_lookup_cache.refresh_adom(adom)
    live = rule_lookup_cache.get_adom(adom)
    rule_lookup_cache._store.clear()
    _prime(monkeypatch, real)
    rule_lookup_cache.refresh_adom(adom)
    stored = rule_lookup_cache.get_adom(adom)
    assert live["status"] == stored["status"] == "ok"
    assert _rules_key(stored["rules"]) == _rules_key(live["rules"]) and live["rules"]
    assert stored["package_errors"] == live["package_errors"] == []
    for q in (
        rule_lookup.Query(
            src=rule_lookup.parse_addr_query("10.0.0.5")
            if hasattr(rule_lookup, "parse_addr_query")
            else None,
            dst=None,
            port=None,
        ),
        rule_lookup.Query(
            src=None,
            dst=None,
            port=rule_lookup.parse_port_query("tcp/1005", lambda n: None),
        ),
    ):
        a = rule_lookup.search(live["rules"], q, live["ctx"], True)
        b = rule_lookup.search(stored["rules"], q, stored["ctx"], True)
        assert json.dumps(a, sort_keys=True, default=str) == json.dumps(
            b, sort_keys=True, default=str
        )


def test_policy_blocks_expand_like_legacy(monkeypatch, rig):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    rule_lookup_cache.refresh_adom(adom)
    rules = rule_lookup_cache.get_adom(adom)["rules"]
    block_rules = [r for r in rules if r["policy_block"] == "blk-0"]
    assert (
        len(block_rules) == 4 * 3
    )  # 3 rules of the block, once per referencing package


def test_block_failure_listed_in_package_errors(monkeypatch, rig):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    policy_store.delete_missing_blocks(adom, set())  # block rows gone from the store

    class FailingBlocks(FMGClient):
        def __init__(self):
            super().__init__(host="fmg.example", token="t")

            def post(body, timeout=None):
                if "/pblock/" in body["params"][0]["url"]:
                    raise RuntimeError("block gone")
                return synth.post(body, timeout)

            self._post = post

    monkeypatch.setattr(rule_lookup_cache, "make_client", lambda: FailingBlocks())
    rule_lookup_cache.refresh_adom(adom)
    entry = rule_lookup_cache.get_adom(adom)
    assert entry["status"] == "ok" and any(
        "blk-0" in e for e in entry["package_errors"]
    )


def test_index_rebuilt_when_store_generation_changes_not_otherwise(
    monkeypatch, rig, http
):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    builds = []
    real_build = rule_lookup_cache._build_adom
    monkeypatch.setattr(
        rule_lookup_cache, "_build_adom", lambda a: (builds.append(1), real_build(a))[1]
    )
    assert _search(http, adom, src="10.0.0.0/8").status_code == 200
    assert _search(http, adom, src="10.0.0.0/8").status_code == 200
    assert len(builds) == 1  # same store generation: no rebuild
    # one package changes in FMG; the collector refetches it
    real_policies = synth._policies
    pkg = policy_store.package_meta(adom)[0]["pkg"]
    synth._policies = lambda a, p: (
        [{**r, "name": "edited"} for r in real_policies(a, p)]
        if p == pkg
        else real_policies(a, p)
    )
    for m in policy_store.package_meta(adom):
        policy_store._set_fetched_at_for_test(
            "policy_pkg",
            (adom, m["pkg"]),
            (datetime.now(UTC) - timedelta(hours=9)).isoformat(),
        )
    policy_cache.refresh_once(real)
    assert (
        _search(http, adom, src="10.0.0.0/8").status_code == 200
    )  # serves the old index, rebuilds async
    deadline = time.time() + 5
    while len(builds) < 2 and time.time() < deadline:
        time.sleep(0.05)
    assert len(builds) == 2


def test_empty_store_falls_back_to_warming_path(monkeypatch, rig, http):
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    synth, real, adom = rig
    started = []
    monkeypatch.setattr(
        rule_lookup_cache, "refresh_adom_async", lambda a: started.append(a)
    )
    resp = _search(http, adom, src="10.0.0.0/8")
    assert (
        resp.status_code == 202
        and resp.get_json()["status"] == "warming"
        and started == [adom]
    )


def test_flag_off_unchanged_warming_on_first_search(monkeypatch, rig, http):
    synth, real, adom = rig
    started = []
    monkeypatch.setattr(
        rule_lookup_cache, "refresh_adom_async", lambda a: started.append(a)
    )
    assert _search(http, adom, src="10.0.0.0/8").status_code == 202 and started == [
        adom
    ]


def test_refresh_endpoint_enqueues_requests_no_fmg_calls(monkeypatch, rig, http):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    guard = NoPmClient(synth)
    monkeypatch.setattr(rule_lookup_cache, "make_client", lambda: guard)
    resp = _post(http, f"/api/hygiene/adoms/{adom}/rule-lookup/refresh")
    assert resp.status_code == 202 and resp.get_json()["requested"] == 4
    assert sorted(p for _, p in policy_store.pop_refresh_requests(100)) == sorted(
        m["pkg"] for m in policy_store.package_meta(adom)
    )
    assert guard.pm_calls == []


def test_response_includes_data_as_of(monkeypatch, rig, http):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    body = _search(http, adom, src="10.0.0.0/8").get_json()
    assert body["data_as_of"] == policies.data_as_of(adom) and body["source"] == "store"


def test_build_time_and_memory_for_a_24k_rule_adom(monkeypatch):
    _quiesce()
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    monkeypatch.setattr(Config, "POLICY_PARALLEL_FETCH", 4)
    rule_lookup_cache._store.clear()
    synth = SyntheticFMG(
        adoms=1, devices=10, packages_per_adom=80, rules_per_package=300, seed=2
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    policy_cache.refresh_objects(real)
    policy_cache.refresh_once(real)
    adom = next(iter(synth._adoms))
    guard = NoPmClient(synth)
    monkeypatch.setattr(rule_lookup_cache, "make_client", lambda: guard)
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    t0 = time.monotonic()
    rule_lookup_cache.refresh_adom(adom)
    build_s = time.monotonic() - t0
    entry = rule_lookup_cache.get_adom(adom)
    assert entry["status"] == "ok" and len(entry["rules"]) == 80 * 300
    assert guard.pm_calls == []
    t1 = time.monotonic()
    q = rule_lookup.Query(
        src=None,
        dst=None,
        port=rule_lookup.parse_port_query("tcp/1005", lambda n: None),
    )
    rule_lookup.search(entry["rules"], q, entry["ctx"], False)
    search_s = time.monotonic() - t1
    delta_mb = (proc.memory_info().rss - rss0) / 1e6
    print(
        f"\nrule lookup 24k rules: build {build_s:.2f}s search {search_s:.3f}s rss +{delta_mb:.0f} MB"
    )
    assert build_s < 10 and search_s < 2 and delta_mb < 400
