"""Scheduled reports read the policy store; alerts stay live (Phase 4, Task 8)."""
# ruff: noqa: RUF059

import json
from datetime import UTC, datetime, timedelta

import pytest

from app import policies, policy_cache, policy_store
from app import rule_policy_scheduler as rps
from app.config import Config
from app.fmg_client import FMGClient
from app.routes import hygiene_routes
from app.synthetic_fmg import SyntheticFMG

_BLOCKED = ("/pm/config/adom/", "/pm/config/global/", "/pm/pkg/")


class GuardClient(FMGClient):
    """Blocks ADOM-scoped policy/package/object reads; per-device reads still go through."""

    def __init__(self, synth):
        super().__init__(host="fmg.example", token="t")
        self.blocked: list[str] = []

        def post(body, timeout=None):
            url = body["params"][0]["url"]
            if url.startswith(_BLOCKED):
                self.blocked.append(url)
                raise AssertionError(f"unexpected FMG policy/object read: {url}")
            return synth.post(body, timeout)

        self._post = post


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    monkeypatch.setattr(Config, "POLICY_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_MAX_AGE_SECS", 0)
    policy_cache._empty_list_seen.clear()
    policies.reset_counters()
    synth = SyntheticFMG(
        adoms=1,
        devices=8,
        packages_per_adom=3,
        rules_per_package=15,
        blocks_per_package=0,
        seed=6,
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    return synth, real, adom


def _use(monkeypatch, client):
    for target in (
        "app.routes.hygiene_routes.make_client",
        "app.rule_policy_scheduler._make_client",
        "app.nat_report_scheduler._make_client",
        "app.fmg_helpers.make_client",
    ):
        monkeypatch.setattr(target, lambda c=client: c)


def _prime(monkeypatch, real):
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    policy_cache.refresh_objects(real)
    policy_cache.refresh_once(real)


def _clean(obj):
    """Drop per-run timestamps so two runs compare equal."""
    if isinstance(obj, dict):
        return {
            k: _clean(v)
            for k, v in obj.items()
            if k not in ("pulled_at", "generated_at", "checked_at")
        }
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return obj


def _key(obj):
    return json.dumps(_clean(obj), sort_keys=True, default=str)


def test_bulk_hygiene_adom_zero_policy_calls_with_store(monkeypatch, rig):
    synth, real, adom = rig
    _use(monkeypatch, real)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    legacy = hygiene_routes.bulk_hygiene_adom(adom, [], True, max_workers=2)
    _prime(monkeypatch, real)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    cached = hygiene_routes.bulk_hygiene_adom(adom, [], True, max_workers=2)
    assert guard.blocked == []
    assert _key(cached) == _key(legacy) and legacy


def test_rule_policy_report_equals_live_content(monkeypatch, rig):
    synth, real, adom = rig
    _use(monkeypatch, real)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    legacy = rps.bulk_policy_adom(adom, [], False, False)
    _prime(monkeypatch, real)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    cached = rps.bulk_policy_adom(adom, [], False, False)
    assert guard.blocked == []
    assert _key(cached["results"]) == _key(legacy["results"]) and legacy["results"]


def test_fresh_report_goes_live_even_with_the_store_on(monkeypatch, rig):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    # FMG now holds an edited rule; the store still has the old one
    real_policies = synth._policies
    pkg = policy_store.package_meta(adom)[0]["pkg"]
    synth._policies = lambda a, p: (
        [{**r, "name": "edited-in-fmg"} for r in real_policies(a, p)]
        if p == pkg
        else real_policies(a, p)
    )
    _use(monkeypatch, real)
    stale = rps.bulk_policy_adom(adom, [pkg.split("/")[-1]], False, False)
    fresh = rps.bulk_policy_adom(adom, [pkg.split("/")[-1]], False, False, fresh=True)
    assert "edited-in-fmg" not in json.dumps(stale["results"], default=str)
    assert "edited-in-fmg" in json.dumps(fresh["results"], default=str)


def test_pca_policy_report_requests_a_fresh_fetch(monkeypatch):
    from app import package_change_alerts as pca

    seen = {}

    def fake(adom, pkgs, g, h, w=4, **kw):
        seen["kw"] = kw
        return {"results": [], "skipped": []}

    monkeypatch.setattr(rps, "_bulk_policy_adom", fake)
    pca._policy_reports("Corp", ["Pkg"], "html")
    assert seen["kw"].get("fresh") is True


def test_nat_report_shared_objects_and_packages_from_store_device_sweep_live(
    monkeypatch, rig
):
    synth, real, adom = rig
    from app import nat_report_scheduler as nrs

    _use(monkeypatch, real)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    legacy = nrs.collect_nat_data(adom, max_workers=2)
    _prime(monkeypatch, real)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    cached = nrs.collect_nat_data(adom, max_workers=2)
    assert guard.blocked == []
    assert _key(cached) == _key(legacy)
    assert nrs._group_members(adom) == nrs._group_members(adom)


def test_digest_states_data_age_when_older_than_15_minutes(monkeypatch, rig):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    assert policies.age_note_html(adom) == ""  # just collected
    for m in policy_store.package_meta(adom):
        policy_store._set_fetched_at_for_test(
            "policy_pkg",
            (adom, m["pkg"]),
            (datetime.now(UTC) - timedelta(hours=3)).isoformat(),
        )
    note = policies.age_note_html(adom)
    assert "Policy data as of" in note and "3 h" in note
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    assert policies.age_note_html(adom) == ""
    assert policies.age_note_html("never-collected") == ""


def test_flag_off_unchanged(monkeypatch, rig):
    synth, real, adom = rig

    def nope(*a, **k):
        raise AssertionError("policy store touched with POLICY_STORE off")

    for fn in (
        "get_packages",
        "get_policies",
        "get_objects",
        "get_block",
        "package_meta",
    ):
        monkeypatch.setattr(policy_store, fn, nope)
    _use(monkeypatch, real)
    synth.calls.clear()
    hygiene_routes.bulk_hygiene_adom(adom, [], False, max_workers=2)
    assert any("/firewall/policy" in k for k in synth.calls)


def test_policy_objects_fresh_flag_bypasses_the_store(monkeypatch, rig):
    synth, real, adom = rig
    _prime(monkeypatch, real)
    policy_store.put_objects(adom, "address", [{"name": "only-in-store"}], "fp-x")
    assert policies.objects(real, adom, "address", "local") == [
        {"name": "only-in-store"}
    ]
    assert {
        o["name"] for o in policies.objects(real, adom, "address", "local", fresh=True)
    } != {"only-in-store"}
