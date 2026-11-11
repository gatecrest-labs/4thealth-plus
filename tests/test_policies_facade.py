"""Policy facade (Phase 4, Task 4)."""
# ruff: noqa: RUF059

from datetime import UTC, datetime, timedelta

import pytest

from app import policies, policy_cache, policy_store
from app.config import Config
from app.fmg_client import FMGClient, FMGError
from app.synthetic_fmg import SyntheticFMG


class Spy:
    """A client stand-in: records calls; with boom=True any call fails the test."""

    METHODS = (
        "get_policy_packages",
        "get_policies",
        "get_pblock_policies",
        "get_pkg_settings",
        "get_pkg_scope_members",
        "get_address_objects",
        "get_address_groups",
        "get_service_objects",
        "get_service_groups",
        "get_vip_objects",
        "get_ippool_objects",
    )

    def __init__(self, real=None, boom=False):
        self.real, self.boom, self.calls = real, boom, []
        for name in self.METHODS:
            setattr(self, name, self._make(name))

    def _make(self, name):
        def call(*a, **k):
            self.calls.append(name)
            if self.boom or self.real is None:
                raise AssertionError(f"unexpected live FMG call: {name}")
            return getattr(self.real, name)(*a, **k)

        return call


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "POLICY_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_MAX_AGE_SECS", 0)
    policy_cache._empty_list_seen.clear()
    policies.reset_counters()
    synth = SyntheticFMG(
        adoms=2,
        devices=10,
        packages_per_adom=3,
        rules_per_package=12,
        blocks_per_package=1,
        seed=5,
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    policy_cache.refresh_once(real)
    policy_cache.refresh_objects(real)
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    path = real.get_policy_packages(adom)[0]["path"]
    return real, adom, path


def _old(seconds):
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()


def test_flag_off_calls_client_never_store(monkeypatch, rig):
    real, adom, path = rig
    monkeypatch.setattr(Config, "POLICY_STORE", False)

    def nope(*a, **k):
        raise AssertionError("store touched with the flag off")

    for fn in (
        "get_packages",
        "get_policies",
        "get_block",
        "get_objects",
        "package_meta",
    ):
        monkeypatch.setattr(policy_store, fn, nope)
    spy = Spy(real)
    assert policies.packages(spy, adom) == real.get_policy_packages(adom)
    assert policies.policies(spy, adom, path) == real.get_policies(adom, path)
    assert policies.objects(spy, adom, "address") == real.get_address_objects(adom)
    assert spy.calls == ["get_policy_packages", "get_policies", "get_address_objects"]
    assert policies.counters() == {"hits": 0, "fallbacks": 0, "store_errors": 0}


def test_fresh_true_goes_live(rig):
    real, adom, path = rig
    spy = Spy(real)
    policies.policies(spy, adom, path, fresh=True)
    policies.packages(spy, adom, fresh=True)
    assert spy.calls == ["get_policies", "get_policy_packages"]


def test_serves_from_store_zero_fmg_calls(rig):
    real, adom, path = rig
    boom = Spy(boom=True)
    assert policies.packages(boom, adom) == real.get_policy_packages(adom)
    assert policies.policies(boom, adom, path) == real.get_policies(adom, path)
    for kind, method in (
        ("address", "get_address_objects"),
        ("addrgrp", "get_address_groups"),
        ("service", "get_service_objects"),
        ("svcgrp", "get_service_groups"),
        ("vip", "get_vip_objects"),
        ("ippool", "get_ippool_objects"),
    ):
        assert policies.objects(boom, adom, kind) == getattr(real, method)(adom), kind
    assert boom.calls == [] and policies.counters()["fallbacks"] == 0


def test_stale_or_missing_row_goes_live_and_counts(rig):
    real, adom, path = rig
    policy_store._set_fetched_at_for_test("policy_pkg", (adom, path), _old(100 * 3600))
    spy = Spy(real)
    assert policies.policies(spy, adom, path) == real.get_policies(adom, path)
    assert spy.calls == ["get_policies"] and policies.counters()["fallbacks"] == 1
    spy2 = Spy(real)
    with pytest.raises(
        FMGError
    ):  # never collected: the live read happens (and fails on FMG)
        policies.policies(spy2, adom, "brand-new-package")
    assert spy2.calls == ["get_policies"]


def test_error_status_with_data_within_max_age_still_served(rig):
    real, adom, path = rig
    policy_store.mark_policies_error(adom, path, "fmg down")
    boom = Spy(boom=True)
    assert policies.policies(boom, adom, path) == real.get_policies(adom, path)
    assert boom.calls == []


def test_store_error_goes_live(monkeypatch, rig):
    real, adom, path = rig

    def broken(*a, **k):
        raise policy_store.PolicyStoreError("io")

    monkeypatch.setattr(policy_store, "get_policies", broken)
    spy = Spy(real)
    assert policies.policies(spy, adom, path) == real.get_policies(adom, path)
    assert policies.counters()["store_errors"] == 1


def test_results_are_copies(rig):
    _, adom, path = rig
    boom = Spy(boom=True)
    first = policies.policies(boom, adom, path)
    first[0]["name"] = "MUTATED"
    first.clear()
    again = policies.policies(boom, adom, path)
    assert again and again[0]["name"] != "MUTATED"


@pytest.mark.parametrize("scope", ["local", "global", "all"])
@pytest.mark.parametrize(
    ("kind", "method"),
    [
        ("address", "get_address_objects"),
        ("addrgrp", "get_address_groups"),
        ("vip", "get_vip_objects"),
        ("ippool", "get_ippool_objects"),
        ("service", "get_service_objects"),
        ("svcgrp", "get_service_groups"),
    ],
)
def test_object_scopes_match_client_for_local_global_all(rig, kind, method, scope):
    real, adom, _ = rig
    boom = Spy(boom=True)
    assert policies.objects(boom, adom, kind, scope) == getattr(real, method)(
        adom, scope=scope
    )
    assert boom.calls == []


def test_pkg_settings_and_scope_equal_client_methods(rig):
    real, adom, path = rig
    boom = Spy(boom=True)
    assert policies.pkg_settings(boom, adom, path) == real.get_pkg_settings(adom, path)
    assert policies.pkg_scope(boom, adom, path) == real.get_pkg_scope_members(
        adom, path
    )
    assert policies.pkg_scope(boom, adom, path)  # not trivially empty
    assert boom.calls == []


def test_unknown_package_settings_go_live(rig):
    real, adom, _ = rig
    spy = Spy(real)
    assert policies.pkg_settings(spy, adom, "no/such/pkg") == {}
    assert spy.calls == ["get_pkg_settings"]


def test_pblock_served_from_store_and_strict_goes_live_when_missing(rig):
    real, adom, _ = rig
    boom = Spy(boom=True)
    assert policies.pblock_policies(boom, adom, "blk-0") == real.get_pblock_policies(
        adom, "blk-0"
    )
    spy = Spy(real)
    assert policies.pblock_policies(spy, adom, "missing-block", strict=False) == []
    assert spy.calls == ["get_pblock_policies"]


def test_data_as_of_is_oldest_involved_row(rig):
    real, adom, path = rig
    policy_store._set_fetched_at_for_test("policy_pkg", (adom, path), _old(3 * 3600))
    assert policies.data_as_of(adom, path) < _old(3 * 3600 - 60)
    oldest = policies.data_as_of(adom)
    assert oldest == min(m["fetched_at"] for m in policy_store.package_meta(adom))
    assert policies.data_as_of("never-collected") is None


def test_system_adoms_empty_without_calls(rig):
    boom = Spy(boom=True)
    assert policies.packages(boom, "FortiAnalyzer") == []
    assert policies.policies(boom, "FortiAnalyzer", "p") == []
    assert policies.objects(boom, "FortiCarrier", "address") == []
    assert boom.calls == [] and policies.counters()["fallbacks"] == 0


def test_system_adoms_still_live_when_flag_off(monkeypatch, rig):
    monkeypatch.setattr(Config, "POLICY_STORE", False)

    class OnlyPackages:
        def get_policy_packages(self, adom):
            return [{"name": "p", "path": "p"}]

    assert policies.packages(OnlyPackages(), "FortiCarrier") == [
        {"name": "p", "path": "p"}
    ]


def test_package_state_has_fingerprint_age_and_count_for_fresh_rows(rig):
    real, adom, path = rig
    state = policies.package_state(adom)
    assert set(state) == {p["path"] for p in real.get_policy_packages(adom)}
    row = state[path]
    meta = {m["pkg"]: m for m in policy_store.package_meta(adom)}[path]
    assert row["fingerprint"] == meta["fingerprint"] and row["fingerprint"]
    # 12 rules + 1 policy-block reference rule per package in this fixture
    assert row["policy_count"] == len(real.get_policies(adom, path)) == 13
    assert row["fetched_at"] and 0 <= row["age_seconds"] < 60


def test_package_state_skips_stale_and_never_collected_rows(rig):
    _, adom, path = rig
    policy_store._set_fetched_at_for_test("policy_pkg", (adom, path), _old(100 * 3600))
    policy_store.mark_policies_error(adom, "ghost", "never fetched")
    state = policies.package_state(adom)
    assert path not in state and "ghost" not in state and state


def test_package_state_empty_when_flag_off_or_system_adom_or_store_error(
    monkeypatch, rig
):
    _, adom, _ = rig
    assert policies.package_state("FortiAnalyzer") == {}

    def broken(*a, **k):
        raise policy_store.PolicyStoreError("io")

    monkeypatch.setattr(policy_store, "package_meta", broken)
    assert policies.package_state(adom) == {}
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    assert policies.package_state(adom) == {}


def test_package_counts_equal_client_policy_count(rig):
    real, adom, path = rig
    counts = policies.package_counts(adom)
    assert counts[path] == real.get_policy_count(adom, path)
