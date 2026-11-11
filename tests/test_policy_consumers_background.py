"""Hygiene sweep and summary rule counts read the policy store (Phase 4, Task 5)."""
# ruff: noqa: RUF059

import copy
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from app import executive_summary_cache as esc
from app import (
    hygiene,
    hygiene_pkg_store,
    policies,
    policy_cache,
    policy_store,
    summary_job,
)
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG


class NoPolicyClient(FMGClient):
    """Serves inventory (``/dvmdb/``) from the synthetic FMG; any ``/pm/`` read fails the test."""

    def __init__(self, synth):
        super().__init__(host="fmg.example", token="t")
        self.pm_calls: list[str] = []

        def post(body, timeout=None):
            url = body["params"][0]["url"]
            if url.startswith("/pm/"):
                self.pm_calls.append(url)
                raise AssertionError(f"unexpected policy/object FMG call: {url}")
            return synth.post(body, timeout)

        self._post = post


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    monkeypatch.setattr(Config, "POLICY_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_MAX_AGE_SECS", 0)
    monkeypatch.setattr(Config, "INFRA_TARGETS", [])
    policy_cache._empty_list_seen.clear()
    policies.reset_counters()
    synth = SyntheticFMG(
        adoms=2, devices=10, packages_per_adom=4, rules_per_package=30, seed=11
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: real)
    return synth, real


def _prime(monkeypatch, real):
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    policy_cache.refresh_objects(real)
    policy_cache.refresh_once(real)


def _use(monkeypatch, client):
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)


def _sweep(monkeypatch, on):
    monkeypatch.setattr(Config, "POLICY_STORE", on)
    assert esc._run_hygiene_sweep(object()) is True
    s = esc.get_summary()
    rh = s["rule_hygiene"]
    return {
        "rule_count_total": s["rule_count_total"],
        "hygiene_score": s["hygiene_score"],
        "by_type": copy.deepcopy(rh["rule_findings_by_type"]),
        "details": copy.deepcopy(rh["details"]),
        "data_as_of": rh.get("data_as_of"),
    }


def _comparable(result):
    return {k: v for k, v in result.items() if k != "data_as_of"}


def test_sweep_makes_zero_fmg_policy_calls_with_populated_store(monkeypatch, rig):
    synth, real = rig
    _prime(monkeypatch, real)
    guard = NoPolicyClient(synth)
    _use(monkeypatch, guard)
    _sweep(monkeypatch, True)
    assert guard.pm_calls == []
    assert policies.counters()["fallbacks"] == 0


def test_sweep_results_equal_live_results_cold_and_warm(monkeypatch, rig):
    synth, real = rig
    legacy = _sweep(monkeypatch, False)
    cold_empty_store = _sweep(
        monkeypatch, True
    )  # store empty: every read falls back live
    assert (
        _comparable(cold_empty_store) == _comparable(legacy)
        and legacy["rule_count_total"] > 0
    )
    _prime(monkeypatch, real)
    warm = _sweep(monkeypatch, True)
    assert _comparable(warm) == _comparable(legacy)
    again = _sweep(monkeypatch, True)
    assert _comparable(again) == _comparable(legacy)


def test_findings_recomputed_only_when_fingerprint_changes(monkeypatch, rig):
    synth, real = rig
    _prime(monkeypatch, real)
    calls = []
    real_run = hygiene.run_checks

    def spy(policies_, checks, *a, **k):
        calls.append(1)
        return real_run(policies_, checks, *a, **k)

    with patch("app.hygiene.run_checks", spy):
        _sweep(monkeypatch, True)
        first = len(calls)
        assert first == 8  # every package computed once
        _sweep(monkeypatch, True)
        assert len(calls) == first  # fingerprints unchanged: nothing recomputed
        # one package changes in FMG and the collector refetches it
        real_policies = synth._policies
        adom = next(iter(synth._adoms))
        pkg = policy_store.package_meta(adom)[0]["pkg"]

        def changed(a, p):
            ps = copy.deepcopy(real_policies(a, p))
            if (a, p) == (adom, pkg):
                ps[0]["name"] = ""
                ps[0]["comments"] = ""
            return ps

        synth._policies = changed
        for m in policy_store.package_meta(adom):
            policy_store._set_fetched_at_for_test(
                "policy_pkg",
                (adom, m["pkg"]),
                (datetime.now(UTC) - timedelta(hours=9)).isoformat(),
            )
        policy_cache.refresh_once(real)
        policy_cache.refresh_once(
            real
        )  # second pass: rows aged past TTL are refetched once
        _sweep(monkeypatch, True)
    assert len(calls) == first + 1


def test_data_as_of_is_oldest_store_fetch(monkeypatch, rig):
    synth, real = rig
    _prime(monkeypatch, real)
    adom = next(iter(synth._adoms))
    pkg = policy_store.package_meta(adom)[0]["pkg"]
    old = (datetime.now(UTC) - timedelta(hours=3)).isoformat()
    policy_store._set_fetched_at_for_test("policy_pkg", (adom, pkg), old)
    result = _sweep(monkeypatch, True)
    assert result["data_as_of"] == old


def test_summary_rule_counts_from_store_equal_live(monkeypatch, rig, tmp_path):
    synth, real = rig
    from app import summary_history

    monkeypatch.setattr(summary_history, "_HISTORY_PATH", tmp_path / "history.json")
    from app import create_app

    app = create_app()
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    summary_job._run_job(app)
    legacy = copy.deepcopy(summary_job.get_summary())
    _prime(monkeypatch, real)
    guard = NoPolicyClient(synth)
    _use(monkeypatch, guard)
    summary_job._run_job(app)
    cached = summary_job.get_summary()
    assert guard.pm_calls == []
    assert cached["rules_total"] == legacy["rules_total"] > 0
    assert cached["adom_breakdown"] == legacy["adom_breakdown"]


def test_flag_off_unchanged_and_never_touches_the_store(monkeypatch, rig):
    synth, real = rig

    def nope(*a, **k):
        raise AssertionError("policy store touched with POLICY_STORE off")

    for fn in (
        "get_packages",
        "get_policies",
        "get_objects",
        "package_meta",
        "get_block",
    ):
        monkeypatch.setattr(policy_store, fn, nope)
    for fn in ("get", "put", "touch", "delete_missing"):
        monkeypatch.setattr(hygiene_pkg_store, fn, nope)
    synth.calls.clear()
    _sweep(monkeypatch, False)
    assert any("/firewall/policy" in k for k in synth.calls)  # fetched live as before
