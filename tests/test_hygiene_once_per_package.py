"""Hygiene checks once per package; reference sets instead of policy lists (Phase 3, Task 3)."""

import copy
from unittest.mock import patch

import pytest

from app import executive_summary_cache as esc
from app import hygiene
from app.fmg_client import FMGClient
from app.hygiene import (
    CHECKS,
    find_unused_objects,
    find_unused_objects_from_refs,
    run_checks,
)
from app.synthetic_fmg import SyntheticFMG

SUBSET = esc._HYGIENE_CHECKS


def _fleet():
    synth = SyntheticFMG(
        adoms=2, devices=10, packages_per_adom=3, rules_per_package=60, seed=4
    )
    client = FMGClient(host="fmg.example", token="t")
    client._post = synth.post
    return synth, client


def _all_policies(client):
    out = []
    for adom in [
        a["name"]
        for a in client.get_adoms()
        if not a["name"].lower().startswith("forti")
    ]:
        for pkg in client.get_policy_packages(adom):
            out.append((adom, pkg["path"], client.get_policies(adom, pkg["path"])))
    return out


def _mutate(policies):
    """Add the shapes the checks care about: exempt comments, disabled, expired, unnamed."""
    ps = copy.deepcopy(policies)
    for i, p in enumerate(ps):
        if i % 7 == 0:
            p["comment"] = "temp EXEMPT rule"
        if i % 5 == 0:
            p["status"] = "disable"
        if i % 11 == 0:
            p["name"] = ""
            p["comment"] = ""
        if i % 13 == 0:
            p["logtraffic"] = "disable"
    return ps


def test_subset_of_full_run_equals_separate_subset_run():
    _, client = _fleet()
    for _adom, _pkg, policies in _all_policies(client):
        for ps in (policies, _mutate(policies)):
            full = run_checks(ps, list(CHECKS))
            assert [f for f in full if f["check"] in SUBSET] == run_checks(ps, SUBSET)


def test_find_unused_objects_from_refs_equals_full_version():
    _, client = _fleet()
    for adom in [
        a["name"]
        for a in client.get_adoms()
        if not a["name"].lower().startswith("forti")
    ]:
        pols = [p for a, _, ps in _all_policies(client) if a == adom for p in ps]
        addrs = client.get_address_objects(adom)
        grps = client.get_address_groups(adom)
        svcs = client.get_service_objects(adom)
        sgrps = client.get_service_groups(adom)
        want = find_unused_objects(pols, addrs, grps, svcs, sgrps)
        a_refs, s_refs = hygiene.collect_policy_refs(pols)
        assert (
            find_unused_objects_from_refs(a_refs, s_refs, addrs, grps, svcs, sgrps)
            == want
        )
        assert (
            want["unused_addresses"] or want["unused_services"]
        )  # not trivially empty


def test_collect_policy_refs_alias_kept():
    assert hygiene._collect_policy_refs is hygiene.collect_policy_refs


@pytest.fixture
def sweep(monkeypatch):
    synth, client = _fleet()
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)
    return synth, client


def _legacy_expectation(client):
    """The pre-refactor arithmetic: two run_checks per package, unused over unioned policies."""
    total_findings = total_policies = 0
    by_type = dict.fromkeys(CHECKS, 0)
    by_type["unused_objects"] = 0
    for adom in [
        a["name"]
        for a in client.get_adoms()
        if not a["name"].lower().startswith("forti")
    ]:
        union = []
        for pkg in client.get_policy_packages(adom):
            ps = client.get_policies(adom, pkg["path"])
            total_policies += len(ps)
            total_findings += len(run_checks(ps, SUBSET))
            for f in run_checks(ps, list(CHECKS)):
                by_type[f["check"]] += 1
            union.extend(ps)
        if union:
            u = find_unused_objects(
                union,
                client.get_address_objects(adom),
                client.get_address_groups(adom),
                client.get_service_objects(adom),
                client.get_service_groups(adom),
            )
            by_type["unused_objects"] += len(u["unused_addresses"]) + len(
                u["unused_services"]
            )
    return total_findings, total_policies, by_type


def test_sweep_calls_run_checks_once_per_package(sweep):
    _, client = sweep
    n_packages = sum(
        len(client.get_policy_packages(a["name"]))
        for a in client.get_adoms()
        if not a["name"].lower().startswith("forti")
    )
    calls = []
    real = hygiene.run_checks

    def spy(policies, checks, *a, **k):
        calls.append(1)
        return real(policies, checks, *a, **k)

    with patch("app.hygiene.run_checks", spy):
        assert esc._run_hygiene_sweep(object()) is True
    assert len(calls) == n_packages


def test_sweep_totals_identical_to_legacy_on_synthetic_fleet(sweep):
    _, client = sweep
    total_findings, total_policies, by_type = _legacy_expectation(client)
    assert esc._run_hygiene_sweep(object()) is True
    summary = esc.get_summary()
    assert summary["rule_count_total"] == total_policies
    assert summary["hygiene_score"] == esc._hygiene_score(
        total_findings, total_policies
    )
    assert summary["rule_hygiene"]["rule_findings_by_type"] == by_type
