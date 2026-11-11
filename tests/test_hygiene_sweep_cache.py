"""Hygiene sweep reuses cached per-package results under POLICY_STORE (Phase 3, Task 5)."""

import copy
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from app import executive_summary_cache as esc
from app import hygiene_pkg_store as hps
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

BASE = 6 * 3600.0


@pytest.fixture
def rig(monkeypatch):
    synth = SyntheticFMG(
        adoms=2, devices=10, packages_per_adom=4, rules_per_package=40, seed=9
    )
    client = FMGClient(host="fmg.example", token="t")
    client._post = synth.post
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)
    monkeypatch.setattr(Config, "HYGIENE_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    return synth, client


def _policy_fetches(synth):
    return sum(n for k, n in synth.calls.items() if "/firewall/policy" in k)


def _result():
    s = esc.get_summary()
    rh = s["rule_hygiene"]
    return {
        "rule_count_total": s["rule_count_total"],
        "hygiene_score": s["hygiene_score"],
        "by_type": copy.deepcopy(rh["rule_findings_by_type"]),
        "total": rh["rule_findings_total"],
        "details": copy.deepcopy(rh["details"]),
    }


def _sweep(monkeypatch, on):
    monkeypatch.setattr(Config, "POLICY_STORE", on)
    assert esc._run_hygiene_sweep(object()) is True
    return _result()


def _age_all(seconds):
    from app import inventory_store  # noqa: F401  (schema owner)

    for adom, pkg in _cached_keys():
        hps._set_fetched_at_for_test(
            adom, pkg, (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()
        )


def _cached_keys():
    with hps._conn() as conn:
        return [(r[0], r[1]) for r in conn.execute("SELECT adom, pkg FROM hygiene_pkg")]


def test_cold_cache_results_equal_flag_off_results(monkeypatch, rig):
    legacy = _sweep(monkeypatch, False)
    cold = _sweep(monkeypatch, True)
    assert cold == legacy and legacy["rule_count_total"] > 0
    assert len(_cached_keys()) == 8  # 2 ADOMs x 4 packages cached


def test_second_sweep_makes_no_policy_fetches_inside_ttl(monkeypatch, rig):
    synth, _ = rig
    first = _sweep(monkeypatch, True)
    synth.calls.clear()
    second = _sweep(monkeypatch, True)
    assert _policy_fetches(synth) == 0
    assert second == first


def test_expired_entries_are_refetched_and_unchanged_fingerprint_is_touched_only(
    monkeypatch, rig
):
    synth, _ = rig
    first = _sweep(monkeypatch, True)
    _age_all(BASE * 1.3)  # past every package's jittered TTL
    synth.calls.clear()
    puts = []
    real_put = hps.put
    with patch.object(hps, "put", lambda *a, **k: (puts.append(1), real_put(*a, **k))):
        again = _sweep(monkeypatch, True)
    assert _policy_fetches(synth) == 8
    assert puts == []  # nothing changed: touched, not rewritten
    assert again == first
    assert all(hps.get(a, p)["age_seconds"] < 60 for a, p in _cached_keys())


def test_changed_policy_is_detected_by_fingerprint_and_findings_update(
    monkeypatch, rig
):
    synth, _ = rig
    first = _sweep(monkeypatch, True)
    _age_all(BASE * 1.3)
    real = synth._policies

    def changed(adom, pkg):
        ps = copy.deepcopy(real(adom, pkg))
        for p in ps[:5]:
            p["logtraffic"] = "disable"
            p["name"] = ""
            p["comment"] = ""
        return ps

    with patch.object(synth, "_policies", changed):
        after = _sweep(monkeypatch, True)
    assert after["by_type"] != first["by_type"]
    legacy_after = None
    with patch.object(synth, "_policies", changed):
        legacy_after = _sweep(monkeypatch, False)
    assert after == legacy_after


def test_deleted_package_disappears_within_one_sweep(monkeypatch, rig):
    _, client = rig
    _sweep(monkeypatch, True)
    adom = _cached_keys()[0][0]
    real = client.get_policy_packages
    dropped = real(adom)[0]["path"]
    client.get_policy_packages = lambda a: [
        p for p in real(a) if not (a == adom and p["path"] == dropped)
    ]
    after = _sweep(monkeypatch, True)
    assert hps.get(adom, dropped) is None
    client.get_policy_packages = real
    assert after["rule_count_total"] < _sweep(monkeypatch, False)["rule_count_total"]


def test_failed_refetch_reuses_entry_under_2x_ttl_else_skips(monkeypatch, rig):
    _, client = rig
    first = _sweep(monkeypatch, True)
    real_get = client.get_policies

    def failing(adom, pkg):
        raise RuntimeError("fmg down")

    _age_all(BASE * 1.3)  # expired (> TTL) but younger than 2 x TTL for every package
    client.get_policies = failing
    reused = _sweep(monkeypatch, True)
    assert reused == first
    _age_all(BASE * 16)  # older than 2 x the largest TTL
    skipped = _sweep(monkeypatch, True)
    client.get_policies = real_get
    assert skipped["rule_count_total"] == 0
    assert (
        skipped["hygiene_score"] != first["hygiene_score"]
        or first["hygiene_score"] is None
    )


def test_mixed_fresh_and_cached_totals_equal_full_refetch_totals(monkeypatch, rig):
    _sweep(monkeypatch, True)
    keys = _cached_keys()
    for adom, pkg in keys[::2]:  # age half of them past TTL
        hps._set_fetched_at_for_test(
            adom, pkg, (datetime.now(UTC) - timedelta(seconds=BASE * 1.3)).isoformat()
        )
    mixed = _sweep(monkeypatch, True)
    full = _sweep(monkeypatch, False)
    assert mixed == full


def test_unused_objects_from_cached_refs_equal_full_detection(monkeypatch, rig):
    first = _sweep(monkeypatch, True)
    second = _sweep(monkeypatch, True)  # everything served from cache
    assert second["by_type"]["unused_objects"] == first["by_type"]["unused_objects"] > 0


def test_flag_off_never_touches_the_package_table(monkeypatch, rig):
    def nope(*a, **k):
        raise AssertionError("package table touched with POLICY_STORE off")

    for fn in ("get", "put", "touch", "delete_missing"):
        monkeypatch.setattr(hps, fn, nope)
    _sweep(monkeypatch, False)


def test_unreadable_store_falls_back_to_fetching(monkeypatch, rig):
    legacy = _sweep(monkeypatch, False)

    def broken(*a, **k):
        raise hps.HygienePkgStoreError("io")

    for fn in ("get", "put", "touch", "delete_missing"):
        monkeypatch.setattr(hps, fn, broken)
    assert _sweep(monkeypatch, True) == legacy


def test_refetch_load_is_spread(monkeypatch):
    synth = SyntheticFMG(
        adoms=1, devices=5, packages_per_adom=60, rules_per_package=5, seed=2
    )
    client = FMGClient(host="fmg.example", token="t")
    client._post = synth.post
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)
    monkeypatch.setattr(Config, "HYGIENE_PACKAGE_TTL_HOURS", 6)
    _sweep(monkeypatch, True)
    _age_all(BASE * 0.9)  # inside the jitter band: some expired, most not
    synth.calls.clear()
    _sweep(monkeypatch, True)
    refetched = _policy_fetches(synth)
    assert 0 < refetched < 60


def test_rule_hygiene_reports_the_age_of_the_data_it_used(monkeypatch, rig):
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    assert esc._run_hygiene_sweep(object()) is True
    fresh = esc.get_summary()["rule_hygiene"]
    assert fresh["data_as_of"] <= fresh["collected_at"]
    assert (
        datetime.fromisoformat(fresh["collected_at"])
        - datetime.fromisoformat(fresh["data_as_of"])
    ).total_seconds() < 120

    _age_all(3 * 3600)  # entries 3 h old, still inside every package's TTL
    assert esc._run_hygiene_sweep(object()) is True
    cached = esc.get_summary()["rule_hygiene"]
    lag = (
        datetime.fromisoformat(cached["collected_at"])
        - datetime.fromisoformat(cached["data_as_of"])
    ).total_seconds()
    assert 3 * 3600 - 120 <= lag <= 3 * 3600 + 120  # oldest entry used is ~3 h old
