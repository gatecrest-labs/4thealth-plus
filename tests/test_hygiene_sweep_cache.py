"""Hygiene sweep equivalence with POLICY_STORE on and an empty policy store (falls back live).

Phase 3 reused cached results by TTL inside the sweep; Phase 4 moved fetching, TTL and
refetch scheduling to the collector (tests/test_policy_cache.py) and the sweep now reads
the policy store (tests/test_policy_consumers_background.py)."""

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
