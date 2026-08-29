"""Unit tests for the pure aggregation functions in app.executive_summary_cache."""
import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import pytest

from app.executive_summary_cache import (
    _HYGIENE_CHECKS,
    _classify_online,
    _device_version,
    _hygiene_score,
    _pending_diff_count,
    _version_compliance_pct,
)


# ── _HYGIENE_CHECKS ─────────────────────────────────────────────────────────

def test_hygiene_checks_excludes_shadow():
    # "shadow" needs live addr/svc resolvers and is deliberately excluded from
    # the cheap check set used by the executive summary sweep — see spec
    # decision 5.
    assert "shadow" not in _HYGIENE_CHECKS


# ── _classify_online ────────────────────────────────────────────────────────

def test_classify_online_counts_conn_status_1_as_online():
    devices = [
        {"name": "FW1", "conn_status": 1},
        {"name": "FW2", "conn_status": 1},
        {"name": "FW3", "conn_status": 0},
    ]
    assert _classify_online(devices) == (2, 3)


def test_classify_online_empty_list():
    assert _classify_online([]) == (0, 0)


# ── _version_compliance_pct ─────────────────────────────────────────────────

def test_version_compliance_pct_none_when_no_target_versions():
    devices = [{"version": "v7.4.3"}]
    assert _version_compliance_pct(devices, []) is None


def test_version_compliance_pct_none_when_no_devices():
    assert _version_compliance_pct([], ["v7.4.3"]) is None


def test_version_compliance_pct_computes_percentage():
    devices = [
        {"version": "v7.4.3"},
        {"version": "v7.4.3"},
        {"version": "v7.2.1"},
        {"version": "v7.6.2"},
    ]
    assert _version_compliance_pct(devices, ["v7.4.3", "v7.6.2"]) == 75.0


# ── _pending_diff_count ──────────────────────────────────────────────────────

def test_pending_diff_count_zero_when_all_in_sync():
    devices_by_adom = {
        "ADOM1": [{"conf_status": "insync", "db_status": "nomod", "pkg_status": "nomod"}],
    }
    assert _pending_diff_count(devices_by_adom) == 0


def test_pending_diff_count_counts_outofsync():
    devices_by_adom = {
        "ADOM1": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}],
    }
    assert _pending_diff_count(devices_by_adom) == 1


def test_pending_diff_count_counts_modified_db_or_pkg():
    devices_by_adom = {
        "ADOM1": [
            {"conf_status": "insync", "db_status": "modified", "pkg_status": "nomod"},
            {"conf_status": "insync", "db_status": "nomod", "pkg_status": "modified"},
        ],
    }
    assert _pending_diff_count(devices_by_adom) == 2


def test_pending_diff_count_sums_across_adoms():
    devices_by_adom = {
        "ADOM1": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}],
        "ADOM2": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}],
    }
    assert _pending_diff_count(devices_by_adom) == 2


def test_pending_diff_count_does_not_double_count_one_device():
    devices_by_adom = {
        "ADOM1": [{"conf_status": "outofsync", "db_status": "modified", "pkg_status": "modified"}],
    }
    assert _pending_diff_count(devices_by_adom) == 1


# ── _hygiene_score ───────────────────────────────────────────────────────────

def test_hygiene_score_none_when_no_policies():
    assert _hygiene_score(total_findings=0, total_policies=0) is None


def test_hygiene_score_100_when_no_findings():
    assert _hygiene_score(total_findings=0, total_policies=50) == 100.0


def test_hygiene_score_computes_density():
    assert _hygiene_score(total_findings=10, total_policies=50) == 80.0


def test_hygiene_score_clamped_to_zero_when_findings_exceed_policies():
    # A policy can trigger more than one check, so findings can outnumber policies.
    assert _hygiene_score(total_findings=200, total_policies=50) == 0.0


# ── _device_version ──────────────────────────────────────────────────────────

def test_device_version_major_mr_patch():
    assert _device_version({"os_ver": 700, "mr": 4, "patch": 3}) == "v7.4.3"


def test_device_version_major_mr_only():
    assert _device_version({"os_ver": 700, "mr": 6, "patch": None}) == "v7.6"


def test_device_version_unknown():
    assert _device_version({"os_ver": 0, "mr": None, "patch": None}) == "n/a"


# ── _run_device_sweep / _run_hygiene_sweep (mocked FMG client) ──────────────

from unittest.mock import MagicMock, patch

import app.executive_summary_cache as cache_mod


@pytest.fixture(autouse=True)
def _reset_store(tmp_path, monkeypatch):
    # Redirect the hygiene rollup file into tmp_path so sweeps triggered by any
    # test in this module never write hygiene_rollup.json into the project root.
    import app.hygiene_rollup as hygiene_rollup_mod

    monkeypatch.setattr(
        hygiene_rollup_mod, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json"
    )
    with cache_mod._lock:
        cache_mod._store.update({
            "hygiene_score": None,
            "version_compliance_pct": None,
            "pending_config_diff_count": None,
            "firewall_online_count": None,
            "firewalls_total": None,
            "adom_count": None,
            "rule_count_total": None,
            "rule_hygiene": None,
            "status": "pending",
            "error": None,
            "last_updated": None,
            "device_sweep_status": "pending",
            "hygiene_sweep_status": "pending",
            "device_sweep_collected_at": None,
            "hygiene_sweep_collected_at": None,
        })
    cache_mod._device_running.clear()
    cache_mod._hygiene_running.clear()
    yield
    cache_mod._device_running.clear()
    cache_mod._hygiene_running.clear()


def _fake_client():
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}, {"name": "FortiForticloud"}]
    client.get_devices.return_value = [
        {"name": "FW1", "conn_status": 1, "os_ver": 700, "mr": 4, "patch": 3},
        {"name": "FW2", "conn_status": 0, "os_ver": 700, "mr": 4, "patch": 3},
    ]
    client.get_policy_packages.return_value = [{"path": "default", "name": "default"}]
    client.get_policies.return_value = [
        {"policyid": 1, "name": "", "status": 1, "logtraffic": 0},  # unnamed + unlogged
        {"policyid": 2, "name": "allow-web", "status": 1, "logtraffic": 2},
    ]
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []
    return client


# ── _run_device_sweep ────────────────────────────────────────────────────────


def test_run_device_sweep_populates_store_from_mocked_fmg(monkeypatch, app_ctx):
    monkeypatch.setattr(
        "app.app_settings.get_setting",
        lambda key, default=None: ["v7.4.3"] if key == "executive_compliant_versions" else default,
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_all_cached_devices",
        lambda: {"Customer1": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}]},
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_cache_status",
        lambda: {"status": "ok", "last_updated": "2026-08-24T00:00:00+00:00", "adoms_cached": 1, "error": None},
    )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        result = cache_mod._run_device_sweep(app_ctx)

    assert result is True
    summary = cache_mod.get_summary()
    assert summary["status"] == "ok"
    assert summary["firewalls_total"] == 2
    assert summary["firewall_online_count"] == 1
    assert summary["version_compliance_pct"] == 100.0  # both devices are v7.4.3
    assert summary["pending_config_diff_count"] == 1
    assert summary["last_updated"] is not None
    # The device sweep never touches hygiene_score — it's the other sweep's job.
    assert summary["hygiene_score"] is None
    fake_client.get_policy_packages.assert_not_called()
    fake_client.get_policies.assert_not_called()


def test_run_device_sweep_preserves_existing_hygiene_score(monkeypatch, app_ctx):
    with cache_mod._lock:
        cache_mod._store["hygiene_score"] = 87.3

    monkeypatch.setattr(
        "app.app_settings.get_setting", lambda key, default=None: default
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_all_cached_devices", lambda: {}
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_cache_status",
        lambda: {"status": "ok", "last_updated": None, "adoms_cached": 0, "error": None},
    )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_device_sweep(app_ctx)

    assert cache_mod.get_summary()["hygiene_score"] == 87.3


def test_run_device_sweep_pending_count_is_none_when_pending_cache_not_ok(monkeypatch, app_ctx):
    # Even if get_all_cached_devices() would return data, an unavailable
    # pending-status cache (not yet run, or errored) must not be trusted —
    # reporting 0 pending diffs in that case would fabricate a number.
    monkeypatch.setattr(
        "app.app_settings.get_setting", lambda key, default=None: default
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_all_cached_devices",
        lambda: {"Customer1": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}]},
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_cache_status",
        lambda: {"status": "pending", "last_updated": None, "adoms_cached": 0, "error": None},
    )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_device_sweep(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["status"] == "ok"
    assert summary["pending_config_diff_count"] is None


def test_run_device_sweep_only_counts_non_forti_adoms(monkeypatch, app_ctx):
    monkeypatch.setattr(
        "app.app_settings.get_setting", lambda key, default=None: default
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_all_cached_devices", lambda: {}
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_cache_status",
        lambda: {"status": "ok", "last_updated": None, "adoms_cached": 0, "error": None},
    )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_device_sweep(app_ctx)

    # get_devices must only be called for "Customer1", not "FortiForticloud"
    assert fake_client.get_devices.call_count == 1
    fake_client.get_devices.assert_called_with("Customer1")


def test_run_device_sweep_sets_error_status_on_exception(monkeypatch, app_ctx):
    with patch("app.fmg_helpers.make_client", side_effect=RuntimeError("boom")):
        result = cache_mod._run_device_sweep(app_ctx)

    assert result is False
    summary = cache_mod.get_summary()
    assert summary["status"] == "error"
    assert "boom" in summary["error"]


def test_run_device_sweep_skips_when_already_running():
    cache_mod._device_running.set()
    try:
        result = cache_mod._run_device_sweep(None)
    finally:
        cache_mod._device_running.clear()
    assert result is False


# ── _run_hygiene_sweep ───────────────────────────────────────────────────────


def test_run_hygiene_sweep_populates_hygiene_score_only(app_ctx):
    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        result = cache_mod._run_hygiene_sweep(app_ctx)

    assert result is True
    summary = cache_mod.get_summary()
    assert summary["status"] == "ok"
    assert summary["hygiene_score"] is not None
    assert summary["last_updated"] is not None
    # The hygiene sweep never touches device-sweep fields.
    assert summary["firewall_online_count"] is None
    assert summary["firewalls_total"] is None
    assert summary["version_compliance_pct"] is None
    assert summary["pending_config_diff_count"] is None
    fake_client.get_devices.assert_not_called()


def test_run_hygiene_sweep_preserves_existing_device_fields(app_ctx):
    with cache_mod._lock:
        cache_mod._store.update(
            {
                "firewall_online_count": 5,
                "firewalls_total": 6,
                "version_compliance_pct": 90.0,
                "pending_config_diff_count": 2,
            }
        )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_hygiene_sweep(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["firewall_online_count"] == 5
    assert summary["firewalls_total"] == 6
    assert summary["version_compliance_pct"] == 90.0
    assert summary["pending_config_diff_count"] == 2


def test_run_hygiene_sweep_only_counts_non_forti_adoms(app_ctx):
    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_hygiene_sweep(app_ctx)

    assert fake_client.get_policy_packages.call_count == 1
    fake_client.get_policy_packages.assert_called_with("Customer1")


def test_run_hygiene_sweep_sets_error_status_on_exception():
    with patch("app.fmg_helpers.make_client", side_effect=RuntimeError("boom")):
        result = cache_mod._run_hygiene_sweep(None)

    assert result is False
    summary = cache_mod.get_summary()
    assert summary["status"] == "error"
    assert "boom" in summary["error"]


def test_run_hygiene_sweep_skips_when_already_running():
    cache_mod._hygiene_running.set()
    try:
        result = cache_mod._run_hygiene_sweep(None)
    finally:
        cache_mod._hygiene_running.clear()
    assert result is False


def test_run_hygiene_sweep_stores_rule_count_total(app_ctx):
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}]
    client.get_devices.return_value = [{"name": "fw1"}]
    client.get_policy_packages.return_value = [{"name": "default", "path": "default"}]
    client.get_policies.return_value = [{"policyid": 1}, {"policyid": 2}, {"policyid": 3}]
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []

    with patch("app.fmg_helpers.make_client", return_value=client):
        cache_mod._run_hygiene_sweep(app_ctx)

    assert cache_mod.get_summary()["rule_count_total"] == 3


def test_run_hygiene_sweep_computes_and_persists_rule_hygiene_rollup(app_ctx, tmp_path, monkeypatch):
    import app.hygiene_rollup as hygiene_rollup

    monkeypatch.setattr(hygiene_rollup, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json")

    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}]
    client.get_devices.return_value = [{"name": "fw1"}]
    client.get_policy_packages.return_value = [{"name": "default", "path": "default"}]
    client.get_policies.return_value = [
        {"policyid": 1, "name": "", "logtraffic": "disable"},
        {"policyid": 2, "name": "rule2"},
    ]
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []

    with patch("app.fmg_helpers.make_client", return_value=client):
        cache_mod._run_hygiene_sweep(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["rule_hygiene"]["rule_findings_total"] >= 0
    assert set(summary["rule_hygiene"]["rule_findings_by_type"]) == {
        "shadow", "unhit", "unlogged", "expired", "disabled", "unnamed", "unused_objects",
    }
    assert summary["rule_hygiene"]["collected_at"] is not None
    assert hygiene_rollup.get_latest()["rule_findings_total"] == summary["rule_hygiene"]["rule_findings_total"]


def _multi_package_client(policies_by_pkg, addresses):
    """Client whose single ADOM has two packages with distinct policies."""
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}]
    client.get_policy_packages.return_value = [
        {"name": "pkgA", "path": "pkgA"},
        {"name": "pkgB", "path": "pkgB"},
    ]
    client.get_policies.side_effect = lambda adom, pkg: policies_by_pkg[pkg]
    client.get_address_objects.return_value = addresses
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []
    return client


def test_hygiene_sweep_fetches_object_lists_once_per_adom_not_per_package(app_ctx):
    """ADOM-scoped object fetches must not be repeated for every package."""
    client = _multi_package_client(
        {
            "pkgA": [{"policyid": 1, "name": "a", "srcaddr": ["addr-a"]}],
            "pkgB": [{"policyid": 2, "name": "b", "srcaddr": ["addr-b"]}],
        },
        addresses=[{"name": "addr-a"}, {"name": "addr-b"}, {"name": "addr-orphan"}],
    )

    with patch("app.fmg_helpers.make_client", return_value=client):
        cache_mod._run_hygiene_sweep(app_ctx)

    assert client.get_address_objects.call_count == 1
    assert client.get_address_groups.call_count == 1
    assert client.get_service_objects.call_count == 1
    assert client.get_service_groups.call_count == 1
    # Both packages' policies were still read.
    assert client.get_policies.call_count == 2


def test_hygiene_sweep_unused_objects_is_fleet_wide_not_summed_per_package(app_ctx):
    """addr-a/addr-b are each used by one package; only addr-orphan is unused.

    Per-package accounting would count addr-b unused in pkgA and addr-a unused
    in pkgB, plus addr-orphan twice — 4 instead of 1.
    """
    client = _multi_package_client(
        {
            "pkgA": [{"policyid": 1, "name": "a", "srcaddr": ["addr-a"]}],
            "pkgB": [{"policyid": 2, "name": "b", "srcaddr": ["addr-b"]}],
        },
        addresses=[{"name": "addr-a"}, {"name": "addr-b"}, {"name": "addr-orphan"}],
    )

    with patch("app.fmg_helpers.make_client", return_value=client):
        cache_mod._run_hygiene_sweep(app_ctx)

    by_type = cache_mod.get_summary()["rule_hygiene"]["rule_findings_by_type"]
    assert by_type["unused_objects"] == 1


def test_device_sweep_error_does_not_affect_hygiene_sweep_status(app_ctx):
    import app.executive_summary_cache as cache_mod

    # A prior successful hygiene sweep already set hygiene_sweep_status ok.
    with cache_mod._lock:
        cache_mod._store["hygiene_sweep_status"] = "ok"
        cache_mod._store["hygiene_sweep_collected_at"] = "2026-08-28T09:00:00Z"

    with patch("app.fmg_helpers.make_client", side_effect=RuntimeError("FMG down")):
        cache_mod._run_device_sweep(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["device_sweep_status"] == "error"
    assert summary["hygiene_sweep_status"] == "ok"


def test_run_device_sweep_sets_device_sweep_collected_at(app_ctx):
    import app.executive_summary_cache as cache_mod

    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}]
    client.get_devices.return_value = [{"name": "fw1", "conn_status": "up"}]

    with patch("app.fmg_helpers.make_client", return_value=client):
        cache_mod._run_device_sweep(app_ctx)

    assert cache_mod.get_summary()["device_sweep_collected_at"] is not None
