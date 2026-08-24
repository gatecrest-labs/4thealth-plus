"""Unit tests for the pure aggregation functions in app.executive_summary_cache."""
import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import pytest

from app.executive_summary_cache import (
    _classify_online,
    _device_version,
    _hygiene_score,
    _pending_diff_count,
    _version_compliance_pct,
)


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


# ── _run_job (mocked FMG client) ────────────────────────────────────────────

from unittest.mock import MagicMock, patch

import app.executive_summary_cache as cache_mod


@pytest.fixture(autouse=True)
def _reset_store():
    with cache_mod._lock:
        cache_mod._store.update({
            "hygiene_score": None,
            "version_compliance_pct": None,
            "pending_config_diff_count": None,
            "firewall_online_count": None,
            "firewalls_total": None,
            "status": "pending",
            "error": None,
            "last_updated": None,
        })
    yield


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
    return client


def test_run_job_populates_store_from_mocked_fmg(monkeypatch, app_ctx):
    monkeypatch.setattr(
        "app.app_settings.get_setting",
        lambda key, default=None: ["v7.4.3"] if key == "executive_compliant_versions" else default,
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_all_cached_devices",
        lambda: {"Customer1": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}]},
    )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_job(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["status"] == "ok"
    assert summary["firewalls_total"] == 2
    assert summary["firewall_online_count"] == 1
    assert summary["version_compliance_pct"] == 100.0  # both devices are v7.4.3
    assert summary["pending_config_diff_count"] == 1
    assert summary["hygiene_score"] is not None
    assert summary["last_updated"] is not None


def test_run_job_only_counts_non_forti_adoms(monkeypatch, app_ctx):
    monkeypatch.setattr(
        "app.app_settings.get_setting", lambda key, default=None: default
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_all_cached_devices", lambda: {}
    )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_job(app_ctx)

    # get_devices/get_policy_packages must only be called for "Customer1",
    # not "FortiForticloud"
    assert fake_client.get_devices.call_count == 1
    fake_client.get_devices.assert_called_with("Customer1")


def test_run_job_sets_error_status_on_exception(monkeypatch, app_ctx):
    with patch("app.fmg_helpers.make_client", side_effect=RuntimeError("boom")):
        cache_mod._run_job(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["status"] == "error"
    assert "boom" in summary["error"]
