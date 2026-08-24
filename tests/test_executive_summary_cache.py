"""Unit tests for the pure aggregation functions in app.executive_summary_cache."""
import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

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
