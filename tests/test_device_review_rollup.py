"""Tests for device-review fleet rollup aggregation and persistence."""

from __future__ import annotations

import app.device_review_rollup as dr_rollup


def _row(device, check, result):
    return {
        "device": device, "interface": "", "vdom": "root", "ip": "10.0.0.1",
        "type": "system", "status": "", "check": check, "result": result,
        "detail": "", "protocols": [], "has_insecure": False, "has_secure": False,
    }


def test_build_rollup_counts_devices_and_severities(monkeypatch):
    monkeypatch.setattr(
        dr_rollup,
        "_name_to_key",
        {"Default 'admin' Account (CIS)": "default_admin", "DNS Servers (CIS)": "dns_servers"},
    )
    monkeypatch.setattr(dr_rollup, "_severity_for_key", lambda k: {"default_admin": "critical", "dns_servers": "low"}[k])

    results = [
        {
            "device": "fw-01", "ip": "10.0.0.1", "error": None,
            "rows": [_row("fw-01", "Default 'admin' Account (CIS)", "FAIL"), _row("fw-01", "DNS Servers (CIS)", "PASS")],
        },
        {
            "device": "fw-02", "ip": "10.0.0.2", "error": None,
            "rows": [_row("fw-02", "DNS Servers (CIS)", "PASS")],
        },
    ]

    rollup = dr_rollup.build_rollup(results)

    assert rollup["devices_reviewed"] == 2
    assert rollup["devices_with_failures"] == 1
    assert rollup["findings_by_severity"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert rollup["top_failing_checks"] == [{"check": "default_admin", "count": 1}]


def test_build_rollup_excludes_devices_with_errors_from_reviewed_count():
    results = [{"device": "fw-01", "ip": "10.0.0.1", "error": "timeout", "rows": []}]

    rollup = dr_rollup.build_rollup(results)

    assert rollup["devices_reviewed"] == 0
    assert rollup["devices_with_failures"] == 0


def test_append_run_and_get_latest(tmp_path, monkeypatch):
    monkeypatch.setattr(dr_rollup, "_ROLLUP_PATH", tmp_path / "device_review_rollup.json")

    record = {
        "ran_at": "2026-08-28T06:00:00Z", "devices_reviewed": 5, "devices_with_failures": 1,
        "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        "top_failing_checks": [{"check": "dns_servers", "count": 1}],
    }
    dr_rollup.append_run(record)

    assert dr_rollup.get_latest() == record
