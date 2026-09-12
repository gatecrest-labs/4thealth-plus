"""Tests for the rule-hygiene fleet rollup persistence."""

from __future__ import annotations

import app.hygiene_rollup as hygiene_rollup
from app.hygiene_rollup import build_details


def test_append_run_and_get_latest(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene_rollup, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json")

    record = {
        "ran_at": "2026-08-28T09:00:00Z",
        "rule_findings_total": 118,
        "rule_findings_by_type": {
            "shadow": 4, "unhit": 60, "unlogged": 12, "expired": 8,
            "disabled": 20, "unnamed": 6, "unused_objects": 8,
        },
    }
    hygiene_rollup.append_run(record)

    assert hygiene_rollup.get_latest() == record


def test_get_latest_returns_none_when_no_history(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene_rollup, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json")

    assert hygiene_rollup.get_latest() is None


def test_append_run_keeps_at_most_30_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene_rollup, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json")

    for i in range(35):
        hygiene_rollup.append_run({"ran_at": f"run-{i}", "rule_findings_total": i, "rule_findings_by_type": {}})

    history = hygiene_rollup.get_history()
    assert len(history) == 30
    assert history[0]["ran_at"] == "run-34"


def test_build_details_orders_by_finding_count_then_adom_then_package():
    package_findings = [
        {
            "package": "pkg-b",
            "adom": "root",
            "findings": [{"check": "unnamed", "policy_id": "1"}],
        },
        {
            "package": "pkg-a",
            "adom": "root",
            "findings": [
                {"check": "unnamed", "policy_id": "1"},
                {"check": "unlogged", "policy_id": "2"},
            ],
        },
        {"package": "pkg-c", "adom": "root", "findings": []},
    ]

    details = build_details(package_findings)

    assert details == [
        {
            "package": "pkg-a",
            "adom": "root",
            "findings": [
                {"check": "unnamed", "policy_id": "1"},
                {"check": "unlogged", "policy_id": "2"},
            ],
        },
        {
            "package": "pkg-b",
            "adom": "root",
            "findings": [{"check": "unnamed", "policy_id": "1"}],
        },
    ]


def test_build_details_caps_at_50():
    package_findings = [
        {
            "package": f"pkg-{i:03d}",
            "adom": "root",
            "findings": [{"check": "unnamed", "policy_id": str(i)}],
        }
        for i in range(60)
    ]

    details = build_details(package_findings)

    assert len(details) == 50
