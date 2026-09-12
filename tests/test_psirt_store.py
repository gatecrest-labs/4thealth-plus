"""Tests for app.psirt_store — persistence, close/reopen, and the
executive-summary rollup math (mean days to remediate, device severity
counts, mitigated half-weighting, top_advisory selection)."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import datetime as dt

import pytest

from app import psirt_store


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(psirt_store, "_DB_PATH", tmp_path / "psirt_test.db")
    yield


def _assessment(
    advisory_id="FG-IR-24-001",
    priority="critical",
    cvss=9.8,
    kev=True,
    findings=None,
):
    if findings is None:
        findings = [
            {
                "device": "FW1",
                "adom": "Corp",
                "current_version": "7.4.3",
                "in_range": True,
                "workaround_status": "not_applicable",
                "verdict": "upgrade_required",
            }
        ]
    return {
        "advisory": {
            "advisory_id": advisory_id,
            "cve_ids": ["CVE-2024-0001"],
            "fortinet_severity": "Critical",
            "cvss_score": cvss,
            "affected_ranges": [
                {
                    "product": "FortiOS",
                    "min_version": "7.4.0",
                    "max_version": "7.4.3",
                    "fixed_version": "7.4.4",
                    "notes": "",
                }
            ],
            "workaround_text": "",
        },
        "findings": findings,
        "priority": priority,
        "priority_rationale": "test",
        "kev_hit": kev,
        "degraded": False,
        "warnings": [],
    }


# ── save / round-trip ────────────────────────────────────────────────────────


def test_save_and_get_advisory_round_trip():
    psirt_store.save_assessment_result(_assessment())
    adv = psirt_store.get_advisory("FG-IR-24-001")
    assert adv is not None
    assert adv["cves"] == ["CVE-2024-0001"]
    assert adv["cvss"] == 9.8
    assert adv["severity"] == "Critical"
    assert adv["kev"] is True
    assert adv["affected_ranges"][0]["product"] == "FortiOS"
    assert adv["closed_at"] is None
    assert adv["created_at"] is not None


def test_save_records_an_assessment_row():
    psirt_store.save_assessment_result(_assessment())
    latest = psirt_store.get_latest_assessment("FG-IR-24-001")
    assert latest is not None
    assert latest["devices_affected"] == [
        {"name": "FW1", "adom": "Corp", "version": "7.4.3", "workaround_applied": False}
    ]
    assert latest["summary"]["priority"] == "critical"


def test_devices_affected_excludes_out_of_range_findings():
    findings = [
        {"device": "FW1", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
         "workaround_status": "not_applicable", "verdict": "upgrade_required"},
        {"device": "FW2", "adom": "Corp", "current_version": "7.6.1", "in_range": False,
         "workaround_status": "not_applicable", "verdict": "no_action"},
    ]
    psirt_store.save_assessment_result(_assessment(findings=findings))
    latest = psirt_store.get_latest_assessment("FG-IR-24-001")
    assert [d["name"] for d in latest["devices_affected"]] == ["FW1"]


def test_second_save_preserves_created_at_and_does_not_reopen():
    psirt_store.save_assessment_result(_assessment())
    first = psirt_store.get_advisory("FG-IR-24-001")
    psirt_store.close_advisory("FG-IR-24-001")

    psirt_store.save_assessment_result(_assessment())  # e.g. a scheduled re-run
    second = psirt_store.get_advisory("FG-IR-24-001")
    assert second["created_at"] == first["created_at"]
    assert second["closed_at"] is not None  # re-saving does not silently reopen


def test_save_refreshes_advisory_fields():
    psirt_store.save_assessment_result(_assessment(cvss=9.8, kev=True))
    psirt_store.save_assessment_result(_assessment(cvss=9.9, kev=True))
    adv = psirt_store.get_advisory("FG-IR-24-001")
    assert adv["cvss"] == 9.9


# ── close / reopen ───────────────────────────────────────────────────────────


def test_close_advisory_sets_closed_at():
    psirt_store.save_assessment_result(_assessment())
    assert psirt_store.close_advisory("FG-IR-24-001") is True
    adv = psirt_store.get_advisory("FG-IR-24-001")
    assert adv["closed_at"] is not None


def test_close_unknown_advisory_returns_false():
    assert psirt_store.close_advisory("does-not-exist") is False


def test_reopen_advisory():
    psirt_store.save_assessment_result(_assessment())
    psirt_store.close_advisory("FG-IR-24-001")
    assert psirt_store.reopen_advisory("FG-IR-24-001") is True
    adv = psirt_store.get_advisory("FG-IR-24-001")
    assert adv["closed_at"] is None


def test_get_open_advisories_excludes_closed():
    psirt_store.save_assessment_result(_assessment(advisory_id="A1"))
    psirt_store.save_assessment_result(_assessment(advisory_id="A2"))
    psirt_store.close_advisory("A1")
    open_ids = [a["advisory_id"] for a in psirt_store.get_open_advisories()]
    assert open_ids == ["A2"]


def test_list_advisories_merges_latest_assessment():
    psirt_store.save_assessment_result(_assessment(advisory_id="A1"))
    rows = psirt_store.list_advisories()
    assert rows[0]["advisory_id"] == "A1"
    assert rows[0]["latest_assessment"]["summary"]["priority"] == "critical"


def test_list_advisories_open_only():
    psirt_store.save_assessment_result(_assessment(advisory_id="A1"))
    psirt_store.save_assessment_result(_assessment(advisory_id="A2"))
    psirt_store.close_advisory("A1")
    rows = psirt_store.list_advisories(open_only=True)
    assert [r["advisory_id"] for r in rows] == ["A2"]


# ── mean days to remediate ───────────────────────────────────────────────────


def test_mean_days_to_remediate_none_when_nothing_closed():
    psirt_store.save_assessment_result(_assessment())
    assert psirt_store.compute_mean_days_to_remediate() is None


def test_mean_days_to_remediate_computes_average(monkeypatch):
    now = dt.datetime(2026, 9, 10, tzinfo=dt.UTC)
    psirt_store.save_assessment_result(_assessment(advisory_id="A1"))
    psirt_store.save_assessment_result(_assessment(advisory_id="A2"))

    conn = psirt_store._connect()
    conn.execute(
        "UPDATE advisories SET created_at=?, closed_at=? WHERE advisory_id=?",
        ((now - dt.timedelta(days=10)).isoformat(), now.isoformat(), "A1"),
    )
    conn.execute(
        "UPDATE advisories SET created_at=?, closed_at=? WHERE advisory_id=?",
        ((now - dt.timedelta(days=20)).isoformat(), now.isoformat(), "A2"),
    )
    conn.commit()
    conn.close()

    assert psirt_store.compute_mean_days_to_remediate(now) == 15.0


def test_mean_days_to_remediate_excludes_closures_older_than_90_days():
    now = dt.datetime(2026, 9, 10, tzinfo=dt.UTC)
    psirt_store.save_assessment_result(_assessment(advisory_id="A1"))

    conn = psirt_store._connect()
    conn.execute(
        "UPDATE advisories SET created_at=?, closed_at=? WHERE advisory_id=?",
        (
            (now - dt.timedelta(days=200)).isoformat(),
            (now - dt.timedelta(days=100)).isoformat(),
            "A1",
        ),
    )
    conn.commit()
    conn.close()

    assert psirt_store.compute_mean_days_to_remediate(now) is None


# ── compute_psirt_rollup ──────────────────────────────────────────────────────


def test_rollup_counts_devices_by_priority_band():
    psirt_store.save_assessment_result(
        _assessment(advisory_id="CRIT", priority="critical", kev=False, findings=[
            {"device": "FW1", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
             "workaround_status": "not_applicable", "verdict": "upgrade_required"},
            {"device": "FW2", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
             "workaround_status": "not_applicable", "verdict": "upgrade_required"},
        ])
    )
    psirt_store.save_assessment_result(
        _assessment(advisory_id="HIGH", priority="high", kev=False, findings=[
            {"device": "FW3", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
             "workaround_status": "not_applicable", "verdict": "upgrade_required"},
        ])
    )
    psirt_store.save_assessment_result(
        _assessment(advisory_id="MED", priority="medium", kev=False, findings=[
            {"device": "FW4", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
             "workaround_status": "not_applicable", "verdict": "upgrade_required"},
        ])
    )

    rollup = psirt_store.compute_psirt_rollup()
    assert rollup["open_advisories"] == 3
    assert rollup["devices_critical"] == 2
    assert rollup["devices_high"] == 1
    assert rollup["devices_medium"] == 1


def test_rollup_mitigated_devices_counted_at_half_weight_not_subtracted():
    psirt_store.save_assessment_result(
        _assessment(advisory_id="CRIT", priority="critical", kev=False, findings=[
            {"device": "FW1", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
             "workaround_status": "in_place", "verdict": "no_action"},
            {"device": "FW2", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
             "workaround_status": "not_applicable", "verdict": "upgrade_required"},
        ])
    )
    rollup = psirt_store.compute_psirt_rollup()
    # Both devices still count in devices_critical (never silently dropped) —
    # the mitigated one is separately surfaced, at half weight.
    assert rollup["devices_critical"] == 2
    assert rollup["devices_critical_mitigated"] == 0.5


def test_rollup_kev_exposed_devices_counts_distinct_devices():
    psirt_store.save_assessment_result(
        _assessment(advisory_id="KEV1", priority="critical", kev=True, findings=[
            {"device": "FW1", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
             "workaround_status": "not_applicable", "verdict": "upgrade_required"},
        ])
    )
    psirt_store.save_assessment_result(
        _assessment(advisory_id="NOTKEV", priority="high", kev=False, findings=[
            {"device": "FW2", "adom": "Corp", "current_version": "7.4.3", "in_range": True,
             "workaround_status": "not_applicable", "verdict": "upgrade_required"},
        ])
    )
    rollup = psirt_store.compute_psirt_rollup()
    assert rollup["kev_exposed_devices"] == 1


def test_rollup_top_advisory_prefers_highest_priority_then_cvss():
    psirt_store.save_assessment_result(
        _assessment(advisory_id="MED", priority="medium", cvss=6.0, kev=False)
    )
    psirt_store.save_assessment_result(
        _assessment(advisory_id="CRIT", priority="critical", cvss=9.8, kev=True)
    )
    rollup = psirt_store.compute_psirt_rollup()
    assert rollup["top_advisory"]["advisory_id"] == "CRIT"
    assert rollup["top_advisory"]["kev"] is True


def test_rollup_top_advisory_devices_lists_unmitigated_first():
    psirt_store.save_assessment_result(
        _assessment(advisory_id="FG-IR-24-001", priority="critical", cvss=9.8, kev=False, findings=[
            {"device": "fw-a", "adom": "root", "current_version": "v7.4.2", "in_range": True,
             "workaround_status": "in_place", "verdict": "no_action"},
            {"device": "fw-b", "adom": "root", "current_version": "v7.4.1", "in_range": True,
             "workaround_status": "not_applicable", "verdict": "upgrade_required"},
        ])
    )
    rollup = psirt_store.compute_psirt_rollup()
    assert rollup["top_advisory"]["device_count"] == 2
    assert rollup["top_advisory"]["devices"] == [
        {"device": "fw-b", "adom": "root", "version": "v7.4.1", "workaround_applied": False},
        {"device": "fw-a", "adom": "root", "version": "v7.4.2", "workaround_applied": True},
    ]


def test_rollup_closed_advisories_excluded():
    psirt_store.save_assessment_result(_assessment(advisory_id="A1"))
    psirt_store.close_advisory("A1")
    rollup = psirt_store.compute_psirt_rollup()
    assert rollup["open_advisories"] == 0
    assert rollup["devices_critical"] == 0
    assert rollup["top_advisory"] is None


def test_rollup_empty_store():
    rollup = psirt_store.compute_psirt_rollup()
    assert rollup["open_advisories"] == 0
    assert rollup["devices_critical"] == 0
    assert rollup["devices_critical_mitigated"] == 0.0
    assert rollup["kev_exposed_devices"] == 0
    assert rollup["top_advisory"] is None
    assert rollup["mean_days_to_remediate_90d"] is None
    assert "collected_at" in rollup
