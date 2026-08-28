"""Tests for GET /external/api/executive/summary."""
import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import patch

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app(test_config={"TESTING": True})
    with app.test_client() as c:
        yield c


def test_returns_503_when_feature_disabled(client):
    with patch("app.routes.external_api_routes.get_setting", return_value=False):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer whatever"},
        )
    assert resp.status_code == 503


def test_returns_401_when_no_token(client):
    with patch("app.routes.external_api_routes.get_setting", return_value=True):
        resp = client.get("/external/api/executive/summary")
    assert resp.status_code == 401


def test_returns_401_when_invalid_token(client):
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch("app.routes.external_api_routes.validate_token", return_value=None),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer bad-token"},
        )
    assert resp.status_code == 401


def test_returns_summary_payload_when_authorized(client):
    fake_summary = {
        "hygiene_score": 87.3,
        "version_compliance_pct": 91.2,
        "pending_config_diff_count": 4,
        "firewall_online_count": 212,
        "firewalls_total": 218,
        "adom_count": 3,
        "rule_count_total": 5120,
        "status": "ok",
        "error": None,
        "last_updated": "2026-08-24T15:00:00+00:00",
    }
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch(
            "app.versions_cache.get_cached",
            return_value={
                "devices": [
                    {"name": "fw1", "version": "v7.4.5"},
                    {"name": "fw2", "version": "v7.4.5"},
                    {"name": "fw3", "version": "v7.2.9"},
                ]
            },
        ),
        patch(
            "app.backup_scheduler.get_all_jobs",
            return_value=[
                {
                    "id": "job1",
                    "runs": [{"started_at": "2026-08-27T01:00:00Z", "status": "success"}],
                }
            ],
        ),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["hygiene_score"] == 87.3
    assert data["firewall_online_count"] == 212
    assert data["firewall_managed_count"] == 218
    assert data["adom_count"] == 3
    assert data["rule_count_total"] == 5120
    assert data["version_breakdown"] == {"v7.4.5": {"count": 2, "eol": False}, "v7.2.9": {"count": 1, "eol": False}}
    assert data["last_backup_status"] == "ok"
    assert data["ai_enabled"] is True
    assert "ai_usage_24h" in data
    assert "error" not in data


def test_ai_usage_omitted_when_ai_assist_disabled(client):
    fake_summary = {"status": "ok", "last_updated": None}

    def fake_get_setting(key, default=None):
        return {"external_api_enabled": True, "ai_assist_enabled": False}.get(
            key, default
        )

    with (
        patch(
            "app.routes.external_api_routes.get_setting", side_effect=fake_get_setting
        ),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch("app.summary_job.get_summary", return_value={}),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ai_enabled"] is False
    assert "ai_usage_24h" not in data
    assert data["last_backup_status"] is None
    assert data["version_breakdown"] == {}


def test_rule_count_total_sourced_from_executive_summary_cache_not_summary_job(client):
    fake_summary = {"status": "ok", "last_updated": None, "rule_count_total": 14203}
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    assert resp.status_code == 200
    assert resp.get_json()["rule_count_total"] == 14203


def test_version_breakdown_annotates_eol_versions(client):
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value={"status": "ok"}),
        patch(
            "app.versions_cache.get_cached",
            return_value={"devices": [
                {"name": "fw1", "version": "v7.4.5"},
                {"name": "fw2", "version": "v6.4.2"},
            ]},
        ),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["version_breakdown"] == {
        "v7.4.5": {"count": 1, "eol": False},
        "v6.4.2": {"count": 1, "eol": True},
    }


def test_payload_includes_schema_version_and_split_freshness(client):
    fake_summary = {
        "status": "ok", "last_updated": "2026-08-28T09:45:00Z",
        "device_sweep_status": "ok", "hygiene_sweep_status": "ok",
        "device_sweep_collected_at": "2026-08-28T09:45:00Z",
        "hygiene_sweep_collected_at": "2026-08-28T09:00:00Z",
        "rule_count_total": 14203,
    }
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["schema_version"] == 1
    assert data["device_sweep_status"] == "ok"
    assert data["hygiene_sweep_status"] == "ok"
    assert data["device_sweep_collected_at"] == "2026-08-28T09:45:00Z"
    assert data["hygiene_sweep_collected_at"] == "2026-08-28T09:00:00Z"
    assert data["rule_count_collected_at"] == "2026-08-28T09:00:00Z"
    assert data["status"] == "ok"  # deprecated alias, still present


def test_payload_includes_device_review_and_rule_hygiene_rollups(client):
    fake_summary = {
        "status": "ok",
        "rule_hygiene": {
            "rule_findings_total": 118,
            "rule_findings_by_type": {"shadow": 4, "unhit": 60},
            "collected_at": "2026-08-28T09:00:00Z",
        },
    }
    fake_dr_rollup = {
        "ran_at": "2026-08-28T06:00:00Z",
        "devices_reviewed": 42,
        "devices_with_failures": 7,
        "findings_by_severity": {"critical": 1, "high": 3, "medium": 9, "low": 4},
        "top_failing_checks": [{"check": "default_admin", "count": 5}],
    }
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
        patch("app.device_review_rollup.get_latest", return_value=fake_dr_rollup),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["rule_hygiene"]["rule_findings_total"] == 118
    assert data["device_review"]["devices_reviewed"] == 42
    assert data["device_review"]["collected_at"] == "2026-08-28T06:00:00Z"


def test_payload_device_review_none_when_no_rollup_yet(client):
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value={"status": "ok"}),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
        patch("app.device_review_rollup.get_latest", return_value=None),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["device_review"] is None
    assert data["rule_hygiene"] is None
