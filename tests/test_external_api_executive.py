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
            "app.summary_job.get_summary", return_value={"rules_total": 5120}
        ),
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
    assert data["version_breakdown"] == {"v7.4.5": 2, "v7.2.9": 1}
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
