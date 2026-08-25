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
        patch(
            "app.executive_summary_cache.get_summary", return_value=fake_summary
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
    assert "last_backup_status" not in data
    assert "error" not in data
