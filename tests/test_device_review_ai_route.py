"""Tests for POST /api/audit-review/ai-summary."""
import json
import time
from unittest.mock import patch

import pytest


@pytest.fixture
def app():
    from app import create_app
    return create_app()


_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def client(app):
    with app.test_client() as c, \
         patch("app.auth._load_users", return_value=_TEST_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def _post(client, url, payload):
    return client.post(
        url, data=json.dumps(payload), content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )


def test_ai_summary_disabled_returns_503(client):
    with patch("app.app_settings.get_setting", return_value=False):
        resp = _post(client, "/api/audit-review/ai-summary", {
            "adom": "CorpADOM", "results": [{"device": "fw-01", "rows": [], "error": None}],
        })
    assert resp.status_code == 503


def test_ai_summary_missing_results_returns_400(client):
    with patch("app.app_settings.get_setting", return_value=True):
        resp = _post(client, "/api/audit-review/ai-summary", {"adom": "CorpADOM"})
    assert resp.status_code == 400


def test_ai_summary_success(client):
    fake_results = [
        {"device": "fw-01", "rows": [
            {"device": "fw-01", "check": "Trusted Hosts on Admin Accounts (CIS)",
             "result": "FAIL", "interface": "system", "vdom": "", "ip": "",
             "detail": "no restriction"},
        ], "error": None},
    ]
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.device_review_ai.build_narrative", return_value="Summary text") as mock_build:
        resp = _post(client, "/api/audit-review/ai-summary", {
            "adom": "CorpADOM", "results": fake_results, "checks": ["trusted_hosts"],
        })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["narrative"] == "Summary text"
    assert data["narrative_error"] is None
    mock_build.assert_called_once()


def test_ai_summary_malformed_results_returns_400(client):
    with patch("app.app_settings.get_setting", return_value=True):
        resp = _post(client, "/api/audit-review/ai-summary", {
            "adom": "CorpADOM", "results": ["not-a-dict"],
        })
    assert resp.status_code == 400
    data = resp.get_json()
    assert "results" in data["error"]


def test_ai_summary_narration_failure_returns_200_with_error(client):
    fake_results = [{"device": "fw-01", "rows": [], "error": None}]
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.device_review_ai.build_narrative", side_effect=RuntimeError("API down")):
        resp = _post(client, "/api/audit-review/ai-summary", {
            "adom": "CorpADOM", "results": fake_results,
        })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["narrative"] is None
    assert data["narrative_error"] == "API down"
