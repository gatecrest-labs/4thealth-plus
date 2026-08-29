"""Tests for POST /api/hygiene/explain-finding."""
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


def test_explain_disabled_returns_503(client):
    with patch("app.app_settings.get_setting", return_value=False):
        resp = _post(client, "/api/hygiene/explain-finding", {
            "check": "unlogged", "policy_name": "Allow-Web", "policy_id": "42",
            "detail": "logtraffic disabled", "rule_detail": {},
        })
    assert resp.status_code == 503


def test_explain_missing_check_returns_400(client):
    with patch("app.app_settings.get_setting", return_value=True):
        resp = _post(client, "/api/hygiene/explain-finding", {"detail": "x"})
    assert resp.status_code == 400


def test_explain_non_dict_body_returns_400(client):
    with patch("app.app_settings.get_setting", return_value=True):
        resp = _post(client, "/api/hygiene/explain-finding", [1])
    assert resp.status_code == 400


def test_explain_success(client):
    finding = {
        "check": "unlogged", "policy_name": "Allow-Web", "policy_id": "42",
        "detail": "logtraffic disabled", "rule_detail": {"name": "Allow-Web"},
    }
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.hygiene_ai.explain_finding", return_value="Explanation text.") as mock_explain:
        resp = _post(client, "/api/hygiene/explain-finding", finding)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["narrative"] == "Explanation text."
    assert data["narrative_error"] is None
    mock_explain.assert_called_once_with(finding, user="admin")


def test_explain_failure_returns_200_with_error(client):
    finding = {"check": "unlogged", "policy_name": "Allow-Web", "policy_id": "42",
               "detail": "x", "rule_detail": {}}
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.hygiene_ai.explain_finding", side_effect=RuntimeError("API down")):
        resp = _post(client, "/api/hygiene/explain-finding", finding)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["narrative"] is None
    assert data["narrative_error"] == "API down"
