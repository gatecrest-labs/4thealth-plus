"""Tests for /admin/api/naming-standards* routes."""
import time
from unittest.mock import patch

import pytest

from app import create_app
from app.naming_standards import NamingValidationError


@pytest.fixture
def admin_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def test_get_naming_standards_returns_current_naming(admin_client):
    fake = {"platforms": {"fortigate": {"conventions": {}}}}
    with patch("app.routes.admin_routes.get_naming", return_value=fake):
        resp = admin_client.get("/admin/api/naming-standards")
    assert resp.status_code == 200
    assert resp.get_json()["naming"] == fake


def test_put_naming_standards_saves_valid_data(admin_client):
    body = {"naming": {"platforms": {"fortigate": {"conventions": {}}}}}
    with patch("app.routes.admin_routes.save_naming") as mock_save:
        resp = admin_client.put(
            "/admin/api/naming-standards",
            json=body,
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
    mock_save.assert_called_once_with(body["naming"])


def test_put_naming_standards_returns_400_on_validation_error(admin_client):
    body = {"naming": {"platforms": {"fortigate": {"conventions": {}}}}}
    with patch(
        "app.routes.admin_routes.save_naming",
        side_effect=NamingValidationError(["host: pattern is empty or missing"]),
    ):
        resp = admin_client.put(
            "/admin/api/naming-standards",
            json=body,
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["ok"] is False
    assert "host: pattern is empty or missing" in data["errors"]


def test_put_naming_standards_requires_naming_key(admin_client):
    resp = admin_client.put(
        "/admin/api/naming-standards",
        json={},
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 400


def test_post_naming_standards_reset(admin_client):
    fake = {"platforms": {"fortigate": {"conventions": {}}}}
    with patch("app.routes.admin_routes.reset_to_default") as mock_reset, \
         patch("app.routes.admin_routes.get_naming", return_value=fake):
        resp = admin_client.post(
            "/admin/api/naming-standards/reset",
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["naming"] == fake
    mock_reset.assert_called_once()


def test_post_naming_standards_parse_valid_yaml(admin_client):
    resp = admin_client.post(
        "/admin/api/naming-standards/parse",
        json={"yaml_text": "platforms:\n  fortigate:\n    conventions:\n      host:\n        pattern: \"H_<IP_ADDRESS>\"\n"},
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["naming"]["platforms"]["fortigate"]["conventions"]["host"]["pattern"] == "H_<IP_ADDRESS>"


def test_post_naming_standards_parse_invalid_yaml_returns_400(admin_client):
    resp = admin_client.post(
        "/admin/api/naming-standards/parse",
        json={"yaml_text": "not: valid: yaml: [unbalanced"},
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_post_naming_standards_parse_requires_yaml_text(admin_client):
    resp = admin_client.post(
        "/admin/api/naming-standards/parse",
        json={},
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 400


def test_naming_standards_routes_require_admin():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["user"] = "viewer"
            sess["role"] = "viewer"
            sess["login_at"] = int(time.time())
        resp = c.get("/admin/api/naming-standards")
    assert resp.status_code in (302, 403)
