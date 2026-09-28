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


def _put(client, url, payload):
    return client.put(
        url, data=json.dumps(payload), content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )


def test_get_log_source_masks_token(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({
        "enabled": True, "base_url": "https://4tlog:5443",
        "token": "real-secret", "verify_ssl": True,
    })
    resp = client.get("/admin/api/log-source")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["token"] == "••••••"
    assert data["base_url"] == "https://4tlog:5443"


def test_get_log_source_empty_token_stays_empty(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    resp = client.get("/admin/api/log-source")
    assert resp.get_json()["token"] == ""


def test_put_log_source_saves_new_token(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    resp = _put(client, "/admin/api/log-source", {
        "enabled": True, "base_url": "https://4tlog:5443",
        "token": "brand-new-token", "verify_ssl": False,
    })
    assert resp.status_code == 200
    cfg = log_source.load_log_source_config()
    assert cfg["token"] == "brand-new-token"
    assert cfg["verify_ssl"] is False


def test_put_log_source_masked_placeholder_preserves_existing_token(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({
        "enabled": True, "base_url": "https://old:5443",
        "token": "original-token", "verify_ssl": True,
    })
    _put(client, "/admin/api/log-source", {
        "enabled": True, "base_url": "https://new:5443",
        "token": "••••••", "verify_ssl": True,
    })
    cfg = log_source.load_log_source_config()
    assert cfg["token"] == "original-token"
    assert cfg["base_url"] == "https://new:5443"


def test_log_source_test_connection_route(client):
    with patch("app.log_usage_client.test_connection", return_value={"ok": True, "error": None}):
        resp = client.post("/admin/api/log-source/test",
                            headers={"X-CSRF-Token": "test-csrf"})
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True, "error": None}


def test_log_source_routes_require_admin(app):
    non_admin_users = {"viewer": {"password_hash": "$2b$12$placeholder", "role": "viewer"}}
    with app.test_client() as c, patch("app.auth._load_users", return_value=non_admin_users):
        with c.session_transaction() as sess:
            sess["user"] = "viewer"
            sess["role"] = "viewer"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        resp = c.get("/admin/api/log-source")
    assert resp.status_code in (302, 403)
