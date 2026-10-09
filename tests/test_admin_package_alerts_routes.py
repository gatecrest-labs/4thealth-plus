"""Tests for /admin/api/package-alerts/* endpoints in admin_routes.py."""

import json
import os
import time
from unittest import mock

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")

_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def app():
    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_session(client):
    """Set up an admin session on the client and mock user lookup."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["_csrf_token"] = "test-csrf"
        sess["login_at"] = int(time.time())
    with mock.patch("app.auth._load_users", return_value=_TEST_USERS):
        yield


# ── Helpers ───────────────────────────────────────────────────────────────────


def _csrf():
    return {"X-CSRF-Token": "test-csrf"}


def _post(client, url, payload=None):
    kwargs = {"headers": _csrf()}
    if payload is not None:
        kwargs["data"] = json.dumps(payload)
        kwargs["content_type"] = "application/json"
    return client.post(url, **kwargs)


def _put(client, url, payload=None):
    kwargs = {"headers": _csrf()}
    if payload is not None:
        kwargs["data"] = json.dumps(payload)
        kwargs["content_type"] = "application/json"
    return client.put(url, **kwargs)


def _delete(client, url):
    return client.delete(url, headers=_csrf())


@pytest.fixture(autouse=True)
def tmp_rules(tmp_path, monkeypatch):
    import app.package_change_alerts as pca

    monkeypatch.setattr(pca, "_RULES_PATH", tmp_path / "package_change_alerts.json")
    yield


def _valid_rule(**overrides):
    base = {
        "name": "Owners",
        "adom": "Corp",
        "packages": [],
        "email": "a@b.com",
        "format": "html",
        "enabled": True,
    }
    base.update(overrides)
    return base


def test_list_empty(client, admin_session):
    resp = client.get("/admin/api/package-alerts/rules")
    assert resp.status_code == 200 and resp.get_json() == []


def test_create_list_update_delete(client, admin_session):
    resp = _post(client, "/admin/api/package-alerts/rules", _valid_rule())
    assert resp.status_code == 201
    rid = resp.get_json()["id"]
    assert len(client.get("/admin/api/package-alerts/rules").get_json()) == 1
    resp = _put(
        client, f"/admin/api/package-alerts/rules/{rid}", _valid_rule(name="New")
    )
    assert resp.status_code == 200 and resp.get_json()["name"] == "New"
    assert _delete(client, f"/admin/api/package-alerts/rules/{rid}").status_code == 200
    assert client.get("/admin/api/package-alerts/rules").get_json() == []


def test_create_invalid_returns_400(client, admin_session):
    resp = _post(client, "/admin/api/package-alerts/rules", _valid_rule(email=""))
    assert resp.status_code == 400 and "email" in resp.get_json()["error"]


def test_update_and_delete_missing_return_404(client, admin_session):
    assert (
        _put(client, "/admin/api/package-alerts/rules/x", _valid_rule()).status_code
        == 404
    )
    assert _delete(client, "/admin/api/package-alerts/rules/x").status_code == 404
    assert _post(client, "/admin/api/package-alerts/rules/x/test").status_code == 404


def test_test_email_success_and_smtp_error(client, admin_session):
    rid = _post(client, "/admin/api/package-alerts/rules", _valid_rule()).get_json()[
        "id"
    ]
    with mock.patch("app.package_change_alerts._send_email") as send:
        assert (
            _post(client, f"/admin/api/package-alerts/rules/{rid}/test").status_code
            == 200
        )
        assert send.called
    with mock.patch(
        "app.package_change_alerts._send_email",
        side_effect=RuntimeError("SMTP not enabled"),
    ):
        resp = _post(client, f"/admin/api/package-alerts/rules/{rid}/test")
        assert resp.status_code == 400 and "SMTP" in resp.get_json()["error"]


def test_endpoints_require_admin(client):
    assert client.get("/admin/api/package-alerts/rules").status_code in (302, 401, 403)


def test_admin_page_contains_package_alerts_ui(client, admin_session):
    resp = client.get("/admin/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'id="pca-rules-tbody"' in body
    assert 'id="pca-modal"' in body
