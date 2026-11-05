"""Tests for POST /admin/api/fmg-selftest."""

import time
from unittest.mock import patch

import pytest


@pytest.fixture
def app():
    from app import create_app

    return create_app()


_USERS = {
    "admin": {"password_hash": "$2b$12$placeholder", "role": "admin"},
    "viewer": {"password_hash": "$2b$12$placeholder", "role": "viewer"},
}


def _client(app, user):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user"] = user
        sess["role"] = _USERS[user]["role"]
        sess["_csrf_token"] = "test-csrf"
        sess["login_at"] = int(time.time())
    return c


REPORT = {
    "fmg_version": "8.0.2",
    "train": "8.0",
    "sample": {},
    "summary": {"ok": 1, "denied": 0, "error": 0, "skipped": 0},
    "checks": [],
}


def test_admin_gets_report(app):
    c = _client(app, "admin")
    with (
        patch("app.auth._load_users", return_value=_USERS),
        patch("app.fmg_selftest.run_selftest", return_value=REPORT) as run,
        patch("app.fmg_helpers.make_client") as mk,
    ):
        resp = c.post("/admin/api/fmg-selftest", headers={"X-CSRF-Token": "test-csrf"})
    assert resp.status_code == 200
    assert resp.get_json()["fmg_version"] == "8.0.2"
    run.assert_called_once()
    mk.return_value.__enter__.assert_called_once()  # client used as a context manager


def test_non_admin_is_forbidden(app):
    c = _client(app, "viewer")
    with patch("app.auth._load_users", return_value=_USERS):
        resp = c.post("/admin/api/fmg-selftest", headers={"X-CSRF-Token": "test-csrf"})
    assert resp.status_code in (401, 403)


def test_get_not_allowed(app):
    c = _client(app, "admin")
    with patch("app.auth._load_users", return_value=_USERS):
        resp = c.get("/admin/api/fmg-selftest")
    assert resp.status_code == 405


def test_unreachable_fmg_returns_502_json_not_500(app):
    c = _client(app, "admin")
    with (
        patch("app.auth._load_users", return_value=_USERS),
        patch("app.fmg_helpers.make_client", side_effect=RuntimeError("no host")),
    ):
        resp = c.post("/admin/api/fmg-selftest", headers={"X-CSRF-Token": "test-csrf"})
    assert resp.status_code == 502
    assert "no host" in resp.get_json()["error"]
