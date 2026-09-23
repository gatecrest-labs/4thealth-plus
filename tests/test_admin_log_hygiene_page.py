"""Smoke test for the Admin -> Log Hygiene sub-tab markup on GET /admin."""

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
    with (
        app.test_client() as c,
        patch("app.auth._load_users", return_value=_TEST_USERS),
    ):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def test_admin_page_contains_log_hygiene_markup(client):
    resp = client.get("/admin/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'id="panel-log-hygiene"' in html
    assert 'id="logSourceBaseUrl"' in html
    assert 'id="logSourceToken"' in html
    assert 'id="btnSaveLogSource"' in html
    assert 'id="btnTestLogSource"' in html
    assert 'data-panel="log-hygiene"' in html
