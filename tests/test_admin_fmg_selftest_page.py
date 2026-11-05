"""Smoke test for the Admin -> API Self-Test sub-tab markup on GET /admin."""

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


def test_admin_page_contains_selftest_markup(client):
    html = client.get("/admin/").get_data(as_text=True)
    assert 'data-panel="api-selftest"' in html
    assert 'id="panel-api-selftest"' in html
    assert 'id="btnFmgSelftest"' in html
    assert 'id="fmgSelftestResult"' in html


def test_selftest_panel_does_not_run_on_page_load(client):
    """The self-test makes live FMG calls, so it must only run on an explicit click."""
    js = client.get("/static/js/admin.js").get_data(as_text=True)
    assert "runFmgSelftest" in js
    # wired only through the button's click listener, never from the tab switcher
    assert "data-panel === 'api-selftest'" not in js
    assert "dataset.panel === 'api-selftest'" not in js
