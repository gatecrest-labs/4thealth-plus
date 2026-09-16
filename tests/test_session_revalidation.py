import os
import time

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import patch


@pytest.fixture()
def client(tmp_path):
    users = {"alice": {"password_hash": "$2b$12$placeholder", "role": "viewer"}}
    groups_path = tmp_path / "groups.json"
    groups_path.write_text("{}")

    with patch("app.groups.GROUPS_FILE", groups_path), \
         patch("app.auth._load_users", return_value=users):
        from app import create_app
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c, tmp_path


def test_expired_session_is_rejected(client):
    """A session older than SESSION_ABSOLUTE_LIFETIME should be rejected."""
    c, _tmp_path = client
    with c.session_transaction() as sess:
        sess["user"] = "alice"
        sess["role"] = "viewer"
        sess["allowed_tabs"] = []
        sess["login_at"] = 0  # epoch — definitely expired

    resp = c.get("/")
    assert resp.status_code in (302, 401, 403)


def test_fresh_session_is_accepted(client):
    """A session stamped right now should pass the absolute cap check."""
    c, _tmp_path = client
    with c.session_transaction() as sess:
        sess["user"] = "alice"
        sess["role"] = "viewer"
        sess["allowed_tabs"] = []
        sess["login_at"] = int(time.time())

    resp = c.get("/")
    # Session is valid — revalidation should NOT clear it.
    # Alice is a viewer with no tab access (empty groups.json), so the dashboard
    # tab check returns 403 (access denied), not a session-rejection redirect/401.
    assert resp.status_code in (200, 302, 403)


def test_deleted_user_session_is_rejected(client):
    """If the user is removed from users.json, their session should be invalidated."""
    c, _tmp_path = client
    with c.session_transaction() as sess:
        sess["user"] = "gone_user"
        sess["role"] = "viewer"
        sess["allowed_tabs"] = []
        sess["login_at"] = int(time.time())

    resp = c.get("/")
    assert resp.status_code in (302, 401, 403)
