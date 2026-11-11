"""Tests for the Admin Executive Briefing routes."""

import json
import time
from unittest.mock import patch

import pytest

from app import executive_briefing_scheduler as sched

BASE = "/admin/api/executive-briefing"
_TEST_USERS = {
    "admin": {"password_hash": "$2b$12$placeholder", "role": "admin"},
    "viewer": {"password_hash": "$2b$12$placeholder", "role": "viewer"},
}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "executive_briefing.json")
    monkeypatch.setattr(sched, "_LOCK_PATH", tmp_path / "eb.lock")
    from app import create_app

    return create_app()


def _client(app, user, role):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user"] = user
        sess["role"] = role
        sess["_csrf_token"] = "test-csrf"
        sess["login_at"] = int(time.time())
    return c


@pytest.fixture
def client(app):
    with patch("app.auth._load_users", return_value=_TEST_USERS):
        yield _client(app, "admin", "admin")


def _send(client, method, url, payload=None):
    return client.open(
        url,
        method=method,
        data=json.dumps(payload) if payload is not None else None,
        content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )


VALID = {"enabled": True, "day": "TUE", "time": "06:30", "email": "a@b.c"}


def test_get_default_config(client):
    r = client.get(BASE)
    assert r.status_code == 200
    data = r.get_json()
    assert data["enabled"] is False and data["day"] == "MON"
    assert "last_payload" not in data


def test_put_valid_config(client):
    r = _send(client, "PUT", BASE, VALID)
    assert r.status_code == 200
    assert client.get(BASE).get_json()["day"] == "TUE"


@pytest.mark.parametrize(
    "body",
    [
        [],
        "x",
        dict(VALID, enabled="true"),
        dict(VALID, day="Monday"),
        dict(VALID, time="6:30"),
        dict(VALID, email=["a@b.c"]),
    ],
)
def test_put_invalid_config_400(client, body):
    r = _send(client, "PUT", BASE, body)
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_routes_require_admin(app):
    with patch("app.auth._load_users", return_value=_TEST_USERS):
        c = _client(app, "viewer", "viewer")
        assert c.get(BASE).status_code in (302, 403)
        assert _send(c, "POST", BASE + "/generate", {}).status_code in (302, 403)
        assert _send(c, "POST", BASE + "/send-now", {}).status_code in (302, 403)


def test_generate_503_when_ai_off(client):
    with (
        patch("app.routes.admin_routes.ai_enabled", return_value=False),
        patch.object(sched, "generate_preview") as gp,
    ):
        r = _send(client, "POST", BASE + "/generate", {})
    assert r.status_code == 503
    assert r.get_json() == {"error": "AI Assist is not enabled"}
    gp.assert_not_called()


def test_generate_returns_narrative_and_deltas_no_email(client):
    with (
        patch("app.routes.admin_routes.ai_enabled", return_value=True),
        patch.object(sched, "_build_payload", return_value={"hygiene_score": 80}),
        patch.object(sched, "build_briefing", return_value=("All good.", None)),
        patch.object(sched, "_send_email") as send,
    ):
        r = _send(client, "POST", BASE + "/generate", {})
    assert r.status_code == 200
    data = r.get_json()
    assert data["narrative"] == "All good."
    assert data["narrative_error"] is None
    assert data["deltas"]["hygiene_score"]["current"] == 80
    send.assert_not_called()


def test_generate_narration_failure_is_200(client):
    with (
        patch("app.routes.admin_routes.ai_enabled", return_value=True),
        patch.object(sched, "_build_payload", return_value={}),
        patch.object(sched, "build_briefing", return_value=(None, "LLM down")),
    ):
        r = _send(client, "POST", BASE + "/generate", {})
    assert r.status_code == 200
    assert r.get_json()["narrative"] is None
    assert r.get_json()["narrative_error"] == "LLM down"


def test_generate_payload_failure_is_not_500(client):
    with (
        patch("app.routes.admin_routes.ai_enabled", return_value=True),
        patch.object(sched, "_build_payload", side_effect=RuntimeError("cache gone")),
    ):
        r = _send(client, "POST", BASE + "/generate", {})
    assert r.status_code == 502
    assert "error" in r.get_json()


def test_send_now_reports_smtp_error(client):
    _send(client, "PUT", BASE, VALID)
    with (
        patch.object(sched, "ai_enabled", return_value=False),
        patch.object(sched, "_build_payload", return_value={}),
        patch.object(
            sched, "_send_email", side_effect=RuntimeError("SMTP not enabled")
        ),
    ):
        r = _send(client, "POST", BASE + "/send-now", {})
    assert r.status_code == 502
    assert "SMTP not enabled" in r.get_json()["error"]


def test_send_now_ok(client):
    _send(client, "PUT", BASE, VALID)
    with (
        patch.object(sched, "ai_enabled", return_value=False),
        patch.object(sched, "_build_payload", return_value={}),
        patch.object(sched, "_send_email") as send,
    ):
        r = _send(client, "POST", BASE + "/send-now", {})
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"
    send.assert_called_once()
