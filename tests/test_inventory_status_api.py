"""Inventory freshness API and badge (Phase 2, Task 9)."""

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from app import inventory_store
from app.config import Config

_USERS = {
    "admin": {"password_hash": "$2b$12$placeholder", "role": "admin"},
    "viewer": {"password_hash": "$2b$12$placeholder", "role": "viewer"},
}


@pytest.fixture
def app():
    from app import create_app

    return create_app()


def _client(app, user):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user"] = user
        sess["role"] = _USERS[user]["role"]
        sess["_csrf_token"] = "test-csrf"
        sess["login_at"] = int(time.time())
        sess["allowed_tabs"] = ["dashboard", "firewalls", "versions", "map"]
    return c


def _req(app, user, method, url):
    with patch("app.auth._load_users", return_value=_USERS):
        return getattr(_client(app, user), method)(
            url, headers={"X-CSRF-Token": "test-csrf"}
        )


def _now():
    return datetime.now(UTC).isoformat()


def _old(seconds):
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    monkeypatch.setattr(Config, "INVENTORY_REFRESH_SECS", 300)
    monkeypatch.setattr(Config, "INVENTORY_MAX_AGE_SECS", 900)


def test_status_requires_login(app):
    assert app.test_client().get("/api/inventory/status").status_code == 401


def test_status_disabled_when_flag_off(app, monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    body = _req(app, "viewer", "get", "/api/inventory/status").get_json()
    assert body["enabled"] is False
    assert body["adoms"] == []


def test_status_lists_adoms_with_age_and_counts(app, on):
    inventory_store.replace_adom("A", [{"name": "d1"}, {"name": "d2"}], None, _now())
    with patch("app.groups.get_allowed_adoms", return_value=None):  # unrestricted
        body = _req(app, "viewer", "get", "/api/inventory/status").get_json()
    assert body["enabled"] is True
    assert body["refresh_seconds"] == 300 and body["max_age_seconds"] == 900
    row = body["adoms"][0]
    assert row["adom"] == "A" and row["device_count"] == 2
    assert row["stale"] is False and row["status"] == "ok"


def test_status_filters_adoms_for_restricted_user(app, on):
    inventory_store.replace_adom("A", [{"name": "d1"}], None, _now())
    inventory_store.replace_adom("B", [{"name": "d2"}], None, _now())
    with patch("app.groups.get_allowed_adoms", return_value=["A"]):
        body = _req(app, "viewer", "get", "/api/inventory/status").get_json()
    assert [r["adom"] for r in body["adoms"]] == ["A"]


def test_status_admin_sees_every_adom(app, on):
    inventory_store.replace_adom("A", [{"name": "d1"}], None, _now())
    inventory_store.replace_adom("B", [{"name": "d2"}], None, _now())
    body = _req(app, "admin", "get", "/api/inventory/status").get_json()
    assert {r["adom"] for r in body["adoms"]} == {"A", "B"}


def test_status_marks_stale_and_error(app, on):
    inventory_store.replace_adom("Old", [{"name": "d"}], None, _old(5000))
    inventory_store.replace_adom("Bad", [{"name": "d"}], None, _now())
    inventory_store.mark_adom_error("Bad", "boom")
    rows = {
        r["adom"]: r
        for r in _req(app, "admin", "get", "/api/inventory/status").get_json()["adoms"]
    }
    assert rows["Old"]["stale"] is True
    assert rows["Bad"]["status"] == "error"


def test_user_in_no_group_sees_no_adoms(app, on):
    inventory_store.replace_adom("A", [{"name": "d1"}], None, _now())
    with patch("app.groups.get_allowed_adoms", return_value=[]):
        body = _req(app, "viewer", "get", "/api/inventory/status").get_json()
    assert body["adoms"] == []


def test_status_degrades_to_empty_when_store_unreadable(app, on, monkeypatch):
    def broken(*a, **k):
        raise inventory_store.InventoryStoreError("io")

    monkeypatch.setattr(inventory_store, "read_meta", broken)
    resp = _req(app, "viewer", "get", "/api/inventory/status")
    assert resp.status_code == 200 and resp.get_json()["adoms"] == []


def test_refresh_admin_only(app, on):
    assert _req(app, "viewer", "post", "/api/inventory/refresh").status_code == 403


def test_refresh_503_when_flag_off(app, monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    assert _req(app, "admin", "post", "/api/inventory/refresh").status_code == 503


def test_refresh_sets_request_row_for_collector(app, on):
    resp = _req(app, "admin", "post", "/api/inventory/refresh")
    assert resp.status_code == 202 and resp.get_json() == {"requested": True}
    assert inventory_store.pop_refresh_request() is True


def test_refresh_throttled_429_with_retry_after(app, on):
    assert _req(app, "admin", "post", "/api/inventory/refresh").status_code == 202
    resp = _req(app, "admin", "post", "/api/inventory/refresh")
    assert resp.status_code == 429
    body = resp.get_json()
    assert 0 < body["retry_after"] <= 60
    assert resp.headers["Retry-After"]


@pytest.mark.parametrize("url", ["/", "/firewalls", "/versions", "/map"])
def test_pages_include_freshness_script_only_when_enabled(app, monkeypatch, url):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    on_html = _req(app, "admin", "get", url).get_data(as_text=True)
    assert "freshness.js" in on_html and 'id="invFreshness"' in on_html
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    off_html = _req(app, "admin", "get", url).get_data(as_text=True)
    assert "freshness.js" not in off_html and 'id="invFreshness"' not in off_html


def test_other_pages_do_not_get_the_badge(app, monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    html = _req(app, "admin", "get", "/admin/").get_data(as_text=True)
    assert "freshness.js" not in html
