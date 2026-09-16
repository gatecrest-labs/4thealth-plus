"""Tests for the Device Versions tab's License Status endpoints.

These read from app.license_status_cache's existing daily-sweep record
(see that module's docstring) rather than running a live FMG sweep.
"""

import os
import time
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")

import pytest

from app import create_app

_TEST_USERS = {"test-admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}

_SAMPLE_RECORD = {
    "devices_licensed": 1,
    "devices_expired": 1,
    "devices_unknown": 0,
    "details": [
        {"device": "fw-b", "adom": "Branch", "status": "expired", "expires": None}
    ],
    "all_devices": [
        {
            "device": "fw-a",
            "adom": "Corp",
            "status": "licensed",
            "expires": "2027-01-01",
            "firmware": "v7.4.5",
        },
        {
            "device": "fw-b",
            "adom": "Branch",
            "status": "expired",
            "expires": None,
            "firmware": "v7.2.1",
        },
    ],
    "collected_at": "2026-09-16T03:00:00+00:00",
}


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_admin(client):
    with client.session_transaction() as sess:
        sess["user"] = "test-admin"
        sess["role"] = "admin"
        sess["allowed_tabs"] = ["dashboard"]
        sess["login_at"] = int(time.time())
        sess["_csrf_token"] = "test-csrf"
    with patch("app.auth._load_users", return_value=_TEST_USERS):
        yield client


def test_all_devices_license_returns_full_fleet(logged_in_admin):
    with patch("app.license_status_cache.get_latest", return_value=_SAMPLE_RECORD):
        resp = logged_in_admin.get("/api/devices/all/license")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["devices"]) == 2
    assert data["last_updated"] == "2026-09-16T03:00:00+00:00"
    assert data["status"] == "ok"


def test_all_devices_license_pending_when_no_sweep_yet(logged_in_admin):
    with patch("app.license_status_cache.get_latest", return_value=None):
        resp = logged_in_admin.get("/api/devices/all/license")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["devices"] == []
    assert data["status"] == "pending"


def test_all_devices_license_running_status(logged_in_admin):
    with (
        patch("app.license_status_cache.get_latest", return_value=_SAMPLE_RECORD),
        patch("app.license_status_cache.is_running", return_value=True),
    ):
        resp = logged_in_admin.get("/api/devices/all/license")
    assert resp.get_json()["status"] == "running"


def test_adom_license_filters_to_one_adom(logged_in_admin):
    with patch("app.license_status_cache.get_latest", return_value=_SAMPLE_RECORD):
        resp = logged_in_admin.get("/api/adoms/Corp/license")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["devices"]) == 1
    assert data["devices"][0]["device"] == "fw-a"


def test_all_devices_license_refresh_triggers_sweep(logged_in_admin):
    with patch("app.license_status_cache.refresh_now") as mock_refresh:
        resp = logged_in_admin.post(
            "/api/devices/all/license/refresh",
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "running", "queued": True}
    mock_refresh.assert_called_once()


def test_license_endpoints_require_login(client):
    resp = client.get("/api/devices/all/license")
    assert resp.status_code == 401
