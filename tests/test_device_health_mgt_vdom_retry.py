"""Tests for the /health and /health/stream mgt_vdom license-status retry.

Multi-VDOM devices whose management VDOM isn't root come back with no
license_status payload under the implicit default (root) proxy call —
app.routes.api_routes.device_health()/device_health_stream() retry once
against the device's own mgt_vdom, mirroring the same fallback already
applied to the daily fleet sweep in app.license_status_cache.
"""

import os
import time
from unittest.mock import MagicMock, patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")

import pytest

from app import create_app

_TEST_USERS = {"test-admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


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
    with patch("app.auth._load_users", return_value=_TEST_USERS):
        yield client


def _fake_client(dev_rec, health_raw, license_status_retry=None):
    fake = MagicMock()
    fake.get_device.return_value = dev_rec
    fake.get_device_vdoms.return_value = []
    fake.get_device_health.return_value = health_raw
    fake.get_device_policy_package.return_value = {}
    fake.get_device_license_status.return_value = license_status_retry or {}
    fake.__enter__ = MagicMock(return_value=fake)
    fake.__exit__ = MagicMock(return_value=False)
    return fake


_EMPTY_LICENSE = {"rpc_code": 0, "http_status": 200, "payload": {}}
_LICENSED_PAYLOAD = {
    "forticare": {
        "support": {"enhanced": {"status": "licensed", "expires": 9999999999}}
    }
}


def test_health_retries_with_mgt_vdom_when_default_call_is_empty(logged_in_admin):
    dev_rec = {"mgt_vdom": "mgmt", "conn_status": 1}
    health_raw = {"license_status": dict(_EMPTY_LICENSE)}
    fake = _fake_client(dev_rec, health_raw, license_status_retry=_LICENSED_PAYLOAD)

    with patch("app.routes.api_routes._make_client", return_value=fake):
        resp = logged_in_admin.get("/api/adoms/Corp/devices/fw-1/health")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["license"]["status"] == "licensed"
    fake.get_device_license_status.assert_called_once_with("Corp", "fw-1", vdom="mgmt")


def test_health_does_not_retry_when_mgt_vdom_is_root(logged_in_admin):
    dev_rec = {"mgt_vdom": "root", "conn_status": 1}
    health_raw = {"license_status": dict(_EMPTY_LICENSE)}
    fake = _fake_client(dev_rec, health_raw)

    with patch("app.routes.api_routes._make_client", return_value=fake):
        resp = logged_in_admin.get("/api/adoms/Corp/devices/fw-1/health")

    assert resp.status_code == 200
    fake.get_device_license_status.assert_not_called()


def test_health_does_not_retry_when_default_call_already_has_payload(
    logged_in_admin,
):
    dev_rec = {"mgt_vdom": "mgmt", "conn_status": 1}
    health_raw = {
        "license_status": {
            "rpc_code": 0,
            "http_status": 200,
            "payload": _LICENSED_PAYLOAD,
        }
    }
    fake = _fake_client(dev_rec, health_raw)

    with patch("app.routes.api_routes._make_client", return_value=fake):
        resp = logged_in_admin.get("/api/adoms/Corp/devices/fw-1/health")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["license"]["status"] == "licensed"
    fake.get_device_license_status.assert_not_called()


def test_health_stream_retries_with_mgt_vdom_when_default_call_is_empty(
    logged_in_admin,
):
    from app.fmg_client import PROXY_ENDPOINTS

    dev_rec = {"mgt_vdom": "mgmt", "conn_status": 1}
    fake = _fake_client(dev_rec, {}, license_status_retry=_LICENSED_PAYLOAD)
    fake.stream_device_health.return_value = iter(
        [
            (i + 1, len(PROXY_ENDPOINTS), ep["label"], ep["key"], dict(_EMPTY_LICENSE))
            if ep["key"] == "license_status"
            else (
                i + 1,
                len(PROXY_ENDPOINTS),
                ep["label"],
                ep["key"],
                {"rpc_code": 0, "http_status": 200, "payload": {}},
            )
            for i, ep in enumerate(PROXY_ENDPOINTS)
        ]
    )

    with patch("app.routes.api_routes._make_client", return_value=fake):
        resp = logged_in_admin.get("/api/adoms/Corp/devices/fw-1/health/stream")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "event: done" in body
    assert '"status": "licensed"' in body
    fake.get_device_license_status.assert_called_once_with("Corp", "fw-1", vdom="mgmt")
