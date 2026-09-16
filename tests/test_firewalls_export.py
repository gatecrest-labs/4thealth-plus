import os
import time
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")


@pytest.fixture
def app():
    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client):
    with client.session_transaction() as sess:
        sess["user"] = "testuser"
        sess["role"] = "admin"
        sess["allowed_tabs"] = ["firewalls"]
        sess["login_at"] = int(time.time())


def test_devices_response_includes_ha_mode(client):
    """devices() endpoint must include ha_mode in every device dict."""
    _login(client)
    raw_devices = [
        {
            "name": "FW-HA-01",
            "ip": "10.0.0.1",
            "sn": "FGT60F0000000001",
            "platform_str": "FortiGate-60F",
            "os_ver": 7,
            "mr": 2,
            "patch": 3,
            "conn_status": 1,
            "desc": "Primary node",
            "ha_mode": "a-p",
        },
        {
            "name": "FW-STANDALONE-01",
            "ip": "10.0.0.2",
            "sn": "FGT60F0000000002",
            "platform_str": "FortiGate-60F",
            "os_ver": 7,
            "mr": 2,
            "patch": 3,
            "conn_status": 1,
            "desc": "",
        },
    ]
    with patch("app.routes.api_routes._make_client") as mock_make:
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_ctx.get_devices.return_value = raw_devices
        mock_make.return_value = mock_ctx

        resp = client.get("/api/adoms/TestADOM/devices")

    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) == 2

    ha_device = next(d for d in data if d["name"] == "FW-HA-01")
    assert ha_device["ha_mode"] == "a-p"

    standalone = next(d for d in data if d["name"] == "FW-STANDALONE-01")
    assert standalone["ha_mode"] == ""


def test_devices_ha_mode_falls_back_to_ha_group_name(client):
    """ha_mode falls back to ha_group_name when ha_mode key is absent."""
    _login(client)
    raw_devices = [
        {
            "name": "FW-HA-02",
            "ip": "10.0.0.3",
            "sn": "FGT60F0000000003",
            "platform_str": "FortiGate-60F",
            "os_ver": 7,
            "mr": 2,
            "patch": 3,
            "conn_status": 1,
            "desc": "",
            "ha_group_name": "cluster-01",
        },
    ]
    with patch("app.routes.api_routes._make_client") as mock_make:
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_ctx.get_devices.return_value = raw_devices
        mock_make.return_value = mock_ctx

        resp = client.get("/api/adoms/TestADOM/devices")

    data = resp.get_json()
    assert data[0]["ha_mode"] == "cluster-01"
