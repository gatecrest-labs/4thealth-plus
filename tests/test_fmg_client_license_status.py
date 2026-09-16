"""Tests for FMGClient.get_device_license_status()."""

from unittest.mock import patch

from app.fmg_client import FMGClient


def _make_client():
    c = FMGClient.__new__(FMGClient)
    c.base_url = "https://fmg.test/jsonrpc"
    c.token = "tok"
    c.session = None
    c.verify_ssl = False
    c._req_id = 0
    return c


def test_get_device_license_status_returns_payload():
    client = _make_client()
    fake_payload = {
        "forticare": {
            "support": {"enhanced": {"status": "licensed", "expires": 9999999999}}
        }
    }
    with patch.object(
        client,
        "_proxy",
        return_value={"rpc_code": 0, "http_status": 200, "payload": fake_payload},
    ) as mock_proxy:
        result = client.get_device_license_status("root", "FW-1")
    assert result == fake_payload
    mock_proxy.assert_called_once_with("root", "FW-1", "/api/v2/monitor/license/status")


def test_get_device_license_status_returns_empty_dict_on_exception():
    client = _make_client()
    with patch.object(client, "_proxy", side_effect=Exception("connection refused")):
        result = client.get_device_license_status("root", "FW-1")
    assert result == {}


def test_get_device_license_status_returns_empty_dict_when_payload_not_a_dict():
    client = _make_client()
    with patch.object(
        client,
        "_proxy",
        return_value={"rpc_code": 0, "http_status": 200, "payload": []},
    ):
        result = client.get_device_license_status("root", "FW-1")
    assert result == {}


def test_get_device_license_status_appends_vdom_query_param():
    client = _make_client()
    with patch.object(
        client,
        "_proxy",
        return_value={"rpc_code": 0, "http_status": 200, "payload": {}},
    ) as mock_proxy:
        client.get_device_license_status("root", "FW-1", vdom="mgmt")
    mock_proxy.assert_called_once_with(
        "root", "FW-1", "/api/v2/monitor/license/status?vdom=mgmt"
    )


def test_get_device_license_status_omits_vdom_query_param_when_not_given():
    client = _make_client()
    with patch.object(
        client,
        "_proxy",
        return_value={"rpc_code": 0, "http_status": 200, "payload": {}},
    ) as mock_proxy:
        client.get_device_license_status("root", "FW-1")
    mock_proxy.assert_called_once_with("root", "FW-1", "/api/v2/monitor/license/status")
