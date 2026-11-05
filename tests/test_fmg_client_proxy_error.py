import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import MagicMock

# Captured from the lab FMG 8.0.2 while the FGFM tunnel to the FortiGate was down:
# the RPC itself succeeds (code 0), but the per-device wrapper carries the error
# and has NO "response" key.
TUNNEL_DOWN = {
    "result": [
        {
            "status": {"code": 0, "message": "OK"},
            "url": "/sys/proxy/json",
            "data": [
                {
                    "status": {
                        "code": -1,
                        "message": "FortiWiFi-71G(169) error: No tunnel 80.\n",
                    },
                    "target": "FortiWiFi-71G",
                }
            ],
        }
    ]
}

GOOD = {
    "result": [
        {
            "status": {"code": 0, "message": "OK"},
            "data": [
                {
                    "status": {"code": 0, "message": "OK"},
                    "target": "FortiWiFi-71G",
                    "response": {"http_status": 200, "results": {"hostname": "fw"}},
                }
            ],
        }
    ]
}


def _client(resp):
    from app.fmg_client import FMGClient

    c = FMGClient(host="fmg.example.com", token="tok")
    c._post = MagicMock(return_value=resp)
    return c


def test_tunnel_down_wrapper_is_an_error_not_a_payload():
    r = _client(TUNNEL_DOWN)._proxy(
        "root", "FortiWiFi-71G", "/api/v2/monitor/system/status"
    )
    assert r["http_status"] == 502
    assert r["payload"] == {}
    assert r["proxy_error"]["code"] == -1
    assert "No tunnel" in r["proxy_error"]["message"]


def test_successful_proxy_response_is_unchanged_and_has_no_proxy_error():
    r = _client(GOOD)._proxy("root", "FortiWiFi-71G", "/api/v2/monitor/system/status")
    assert r["http_status"] == 200
    assert r["payload"] == {"hostname": "fw"}
    assert "proxy_error" not in r


def test_license_status_is_empty_when_tunnel_down_so_it_parses_as_unknown():
    assert _client(TUNNEL_DOWN).get_device_license_status("root", "FortiWiFi-71G") == {}


def test_get_device_proxy_error_reports_message_when_down_and_none_when_up():
    assert (
        "No tunnel"
        in _client(TUNNEL_DOWN).get_device_proxy_error("root", "FortiWiFi-71G")[
            "message"
        ]
    )
    assert _client(GOOD).get_device_proxy_error("root", "FortiWiFi-71G") is None
