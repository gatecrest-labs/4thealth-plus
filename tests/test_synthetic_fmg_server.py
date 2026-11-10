"""HTTP wrapper around SyntheticFMG used by the Docker test rig."""

import importlib.util
import sys
from pathlib import Path

from app.synthetic_fmg import SyntheticFMG

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "synthetic_fmg_server.py"


def _server_app():
    spec = importlib.util.spec_from_file_location("synthetic_fmg_server", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["synthetic_fmg_server"] = mod
    spec.loader.exec_module(mod)
    return mod.create_server_app(SyntheticFMG(devices=6, adoms=1))


def test_jsonrpc_endpoint_answers_like_the_transport():
    client = _server_app().test_client()
    resp = client.post(
        "/jsonrpc", json={"id": 3, "method": "get", "params": [{"url": "/sys/status"}]}
    )
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["id"] == 3
    assert "Version" in body["result"][0]["data"]


def test_calls_endpoint_reports_counts_and_unsupported():
    client = _server_app().test_client()
    client.post(
        "/jsonrpc", json={"id": 1, "method": "get", "params": [{"url": "/sys/status"}]}
    )
    client.post(
        "/jsonrpc", json={"id": 2, "method": "get", "params": [{"url": "/nope"}]}
    )
    body = client.get("/_calls").get_json()
    assert body["calls"]["get /sys/status"] == 1
    assert body["unsupported"]["get /nope"] == 1
    assert body["total"] == 2


def test_injected_failure_becomes_http_502():
    from app.synthetic_fmg import SyntheticFMG as S

    spec = importlib.util.spec_from_file_location("synthetic_fmg_server2", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    client = mod.create_server_app(S(devices=2, adoms=1, error_rate=1.0)).test_client()
    resp = client.post(
        "/jsonrpc", json={"id": 1, "method": "get", "params": [{"url": "/sys/status"}]}
    )
    assert resp.status_code == 502
