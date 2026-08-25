"""Tests for get_vip_objects and get_ippool_objects FMG client methods."""
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


def test_get_vip_objects_returns_merged_list():
    client = _make_client()
    adom_vips = [{"name": "vip1", "extip": "1.2.3.4", "mappedip": [{"range": "10.0.0.1-10.0.0.1"}]}]
    global_vips = [{"name": "vip_global", "extip": "5.6.7.8", "mappedip": [{"range": "10.0.0.2-10.0.0.2"}]}]

    call_count = {"n": 0}
    def fake_paged(url):
        call_count["n"] += 1
        if "global" in url:
            return global_vips
        return adom_vips

    with patch.object(client, "_get_paged", side_effect=fake_paged):
        result = client.get_vip_objects("TestADOM")

    assert len(result) == 2
    assert call_count["n"] == 2
    names = {r["name"] for r in result}
    assert "vip1" in names
    assert "vip_global" in names


def test_get_vip_objects_graceful_on_error():
    client = _make_client()

    def fake_paged(url):
        raise Exception("FMG unreachable")

    with patch.object(client, "_get_paged", side_effect=fake_paged):
        result = client.get_vip_objects("TestADOM")

    assert result == []


def test_get_ippool_objects_returns_merged_list():
    client = _make_client()
    adom_pools = [{"name": "pool1", "startip": "1.2.3.1", "endip": "1.2.3.10"}]
    global_pools = [{"name": "pool_global", "startip": "5.6.7.1", "endip": "5.6.7.20"}]

    def fake_paged(url):
        if "global" in url:
            return global_pools
        return adom_pools

    with patch.object(client, "_get_paged", side_effect=fake_paged):
        result = client.get_ippool_objects("TestADOM")

    assert len(result) == 2
    names = {r["name"] for r in result}
    assert "pool1" in names
    assert "pool_global" in names


def test_get_ippool_objects_graceful_on_error():
    client = _make_client()

    def fake_paged(url):
        raise Exception("FMG unreachable")

    with patch.object(client, "_get_paged", side_effect=fake_paged):
        result = client.get_ippool_objects("TestADOM")

    assert result == []


def test_get_device_vip_objects_returns_paged_result():
    client = _make_client()
    device_vips = [{"name": "vip-dev", "extip": "9.9.9.9"}]

    captured = {}
    def fake_paged(url):
        captured["url"] = url
        return device_vips

    with patch.object(client, "_get_paged", side_effect=fake_paged):
        result = client.get_device_vip_objects("FW01", "root")

    assert result == device_vips
    assert captured["url"] == "/pm/config/device/FW01/vdom/root/firewall/vip"


def test_get_device_vip_objects_graceful_on_error():
    client = _make_client()

    def fake_paged(url):
        raise Exception("FMG unreachable")

    with patch.object(client, "_get_paged", side_effect=fake_paged):
        result = client.get_device_vip_objects("FW01")

    assert result == []
