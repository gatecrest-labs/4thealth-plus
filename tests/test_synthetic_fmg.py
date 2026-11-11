"""SyntheticFMG: a deterministic, in-process stand-in for FortiManager."""

import pytest
import requests

from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG


def _client(fmg):
    c = FMGClient(host="fmg.invalid", token="t")
    c._post = fmg.post
    return c


def _real_adoms(c):
    return [
        a["name"] for a in c.get_adoms() if not a["name"].lower().startswith("forti")
    ]


def test_deterministic_for_seed():
    a = _client(SyntheticFMG(devices=30, adoms=2, seed=7))
    b = _client(SyntheticFMG(devices=30, adoms=2, seed=7))
    other = _client(SyntheticFMG(devices=30, adoms=2, seed=8))
    adom = _real_adoms(a)[0]
    assert a.get_devices(adom) == b.get_devices(adom)
    assert a.get_devices(adom) != other.get_devices(adom)


def test_device_counts_match_config():
    c = _client(SyntheticFMG(devices=50, adoms=2, multi_vdom_fraction=0.5))
    devices = [d for adom in _real_adoms(c) for d in c.get_devices(adom)]
    assert len(devices) == 50
    assert len({d["name"] for d in devices}) == 50
    assert any(len(d["vdom"]) > 1 for d in devices)
    assert all("sn" in d and "conn_status" in d and "os_ver" in d for d in devices)


def test_system_adom_is_listed_but_empty():
    c = _client(SyntheticFMG(devices=10, adoms=2))
    names = [a["name"] for a in c.get_adoms()]
    assert any(n.lower().startswith("forti") for n in names)


def test_policy_paging_returns_all_rules():
    fmg = SyntheticFMG(devices=4, adoms=1, packages_per_adom=2, rules_per_package=2500)
    c = _client(fmg)
    adom = _real_adoms(c)[0]
    pkg = c.get_policy_packages(adom)[0]["path"]
    assert len(c.get_policies(adom, pkg)) == 2500
    key = "get /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy"
    assert fmg.calls[key] == 3  # 1000 + 1000 + 500


def test_package_scope_and_status():
    c = _client(SyntheticFMG(devices=10, adoms=1, packages_per_adom=2))
    adom = _real_adoms(c)[0]
    scoped = {
        m["name"]
        for p in c.get_policy_packages(adom)
        for m in c.get_pkg_scope_members(adom, p["path"])
    }
    assert scoped == {d["name"] for d in c.get_devices(adom)}
    info = c.get_package_info(adom, c.get_devices(adom)[0]["name"], "root")
    assert info["pkg_name"]
    assert info["pkg_status"] in ("nomod", "modified")


def test_catalog_objects_are_paged_through_post():
    fmg = SyntheticFMG(devices=4, adoms=1, address_objects=2500)
    c = _client(fmg)
    adom = _real_adoms(c)[0]
    assert len(c.get_address_objects(adom, scope="local")) == 2500
    assert fmg.calls["get /pm/config/adom/{adom}/obj/firewall/address"] == 3


def test_proxy_license_status_parses_via_license_status():
    from app.license_status import parse_license_payload

    c = _client(SyntheticFMG(devices=10, adoms=1))
    adom = _real_adoms(c)[0]
    dev = c.get_devices(adom)[0]["name"]
    parsed = parse_license_payload(c.get_device_license_status(adom, dev))
    assert parsed["status"] in ("licensed", "expired")
    assert "antivirus" in parsed["subscriptions"]


def test_unsupported_url_returns_error_object_and_counts():
    fmg = SyntheticFMG(devices=2, adoms=1)
    resp = fmg.post({"id": 5, "method": "get", "params": [{"url": "/nope/never"}]})
    assert resp["id"] == 5
    assert resp["result"][0]["status"]["code"] == -3
    assert fmg.unsupported["get /nope/never"] == 1
    assert fmg.calls["get /nope/never"] == 1  # unsupported calls are still calls


def test_error_injection_raises_connection_error():
    fmg = SyntheticFMG(devices=2, adoms=1, error_rate=1.0)
    with pytest.raises(requests.ConnectionError):
        fmg.post({"id": 1, "method": "get", "params": [{"url": "/sys/status"}]})


def test_calls_counter_counts_per_normalized_url():
    fmg = SyntheticFMG(devices=10, adoms=2)
    c = _client(fmg)
    adoms = _real_adoms(c)
    for a in adoms:
        c.get_devices(a)
        c.get_devices(a)
    assert fmg.calls["get /dvmdb/adom/{adom}/device"] == 4
    assert fmg.total_calls == sum(fmg.calls.values())
