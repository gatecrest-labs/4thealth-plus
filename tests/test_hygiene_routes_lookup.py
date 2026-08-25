"""Tests for interface and NAT lookup endpoints."""
import os
import json
import time
import pytest
from unittest.mock import patch


@pytest.fixture
def app():
    os.environ.setdefault("SECRET_KEY", "test-secret")
    os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")
    from app import create_app
    return create_app()


_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def client(app):
    with app.test_client() as c, \
         patch("app.auth._load_users", return_value=_TEST_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def _post(client, url, payload):
    """POST with JSON body and CSRF header to bypass CSRF validation."""
    return client.post(
        url,
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )


# ── Interface Lookup ──────────────────────────────────────────────────────────

def test_interface_lookup_returns_match(client):
    devices = [{"name": "FW-01"}]
    interfaces = [
        {"name": "port1", "ip": "10.1.2.3 255.255.255.0", "vdom": "root", "type": "physical", "status": "up"},
        {"name": "port2", "ip": "192.168.1.1 255.255.255.0", "vdom": "root", "type": "physical", "status": "up"},
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_devices.return_value = devices
        inst.get_device_interfaces_all_vdoms.return_value = interfaces
        resp = _post(client, "/api/hygiene/adoms/TestADOM/interfaces/lookup", {"ips": ["10.1.2.3"]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["interface"] == "port1"
    assert data["results"][0]["device"] == "FW-01"
    assert data["skipped_devices"] == []


def test_interface_lookup_not_found(client):
    devices = [{"name": "FW-01"}]
    interfaces = [
        {"name": "port1", "ip": "192.168.1.1 255.255.255.0", "vdom": "root", "type": "physical", "status": "up"},
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_devices.return_value = devices
        inst.get_device_interfaces_all_vdoms.return_value = interfaces
        resp = _post(client, "/api/hygiene/adoms/TestADOM/interfaces/lookup", {"ips": ["10.1.2.3"]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 0
    assert data["results"] == []


def test_interface_lookup_skips_unreachable_device(client):
    devices = [{"name": "FW-01"}, {"name": "FW-02"}]

    def fake_ifaces(adom, device):
        if device == "FW-02":
            raise Exception("unreachable")
        return [{"name": "port1", "ip": "10.1.2.3 255.255.255.0", "vdom": "root", "type": "physical", "status": "up"}]

    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_devices.return_value = devices
        inst.get_device_interfaces_all_vdoms.side_effect = fake_ifaces
        resp = _post(client, "/api/hygiene/adoms/TestADOM/interfaces/lookup", {"ips": ["10.1.2.3"]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "FW-02" in data["skipped_devices"]


def test_interface_lookup_invalid_ip(client):
    resp = _post(client, "/api/hygiene/adoms/TestADOM/interfaces/lookup", {"ips": ["not-an-ip"]})
    assert resp.status_code == 400
    assert "invalid" in resp.get_json()["error"].lower()


def test_interface_lookup_missing_ips(client):
    resp = _post(client, "/api/hygiene/adoms/TestADOM/interfaces/lookup", {})
    assert resp.status_code == 400


# ── NAT Lookup ────────────────────────────────────────────────────────────────

def test_nat_lookup_matches_vip_extip(client):
    vips = [
        {
            "name": "vip_web",
            "extip": "203.0.113.10",
            "extintf": "wan1",
            "mappedip": [{"range": "10.0.0.1-10.0.0.1"}],
            "portforward": "disable",
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "203.0.113.10"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["nat_type"] == "VIP"
    assert data["results"][0]["name"] == "vip_web"


def test_nat_lookup_matches_vip_mapped_ip(client):
    vips = [
        {
            "name": "vip_web",
            "extip": "203.0.113.10",
            "extintf": "wan1",
            "mappedip": [{"range": "10.0.0.5-10.0.0.10"}],
            "portforward": "disable",
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "10.0.0.7"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["name"] == "vip_web"


def test_nat_lookup_matches_vip_single_mapped_ip(client):
    """Single-IP mappedip entries (no dash) must be matched — regression for FMG format."""
    vips = [
        {
            "name": "vip-Cherokee-GE-OMS-NAT",
            "extip": "192.234.135.43",
            "extintf": "any",
            "mappedip": [{"range": "170.152.57.68"}],
            "portforward": "disable",
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "170.152.57.68"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["name"] == "vip-Cherokee-GE-OMS-NAT"


def test_nat_lookup_matches_vip_extip_range(client):
    """VIP extip returned as a range string must be matched."""
    vips = [
        {
            "name": "vip_range",
            "extip": "203.0.113.10-203.0.113.20",
            "extintf": "wan1",
            "mappedip": [{"range": "10.0.0.1"}],
            "portforward": "disable",
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "203.0.113.15"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["name"] == "vip_range"


def test_nat_lookup_matches_ippool(client):
    pools = [
        {
            "name": "outbound_pool",
            "startip": "203.0.113.1",
            "endip": "203.0.113.20",
            "type": "overload",
            "comments": "Corp PAT",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = []
        inst.get_ippool_objects.return_value = pools
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "203.0.113.10"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["nat_type"] == "IP Pool"
    assert data["results"][0]["name"] == "outbound_pool"


def test_nat_lookup_response_includes_objects_checked(client):
    """Response must include objects_checked with shared_vips/device_vips/devices/pools counts."""
    vips = [{"name": "v1", "extip": "1.2.3.4", "mappedip": [{"range": "10.0.0.1"}],
             "portforward": "disable", "protocol": "", "extport": "", "mappedport": "", "comment": ""}]
    pools = [{"name": "p1", "startip": "5.6.7.8", "endip": "5.6.7.9", "type": "overload", "comments": ""}]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = pools
        inst.get_devices.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "9.9.9.9"})
    data = resp.get_json()
    assert "objects_checked" in data
    oc = data["objects_checked"]
    assert oc["shared_vips"] == 1
    assert oc["device_vips"] == 0
    assert oc["devices"] == 0
    assert oc["pools"] == 1


def test_nat_lookup_finds_per_device_vip(client):
    """Per-device VIPs (not in ADOM shared objects) must be found via the device sweep."""
    device_vips = [
        {
            "name": "vip-per-device",
            "extip": "203.0.113.99",
            "extintf": "wan1",
            "mappedip": [{"range": "10.10.10.1"}],
            "portforward": "disable",
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    devices = [{"name": "FW-EDGE-01"}]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = []        # no ADOM-level VIPs
        inst.get_ippool_objects.return_value = []
        inst.get_devices.return_value = devices
        inst.get_device_vdoms.return_value = [{"name": "root"}]
        inst.get_device_vip_objects.return_value = device_vips
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "10.10.10.1"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["name"] == "vip-per-device"
    assert data["results"][0]["device"] == "FW-EDGE-01"
    assert data["objects_checked"]["device_vips"] == 1
    assert data["objects_checked"]["devices"] == 1


def test_nat_lookup_matches_vip_hyphenated_mapped_ip(client):
    """Some FMG versions return 'mapped-ip' (hyphenated) — must still match."""
    vips = [
        {
            "name": "vip-hyphen",
            "extip": "203.0.113.50",
            "extintf": "wan1",
            "mapped-ip": [{"range": "10.0.0.99"}],
            "portforward": "disable",
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "10.0.0.99"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["name"] == "vip-hyphen"


def test_nat_lookup_matches_vip_extip_as_list(client):
    """FMG returns extip as a list (e.g. ['192.234.135.43']) — must match by external IP."""
    vips = [
        {
            "name": "vip-list-extip",
            "extip": ["203.0.113.55"],
            "extintf": ["any"],
            "mappedip": ["10.5.5.5"],
            "portforward": 0,
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "203.0.113.55"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["name"] == "vip-list-extip"
    assert data["results"][0]["ext_ip"] == "203.0.113.55"


def test_nat_lookup_matches_vip_mappedip_plain_string(client):
    """FMG per-device path may return mappedip as a plain string — must still match."""
    vips = [
        {
            "name": "vip-str",
            "extip": "203.0.113.70",
            "extintf": "wan1",
            "mappedip": "10.0.1.50",
            "portforward": "disable",
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "10.0.1.50"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["name"] == "vip-str"


def test_nat_lookup_matches_vip_mappedip_list_of_strings(client):
    """FMG may return mappedip as a list of strings (not dicts) — must still match."""
    vips = [
        {
            "name": "vip-strlist",
            "extip": "203.0.113.80",
            "extintf": "wan1",
            "mappedip": ["10.0.2.75"],
            "portforward": "disable",
            "protocol": "",
            "extport": "",
            "mappedport": "",
            "comment": "",
        }
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = vips
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "10.0.2.75"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["name"] == "vip-strlist"


def test_nat_lookup_not_found(client):
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_vip_objects.return_value = []
        inst.get_ippool_objects.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "1.2.3.4"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 0


def test_nat_lookup_invalid_ip(client):
    resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {"ip": "not-an-ip"})
    assert resp.status_code == 400


def test_nat_lookup_missing_ip(client):
    resp = _post(client, "/api/hygiene/adoms/TestADOM/nat/lookup", {})
    assert resp.status_code == 400


# ── Where Used ────────────────────────────────────────────────────────────────

def test_where_used_direct_address_match(client):
    packages = [{"name": "Corp-Policy", "path": "Corp-Policy", "obj ver": 0}]
    policies = [
        {"policyid": 42, "name": "permit-srv", "action": "accept",
         "srcaddr": [{"name": "HOST-10.1.1.1"}], "dstaddr": [{"name": "any"}], "service": []},
        {"policyid": 99, "name": "other-rule", "action": "accept",
         "srcaddr": [{"name": "other-obj"}], "dstaddr": [{"name": "any"}], "service": []},
    ]
    addr_groups = []
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_policy_packages.return_value = packages
        inst.get_policies.return_value = policies
        inst.get_address_groups.return_value = addr_groups
        resp = _post(client, "/api/hygiene/adoms/TestADOM/objects/where-used",
                     {"name": "HOST-10.1.1.1", "category": "address"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["name"] == "HOST-10.1.1.1"
    assert data["groups"] == []
    assert data["packages_scanned"] == 1
    assert len(data["rules"]) == 1
    assert data["rules"][0]["rule_id"] == "42"
    assert data["rules"][0]["rule_name"] == "permit-srv"
    assert data["rules"][0]["via"] == "direct"
    assert data["rules"][0]["package"] == "Corp-Policy"


def test_where_used_indirect_via_group(client):
    packages = [{"name": "Corp-Policy", "path": "Corp-Policy", "obj ver": 0}]
    policies = [
        {"policyid": 55, "name": "block-out", "action": "deny",
         "srcaddr": [{"name": "SERVERS"}], "dstaddr": [{"name": "any"}], "service": []},
    ]
    addr_groups = [
        {"name": "SERVERS", "member": [{"name": "HOST-10.1.1.1"}, {"name": "HOST-10.1.1.2"}]},
        {"name": "OTHER-GROUP", "member": [{"name": "HOST-10.2.2.2"}]},
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_policy_packages.return_value = packages
        inst.get_policies.return_value = policies
        inst.get_address_groups.return_value = addr_groups
        resp = _post(client, "/api/hygiene/adoms/TestADOM/objects/where-used",
                     {"name": "HOST-10.1.1.1", "category": "address"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["groups"]) == 1
    assert data["groups"][0]["name"] == "SERVERS"
    assert len(data["rules"]) == 1
    assert data["rules"][0]["rule_id"] == "55"
    assert data["rules"][0]["via"] == "SERVERS"


def test_where_used_not_referenced(client):
    packages = [{"name": "Corp-Policy", "path": "Corp-Policy", "obj ver": 0}]
    policies = [
        {"policyid": 1, "name": "some-rule", "action": "accept",
         "srcaddr": [{"name": "other-obj"}], "dstaddr": [{"name": "any"}], "service": []},
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_policy_packages.return_value = packages
        inst.get_policies.return_value = policies
        inst.get_address_groups.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/objects/where-used",
                     {"name": "UNUSED-OBJ", "category": "address"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["groups"] == []
    assert data["rules"] == []
    assert data["packages_scanned"] == 1


def test_where_used_service_category(client):
    packages = [{"name": "Corp-Policy", "path": "Corp-Policy", "obj ver": 0}]
    policies = [
        {"policyid": 10, "name": "web-rule", "action": "accept",
         "srcaddr": [{"name": "any"}], "dstaddr": [{"name": "any"}],
         "service": [{"name": "HTTPS-8443"}]},
    ]
    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_policy_packages.return_value = packages
        inst.get_policies.return_value = policies
        inst.get_service_groups.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/objects/where-used",
                     {"name": "HTTPS-8443", "category": "service"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["rules"]) == 1
    assert data["rules"][0]["rule_id"] == "10"
    assert data["rules"][0]["via"] == "direct"
    assert data["groups"] == []
    assert data["packages_scanned"] == 1


def test_where_used_multiple_packages(client):
    packages = [
        {"name": "Corp-Policy", "path": "Corp-Policy", "obj ver": 0},
        {"name": "Edge-Policy", "path": "Folder/Edge-Policy", "obj ver": 0},
    ]
    policies_corp = [
        {"policyid": 1, "name": "rule-a", "action": "accept",
         "srcaddr": [{"name": "HOST-10.1.1.1"}], "dstaddr": [{"name": "any"}], "service": []},
    ]
    policies_edge = [
        {"policyid": 2, "name": "rule-b", "action": "deny",
         "srcaddr": [{"name": "any"}], "dstaddr": [{"name": "HOST-10.1.1.1"}], "service": []},
    ]
    def side_effect(adom, pkg_path):
        if pkg_path == "Corp-Policy":
            return policies_corp
        if pkg_path == "Folder/Edge-Policy":
            return policies_edge
        return []

    with patch("app.routes.hygiene_routes.make_client") as mc:
        inst = mc.return_value.__enter__.return_value
        inst.get_policy_packages.return_value = packages
        inst.get_policies.side_effect = side_effect
        inst.get_address_groups.return_value = []
        resp = _post(client, "/api/hygiene/adoms/TestADOM/objects/where-used",
                     {"name": "HOST-10.1.1.1", "category": "address"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["packages_scanned"] == 2
    rule_ids = {r["rule_id"] for r in data["rules"]}
    assert rule_ids == {"1", "2"}
    packages_seen = {r["package"] for r in data["rules"]}
    assert "Corp-Policy" in packages_seen
    assert "Folder/Edge-Policy" in packages_seen


def test_where_used_missing_name_returns_400(client):
    resp = _post(client, "/api/hygiene/adoms/TestADOM/objects/where-used",
                 {"category": "address"})
    assert resp.status_code == 400


def test_where_used_invalid_category_returns_400(client):
    resp = _post(client, "/api/hygiene/adoms/TestADOM/objects/where-used",
                 {"name": "HOST-10.1.1.1", "category": "vip"})
    assert resp.status_code == 400
