"""Tests for app.planner.catalogs — address/service catalog building."""
from unittest.mock import MagicMock

from app.planner.catalogs import (
    build_catalogs,
    get_device_policies,
    package_targets_device,
    summarise_policy,
)


def test_package_targets_device_scoped_match():
    pkg = {"scope member": [{"name": "FW-A"}, {"name": "FW-B"}]}
    assert package_targets_device(pkg, "FW-A") is True
    assert package_targets_device(pkg, "FW-C") is False


def test_package_targets_device_unscoped_applies_to_all():
    assert package_targets_device({}, "FW-A") is True
    assert package_targets_device({"scope member": []}, "FW-A") is True


def test_build_catalogs_indexes_per_adom_and_global_objects():
    client = MagicMock()
    client.get_address_objects.side_effect = lambda adom: (
        [{"name": "H_10.1.1.1", "type": "ipmask", "subnet": "10.1.1.1/32"}]
        if adom == "OT-ADOM" else [{"name": "H_GLOBAL", "type": "ipmask", "subnet": "10.9.9.9/32"}]
    )
    client.get_address_groups.side_effect = lambda adom: []
    client.get_service_objects.return_value = [
        {"name": "SVC_TCP_443", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}
    ]
    client.get_service_groups.return_value = []

    addr_catalog, svc_catalog = build_catalogs(client, "OT-ADOM")

    assert addr_catalog.exact_match_name("10.1.1.1/32") == "H_10.1.1.1"
    assert addr_catalog.exact_match_name("10.9.9.9/32") == "H_GLOBAL"
    from app.planner.matching import PortRange
    assert svc_catalog.exact_match_name([PortRange("tcp", 443, 443)]) == "SVC_TCP_443"


def test_build_catalogs_degrades_gracefully_if_global_fetch_fails():
    client = MagicMock()
    def addr_objects(adom):
        if adom == "global":
            raise RuntimeError("global ADOM not accessible")
        return []
    client.get_address_objects.side_effect = addr_objects
    client.get_address_groups.side_effect = lambda adom: (
        (_ for _ in ()).throw(RuntimeError("boom")) if adom == "global" else []
    )
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []

    addr_catalog, _svc_catalog = build_catalogs(client, "OT-ADOM")
    assert addr_catalog.exact_match_name("10.1.1.1/32") is None  # no crash, just empty


def test_get_device_policies_returns_none_on_fetch_failure():
    client = MagicMock()
    def get_policies(adom, pkg):
        if pkg == "bad-pkg":
            raise RuntimeError("fetch failed")
        return [{"policyid": 1}]
    client.get_policies.side_effect = get_policies

    result = get_device_policies(client, "OT-ADOM", ["good-pkg", "bad-pkg"])
    assert result["good-pkg"] == [{"policyid": 1}]
    assert result["bad-pkg"] is None


def test_summarise_policy_shape():
    pol = {
        "policyid": 42, "name": "TEST_RULE", "status": "enable",
        "srcaddr": ["H_A"], "srcintf": ["port1"],
        "dstaddr": ["H_B"], "dstintf": ["port2"],
        "service": ["SVC_TCP_443"], "action": 1, "logtraffic": 2,
        "nat": "disable", "schedule": ["always"],
        "srcaddr-negate": "disable", "dstaddr-negate": "disable",
        "comments": "test", "uuid": "abc-123",
    }
    summary = summarise_policy(pol, "TestPkg")
    assert summary["package"] == "TestPkg"
    assert summary["policy_id"] == 42
    assert summary["name"] == "TEST_RULE"
    assert summary["source"] == ["H_A"]
    assert summary["destination"] == ["H_B"]
    assert summary["service"] == ["SVC_TCP_443"]
    assert summary["action"] == "accept"
    assert summary["log"] == "all"
    assert summary["srcaddr_negate"] is False


def test_build_fqdn_catalog_indexes_objects_and_groups():
    from app.planner.catalogs import build_fqdn_catalog

    client = MagicMock()
    client.get_address_objects.return_value = [
        {"name": "FQDN-a", "type": "fqdn", "fqdn": "api.vendor.com"}
    ]
    client.get_address_groups.return_value = [
        {"name": "GRP-DST", "member": ["FQDN-a"]}
    ]

    cat = build_fqdn_catalog(client, "OT-ADOM")
    assert cat.fqdns_for_ref("GRP-DST") == {"api.vendor.com"}


def test_search_fqdn_rules_reports_covered_and_uncovered():
    from app.planner.catalogs import search_fqdn_rules

    client = MagicMock()
    client.get_address_objects.return_value = [
        {"name": "FQDN-covered", "type": "fqdn", "fqdn": "covered.vendor.com"},
    ]
    client.get_address_groups.return_value = [
        {"name": "GRP-Vendor-DST", "member": ["FQDN-covered"]},
    ]
    client.get_policy_packages.return_value = [{"name": "pkg1", "path": "pkg1"}]
    client.get_policies.return_value = [
        {
            "policyid": 10, "name": "ALLOW-VENDOR", "status": "enable", "action": 1,
            "dstaddr": ["GRP-Vendor-DST"],
        }
    ]

    result = search_fqdn_rules(
        client, "OT-ADOM", "FW-A", ["covered.vendor.com", "uncovered.vendor.com"]
    )

    by_fqdn = {r["fqdn"]: r for r in result["results"]}
    assert by_fqdn["covered.vendor.com"]["covered"] is True
    assert by_fqdn["covered.vendor.com"]["rule_id"] == 10
    assert by_fqdn["covered.vendor.com"]["via_group"] == "GRP-Vendor-DST"
    assert by_fqdn["uncovered.vendor.com"]["covered"] is False
    assert result["degraded"] is False
    assert result["packages_searched"] == ["pkg1"]


def test_search_fqdn_rules_degrades_on_policy_fetch_failure():
    from app.planner.catalogs import search_fqdn_rules

    client = MagicMock()
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_policy_packages.return_value = [{"name": "pkg1", "path": "pkg1"}]
    client.get_policies.side_effect = RuntimeError("timeout")

    result = search_fqdn_rules(client, "OT-ADOM", "FW-A", ["x.vendor.com"])
    assert result["degraded"] is True
    assert result["packages_failed"][0]["package"] == "pkg1"


# ── Finding 6: only accept policies count as coverage ──────────────────────

def _fqdn_search_client(policy_action):
    """MagicMock FMG client with one FQDN object referenced by one policy
    whose `action` is `policy_action` (omitted entirely when None)."""
    client = MagicMock()
    client.get_address_objects.return_value = [
        {"name": "FQDN-vendor", "type": "fqdn", "fqdn": "api.vendor.com"},
    ]
    client.get_address_groups.return_value = []
    client.get_policy_packages.return_value = [{"name": "pkg1", "path": "pkg1"}]
    pol = {
        "policyid": 10, "name": "RULE", "status": "enable",
        "dstaddr": ["FQDN-vendor"],
    }
    if policy_action is not None:
        pol["action"] = policy_action
    client.get_policies.return_value = [pol]
    return client


def test_search_fqdn_rules_deny_policy_is_not_coverage():
    from app.planner.catalogs import search_fqdn_rules

    # _ACTION_MAP in app.planner.matching: 0 == deny
    result = search_fqdn_rules(
        _fqdn_search_client(0), "OT-ADOM", "FW-A", ["api.vendor.com"]
    )
    row = result["results"][0]
    assert row["covered"] is False
    assert row["rule_id"] is None
    assert result["partial_group_match"] is None


def test_search_fqdn_rules_deny_action_string_is_not_coverage():
    from app.planner.catalogs import search_fqdn_rules

    result = search_fqdn_rules(
        _fqdn_search_client("deny"), "OT-ADOM", "FW-A", ["api.vendor.com"]
    )
    assert result["results"][0]["covered"] is False


def test_search_fqdn_rules_missing_action_is_not_coverage():
    from app.planner.catalogs import search_fqdn_rules

    # FortiGate's implicit default is deny — an absent action must never be
    # optimistically read as accept.
    result = search_fqdn_rules(
        _fqdn_search_client(None), "OT-ADOM", "FW-A", ["api.vendor.com"]
    )
    assert result["results"][0]["covered"] is False


def test_search_fqdn_rules_accept_action_is_coverage():
    from app.planner.catalogs import search_fqdn_rules

    for accept_val in (1, "1", "accept"):
        result = search_fqdn_rules(
            _fqdn_search_client(accept_val), "OT-ADOM", "FW-A", ["api.vendor.com"]
        )
        assert result["results"][0]["covered"] is True, accept_val
        assert result["results"][0]["rule_id"] == 10


def test_search_fqdn_rules_disabled_accept_policy_is_not_coverage():
    from app.planner.catalogs import search_fqdn_rules

    client = _fqdn_search_client(1)
    client.get_policies.return_value[0]["status"] = "disable"
    result = search_fqdn_rules(client, "OT-ADOM", "FW-A", ["api.vendor.com"])
    assert result["results"][0]["covered"] is False
