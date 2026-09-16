"""Tests for app.planner.engine.plan_change — the deterministic core."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.planner import standards
from app.planner.engine import plan_change
from app.planner.models import PlannerDataError, TargetFirewall
from app.planner.zone_adapter import ZoneDBAdapter

_REPO_ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def _use_example_standards_files(monkeypatch):
    """plan_change() reads naming.yaml/review_requirements.yaml via
    standards.load_naming()/review_requirements() with no path override, so
    it always hits the real (gitignored, team-maintained) files. Point it at
    the committed .example.yaml templates instead so these tests are
    self-contained and don't depend on runtime config existing on disk."""
    monkeypatch.setattr(standards, "_NAMING_FILE", _REPO_ROOT / "naming.example.yaml")
    monkeypatch.setattr(
        standards, "_REVIEW_FILE", _REPO_ROOT / "review_requirements.example.yaml"
    )


def _zone_client(verdict="ALLOWED", src_zones=("DMZ",), dst_zones=("Internet",)):
    zc = MagicMock(spec=ZoneDBAdapter)
    zc.query.return_value = [
        {
            "src": "x",
            "dst": "y",
            "service": "z",
            "verdict": verdict,
            "src_zones": list(src_zones),
            "dst_zones": list(dst_zones),
            "governing": [{"policy_set": "Corp", "access_type": "allow all"}],
            "all_policies": [],
        }
    ]
    zc.zones.return_value = {
        "zones": [
            {"name": "DMZ", "domain": "Default"},
            {"name": "Internet", "domain": "Default"},
        ]
    }
    zc.policies.return_value = []
    return zc


def _fmg_client_with_no_devices():
    client = MagicMock()
    client.get_devices.return_value = []
    return client


def test_plan_change_unknown_verdict_skips_firewall_analysis():
    zc = _zone_client(verdict="UNKNOWN", src_zones=(), dst_zones=())
    zc.zones.return_value = {"zones": []}  # no Internet zone → stays UNKNOWN
    plan = plan_change(
        src="1.2.3.4",
        dst="5.6.7.8",
        service="tcp/443",
        firewalls=[TargetFirewall(device="FW-A", adom="OT-ADOM")],
        zone_client=zc,
        fmg_client=MagicMock(),
    )
    assert plan.cli_status == "unknown_no_action"
    assert plan.firewalls[0].status == "no_action"


def test_plan_change_mixed_verdicts_raises():
    zc = MagicMock(spec=ZoneDBAdapter)

    def query_side_effect(src, dst, service, verbose=True):
        verdict = "ALLOWED" if dst == "5.6.7.8" else "BLOCKED"
        return [
            {
                "src": src,
                "dst": dst,
                "service": service,
                "verdict": verdict,
                "src_zones": ["DMZ"],
                "dst_zones": ["Internet"],
                "governing": [{"policy_set": "Corp", "access_type": "block all"}],
                "all_policies": [],
            }
        ]

    zc.query.side_effect = query_side_effect
    zc.zones.return_value = {
        "zones": [
            {"name": "DMZ", "domain": "Default"},
            {"name": "Internet", "domain": "Default"},
        ]
    }

    with pytest.raises(PlannerDataError) as exc_info:
        plan_change(
            src="1.2.3.4",
            dst="5.6.7.8, 9.9.9.9",
            service="tcp/443",
            firewalls=[TargetFirewall(device="FW-A", adom="OT-ADOM")],
            zone_client=zc,
            fmg_client=MagicMock(),
        )
    assert exc_info.value.source == "request"


def test_plan_change_device_not_found_reports_error_status():
    zc = _zone_client()
    client = _fmg_client_with_no_devices()
    plan = plan_change(
        src="1.2.3.4",
        dst="5.6.7.8",
        service="tcp/443",
        firewalls=[TargetFirewall(device="FW-MISSING", adom="OT-ADOM")],
        zone_client=zc,
        fmg_client=client,
    )
    assert plan.firewalls[0].status == "not_found"
    assert (
        plan.cli_status == "new_rule"
    )  # not "already_covered" — device errored, not covered


def test_plan_change_already_covered_all_firewalls():
    zc = _zone_client()
    client = MagicMock()
    client.get_devices.return_value = [{"name": "FW-A"}]
    client.get_policy_packages.return_value = [{"name": "Pkg1", "scope member": []}]
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []
    client.get_device_interfaces.return_value = [
        {"name": "port1", "ip": "10.0.0.1 255.255.255.0"}
    ]
    client.get_device_routes.return_value = []
    client.get_policies.return_value = [
        {
            "policyid": 5,
            "name": "EXISTING",
            "status": "enable",
            "action": 1,
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "srcintf": ["any"],
            "dstintf": ["any"],
            "schedule": ["always"],
        }
    ]
    plan = plan_change(
        src="10.0.0.5",
        dst="10.0.0.6",
        service="tcp/443",
        firewalls=[TargetFirewall(device="FW-A", adom="OT-ADOM")],
        zone_client=zc,
        fmg_client=client,
    )
    assert plan.firewalls[0].status == "already_covered"
    assert plan.cli_status == "already_covered"


def test_plan_change_new_rule_generates_cli_and_naming():
    zc = _zone_client()
    client = MagicMock()
    client.get_devices.return_value = [{"name": "FW-A"}]
    client.get_policy_packages.return_value = [{"name": "Pkg1", "scope member": []}]
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []
    client.get_device_interfaces.return_value = [
        {"name": "port1", "ip": "10.0.0.1 255.255.255.0"},
        {"name": "port2", "ip": "192.168.1.1 255.255.255.0"},
    ]
    client.get_device_routes.return_value = []
    client.get_policies.return_value = []  # no existing rules

    plan = plan_change(
        src="10.0.0.5",
        dst="192.168.1.50",
        service="tcp/8443",
        ticket_id="CHG0001",
        firewalls=[TargetFirewall(device="FW-A", adom="OT-ADOM")],
        zone_client=zc,
        fmg_client=client,
    )
    fw = plan.firewalls[0]
    assert fw.status == "new_rule"
    assert fw.srcintf == "port1"
    assert fw.dstintf == "port2"
    assert "CHG0001" in fw.policy_cli
    assert plan.cli_status == "new_rule"
    assert plan.naming["objects"]  # at least the two address objects + one service


def test_group_blast_radius_uses_package_path_not_name():
    """_group_blast_radius must call get_policies() with the package's full
    path (folder-organized ADOMs), not just its bare name."""
    from app.planner.engine import _group_blast_radius
    from app.planner.fetch import DeviceSnapshot

    client = MagicMock()
    client.get_policy_packages.return_value = [
        {"name": "MyPackage", "path": "MyFolder/MyPackage", "scope member": []}
    ]
    client.get_policies.return_value = []

    addr_catalog = MagicMock()
    addr_catalog.groups_containing.return_value = set()
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=addr_catalog,
        svc_catalog=MagicMock(),
        interfaces=[],
        routing_table=[],
    )

    _group_blast_radius(client, snapshot, "SOME_GROUP", exclude=("other", 1))

    called_args = [c.args for c in client.get_policies.call_args_list]
    assert ("OT-ADOM", "MyFolder/MyPackage") in called_args
    assert ("OT-ADOM", "MyPackage") not in called_args


def test_plan_change_blocked_verdict_generates_exception_cli():
    """BLOCKED verdict → cli_status 'blocked_exception' and the generated
    CLI carries an EXCEPTION comment instead of the normal ticket comment —
    a high-consequence path that previously had zero test coverage."""
    zc = _zone_client(verdict="BLOCKED")
    client = MagicMock()
    client.get_devices.return_value = [{"name": "FW-A"}]
    client.get_policy_packages.return_value = [{"name": "Pkg1", "scope member": []}]
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []
    client.get_device_interfaces.return_value = [
        {"name": "port1", "ip": "10.0.0.1 255.255.255.0"},
        {"name": "port2", "ip": "192.168.1.1 255.255.255.0"},
    ]
    client.get_device_routes.return_value = []
    client.get_policies.return_value = []  # no existing rules

    plan = plan_change(
        src="10.0.0.5",
        dst="192.168.1.50",
        service="tcp/8443",
        ticket_id="CHG0001",
        firewalls=[TargetFirewall(device="FW-A", adom="OT-ADOM")],
        zone_client=zc,
        fmg_client=client,
    )
    fw = plan.firewalls[0]
    assert plan.cli_status == "blocked_exception"
    assert "EXCEPTION" in fw.policy_cli


def test_to_report_payload_has_expected_top_level_keys():
    from app.planner.engine import to_report_payload

    zc = _zone_client()
    client = MagicMock()
    client.get_devices.return_value = [{"name": "FW-A"}]
    client.get_policy_packages.return_value = []
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []
    client.get_device_interfaces.return_value = []
    client.get_device_routes.return_value = []

    plan = plan_change(
        src="10.0.0.5",
        dst="192.168.1.50",
        service="tcp/8443",
        firewalls=[TargetFirewall(device="FW-A", adom="OT-ADOM")],
        zone_client=zc,
        fmg_client=client,
    )
    payload = to_report_payload(plan)
    assert set(payload.keys()) == {
        "ticket_id",
        "request",
        "zone_verdict",
        "existing_rules",
        "naming",
        "logging",
        "approval",
        "recommendation",
        "cli",
    }


def test_plan_change_rejects_non_ip_src():
    with pytest.raises(PlannerDataError, match="plan_fqdn_change"):
        plan_change(
            src="not-an-ip.example.com",
            dst="10.0.0.6",
            service="tcp/443",
            firewalls=[TargetFirewall(device="FW-A", adom="OT-ADOM")],
        )


def test_plan_change_rejects_non_ip_dst():
    with pytest.raises(PlannerDataError, match="plan_fqdn_change"):
        plan_change(
            src="10.0.0.5",
            dst="*.vendor.com",
            service="tcp/443",
            firewalls=[TargetFirewall(device="FW-A", adom="OT-ADOM")],
        )


def _fqdn_entry(fqdn="new.vendor.com", ports=(443,), protocol="TCP"):
    from app.planner.models import FQDNEntry

    return FQDNEntry(
        fqdn=fqdn,
        is_wildcard=fqdn.startswith("*."),
        ports=list(ports),
        protocol=protocol,
        required=True,
        comment="",
    )


def test_plan_fqdn_change_proposes_objects_for_uncovered_entries():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )

    fake_fmg = MagicMock()
    fake_fmg.get_devices.return_value = [{"name": "FW-A"}]
    fake_fmg.get_policy_packages.return_value = [{"name": "pkg1", "path": "pkg1"}]
    fake_fmg.get_policies.return_value = []
    fake_fmg.get_address_objects.return_value = []
    fake_fmg.get_address_groups.return_value = []
    fake_fmg.get_service_objects.return_value = []
    fake_fmg.get_service_groups.return_value = []
    fake_fmg.get_device_interfaces.return_value = []
    fake_fmg.get_device_routes.return_value = []

    fake_zc = MagicMock()
    fake_zc.query.return_value = [
        {
            "verdict": "ALLOWED",
            "src_zones": ["OT-LAN"],
            "dst_zones": ["Internet"],
            "governing": [],
            "all_policies": [],
        }
    ]
    fake_zc.zones.return_value = {"zones": [], "total_subnets": 0}

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)

    assert len(plan.per_firewall) == 1
    fw = plan.per_firewall[0]
    assert fw.firewall == "FW-A"
    assert fw.adom == "OT-ADOM"
    assert fw.coverage == "new_rule"
    assert len(fw.proposed_objects) == 1
    assert fw.proposed_objects[0].name == "FQDN-new.vendor.com"
    assert fw.proposed_group.name == "GRP-Vendor-Co-API-DST"
    assert "SVC_TCP_443" in fw.proposed_policy["service"]
    # The real ticket_id ("CHG1") must appear in every generated comment —
    # not the literal "<TICKET_ID>" placeholder — across every CLI block.
    assert "CHG1" in fw.proposed_objects[0].cli
    assert "<TICKET_ID>" not in fw.proposed_objects[0].cli
    assert "CHG1" in fw.proposed_group.cli
    assert "<TICKET_ID>" not in fw.proposed_group.cli
    assert "CHG1" in fw.proposed_policy["cli"]
    assert "<TICKET_ID>" not in fw.proposed_policy["cli"]


def _base_fqdn_fmg_mock(**overrides):
    fake_fmg = MagicMock()
    fake_fmg.get_devices.return_value = [{"name": "FW-A"}]
    fake_fmg.get_policy_packages.return_value = [
        {"name": "pkg1", "path": "pkg1"},
        {"name": "pkg2", "path": "pkg2"},
    ]
    fake_fmg.get_policies.return_value = []
    fake_fmg.get_address_objects.return_value = []
    fake_fmg.get_address_groups.return_value = []
    fake_fmg.get_service_objects.return_value = []
    fake_fmg.get_service_groups.return_value = []
    fake_fmg.get_device_interfaces.return_value = []
    fake_fmg.get_device_routes.return_value = []
    for k, v in overrides.items():
        getattr(fake_fmg, k).return_value = v
    return fake_fmg


def _base_fqdn_zc_mock():
    fake_zc = MagicMock()
    fake_zc.query.return_value = [
        {
            "verdict": "ALLOWED",
            "src_zones": ["OT-LAN"],
            "dst_zones": ["Internet"],
            "governing": [],
            "all_policies": [],
        }
    ]
    fake_zc.zones.return_value = {"zones": [], "total_subnets": 0}
    return fake_zc


def test_plan_fqdn_change_uses_actually_installed_package_not_first_scoped():
    """Two packages are scoped to this ADOM; only "pkg2" is actually
    installed on the device per FortiManager's device database — the
    proposed policy's package must be "pkg2", not "pkg1" (the first
    package FortiManager happened to list)."""
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )
    fake_fmg = _base_fqdn_fmg_mock(
        get_device_policy_package=[{"name": "pkg2", "vdom": "root"}],
    )

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=_base_fqdn_zc_mock())

    fw = plan.per_firewall[0]
    assert fw.proposed_policy["package"] == "pkg2"


def test_plan_fqdn_change_multi_vdom_prefers_root_and_warns():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )
    fake_fmg = _base_fqdn_fmg_mock(
        get_device_policy_package=[
            {"name": "pkg1", "vdom": "dmz"},
            {"name": "pkg2", "vdom": "root"},
        ],
    )

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=_base_fqdn_zc_mock())

    fw = plan.per_firewall[0]
    assert fw.proposed_policy["package"] == "pkg2"
    assert any("policy packages installed across VDOMs" in w for w in fw.warnings)


def test_plan_fqdn_change_no_installed_package_falls_back_and_warns():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )
    fake_fmg = _base_fqdn_fmg_mock(get_device_policy_package=[])

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=_base_fqdn_zc_mock())

    fw = plan.per_firewall[0]
    assert fw.proposed_policy["package"] == "pkg1"  # first ADOM-scoped package
    assert any(
        "Could not determine the policy package actually installed" in w
        for w in fw.warnings
    )


def test_plan_fqdn_change_missing_ticket_id_falls_back_to_placeholder():
    """No ticket_id supplied -> the literal <TICKET_ID> placeholder is kept
    (an engineer fills it in before applying), never a blank/None comment."""
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )

    fake_fmg = MagicMock()
    fake_fmg.get_devices.return_value = [{"name": "FW-A"}]
    fake_fmg.get_policy_packages.return_value = [{"name": "pkg1", "path": "pkg1"}]
    fake_fmg.get_policies.return_value = []
    fake_fmg.get_address_objects.return_value = []
    fake_fmg.get_address_groups.return_value = []
    fake_fmg.get_service_objects.return_value = []
    fake_fmg.get_service_groups.return_value = []
    fake_fmg.get_device_interfaces.return_value = []
    fake_fmg.get_device_routes.return_value = []

    fake_zc = MagicMock()
    fake_zc.query.return_value = [
        {
            "verdict": "ALLOWED",
            "src_zones": ["OT-LAN"],
            "dst_zones": ["Internet"],
            "governing": [],
            "all_policies": [],
        }
    ]
    fake_zc.zones.return_value = {"zones": [], "total_subnets": 0}

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)
    fw = plan.per_firewall[0]
    assert "<TICKET_ID>" in fw.proposed_objects[0].cli
    assert "<TICKET_ID>" in fw.proposed_group.cli
    assert "<TICKET_ID>" in fw.proposed_policy["cli"]


def test_plan_fqdn_change_resolves_dstintf_via_default_route():
    """dstintf is resolved directly from the device's default route
    (0.0.0.0/0), not by overlap-matching an internet-sentinel IP."""
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )

    fake_fmg = MagicMock()
    fake_fmg.get_devices.return_value = [{"name": "FW-A"}]
    fake_fmg.get_policy_packages.return_value = [{"name": "pkg1", "path": "pkg1"}]
    fake_fmg.get_policies.return_value = []
    fake_fmg.get_address_objects.return_value = []
    fake_fmg.get_address_groups.return_value = []
    fake_fmg.get_service_objects.return_value = []
    fake_fmg.get_service_groups.return_value = []
    fake_fmg.get_device_interfaces.return_value = [
        {"name": "port1", "ip": "10.0.0.1 255.255.255.0"}
    ]
    fake_fmg.get_device_routes.return_value = [
        {"ip_mask": "0.0.0.0/0", "interface": "wan1", "status": "enable"},
    ]

    fake_zc = MagicMock()
    fake_zc.query.return_value = [
        {
            "verdict": "ALLOWED",
            "src_zones": ["OT-LAN"],
            "dst_zones": ["Internet"],
            "governing": [],
            "all_policies": [],
        }
    ]
    fake_zc.zones.return_value = {"zones": [], "total_subnets": 0}

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)

    fw = plan.per_firewall[0]
    assert fw.proposed_policy["dstintf"] == "wan1"
    assert fw.proposed_policy["srcintf"] == "port1"
    assert not any("8.8.8.8" in w for w in fw.warnings)


def test_plan_fqdn_change_no_default_route_warns_and_falls_back_to_any():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )

    fake_fmg = MagicMock()
    fake_fmg.get_devices.return_value = [{"name": "FW-A"}]
    fake_fmg.get_policy_packages.return_value = [{"name": "pkg1", "path": "pkg1"}]
    fake_fmg.get_policies.return_value = []
    fake_fmg.get_address_objects.return_value = []
    fake_fmg.get_address_groups.return_value = []
    fake_fmg.get_service_objects.return_value = []
    fake_fmg.get_service_groups.return_value = []
    fake_fmg.get_device_interfaces.return_value = []
    fake_fmg.get_device_routes.return_value = []  # no default route synced

    fake_zc = MagicMock()
    fake_zc.query.return_value = [
        {
            "verdict": "ALLOWED",
            "src_zones": ["OT-LAN"],
            "dst_zones": ["Internet"],
            "governing": [],
            "all_policies": [],
        }
    ]
    fake_zc.zones.return_value = {"zones": [], "total_subnets": 0}

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)

    fw = plan.per_firewall[0]
    assert fw.proposed_policy["dstintf"] == "any"
    assert any("No enabled default route" in w for w in fw.warnings)


def test_plan_fqdn_change_invalid_firewall_spec_yields_error_plan():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip="any",
        ticket_id="CHG1",
        firewalls=["not-a-valid-spec"],
        entries=[_fqdn_entry()],
    )
    plan = plan_fqdn_change(req, fmg_client=MagicMock(), zone_client=MagicMock())
    assert plan.per_firewall[0].verdict == "error"
    assert plan.per_firewall[0].degraded is True


def test_to_fqdn_report_payload_shape():
    from app.planner.engine import to_fqdn_report_payload
    from app.planner.models import (
        FQDNAllowlistRequest,
        FQDNChangePlan,
        FQDNFirewallPlan,
    )

    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )
    fw_plan = FQDNFirewallPlan(
        firewall="FW-A",
        adom="OT-ADOM",
        verdict="new_rule",
        src_zone="OT-LAN",
        coverage="new_rule",
        covered_entries=[],
        uncovered_entries=[_fqdn_entry()],
        proposed_objects=[],
        proposed_group=None,
        proposed_policy=None,
        group_append_alternative=None,
        degraded=False,
        warnings=["w1"],
    )
    plan = FQDNChangePlan(request=req, per_firewall=[fw_plan])

    payload = to_fqdn_report_payload(plan)
    assert payload["plan_type"] == "fqdn_allowlist"
    assert payload["vendor"] == "V"
    assert payload["per_firewall"][0]["firewall"] == "FW-A"
    assert payload["warnings"] == ["w1"]


# ---------------------------------------------------------------------------
# FQDN planner — additional coverage (fix round 1)
# ---------------------------------------------------------------------------


def _fqdn_zone_client(
    verdict="ALLOWED", src_zones=("OT-LAN",), dst_zones=("Internet",)
):
    zc = MagicMock()
    zc.query.return_value = [
        {
            "verdict": verdict,
            "src_zones": list(src_zones),
            "dst_zones": list(dst_zones),
            "governing": [],
            "all_policies": [],
        }
    ]
    zc.zones.return_value = {"zones": [], "total_subnets": 0}
    return zc


def _fqdn_fmg_base(address_objects=(), address_groups=(), policies=()):
    """MagicMock FMGClient stub with the FQDN-planner defaults; override any
    of the pre-seeded object/group/policy lists via kwargs."""
    fake_fmg = MagicMock()
    fake_fmg.get_devices.return_value = [{"name": "FW-A"}]
    fake_fmg.get_policy_packages.return_value = [{"name": "pkg1", "path": "pkg1"}]
    fake_fmg.get_policies.return_value = list(policies)
    fake_fmg.get_address_objects.return_value = list(address_objects)
    fake_fmg.get_address_groups.return_value = list(address_groups)
    fake_fmg.get_service_objects.return_value = []
    fake_fmg.get_service_groups.return_value = []
    fake_fmg.get_device_interfaces.return_value = []
    fake_fmg.get_device_routes.return_value = []
    return fake_fmg


def test_plan_fqdn_change_malformed_spec_in_zone_error_path_yields_error_not_unknown():
    """Regression for review finding 1: a malformed DEVICE:ADOM spec must
    yield verdict='error' even when it's the zone client itself that fails
    (not just in the main per-firewall validation loop)."""
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest, PlannerDataError

    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["not-a-valid-spec", "FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )

    fake_zc = MagicMock()
    fake_zc.query.side_effect = PlannerDataError("4thealth", "zone db unreachable")

    plan = plan_fqdn_change(req, fmg_client=MagicMock(), zone_client=fake_zc)

    assert len(plan.per_firewall) == 2
    bad, good = plan.per_firewall
    assert bad.firewall == "not-a-valid-spec"
    assert bad.verdict == "error"
    assert bad.degraded is True
    assert "Invalid firewall spec" in bad.warnings[0]

    assert good.firewall == "FW-A"
    assert good.adom == "OT-ADOM"
    assert good.verdict == "unknown_no_action"
    assert good.degraded is True
    assert "Zone client unavailable" in good.warnings[0]


def test_plan_fqdn_change_truncates_long_object_name():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    long_fqdn = "a" * 90 + ".example.com"
    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry(fqdn=long_fqdn)],
    )
    fake_fmg = _fqdn_fmg_base()
    fake_zc = _fqdn_zone_client()

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)
    fw = plan.per_firewall[0]

    assert len(fw.proposed_objects) == 1
    name = fw.proposed_objects[0].name
    assert len(name) == 79
    assert name.endswith("...")
    assert any("truncated" in w for w in fw.warnings)


def test_plan_fqdn_change_disambiguates_colliding_truncated_names():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    base = "a" * 71
    fqdn1 = base + "1" + "b" * 20 + ".com"
    fqdn2 = base + "2" + "b" * 20 + ".com"
    # Both truncate to the same first 76 chars ("FQDN-" + base), so their
    # names collide unless disambiguated.
    assert ("FQDN-" + fqdn1)[:76] == ("FQDN-" + fqdn2)[:76]

    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry(fqdn=fqdn1), _fqdn_entry(fqdn=fqdn2)],
    )
    fake_fmg = _fqdn_fmg_base()
    fake_zc = _fqdn_zone_client()

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)
    fw = plan.per_firewall[0]

    names = [o.name for o in fw.proposed_objects]
    assert len(names) == 2
    assert len(set(names)) == 2  # distinct — no silent overwrite
    assert any("collision" in w for w in fw.warnings)


def test_plan_fqdn_change_unknown_verdict_skips_analysis():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )
    fake_fmg = _fqdn_fmg_base()
    fake_zc = _fqdn_zone_client(verdict="UNKNOWN")

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)
    fw = plan.per_firewall[0]

    assert fw.verdict == "unknown_no_action"
    assert fw.coverage == "n/a"
    assert fw.proposed_objects == []
    fake_fmg.get_devices.assert_not_called()
    fake_fmg.get_address_objects.assert_not_called()


def test_plan_fqdn_change_blocked_verdict_survives_new_rule_analysis():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )
    fake_fmg = _fqdn_fmg_base()
    fake_zc = _fqdn_zone_client(verdict="BLOCKED")

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)
    fw = plan.per_firewall[0]

    assert fw.verdict == "blocked_exception"
    assert fw.coverage == "new_rule"
    assert len(fw.proposed_objects) == 1


def test_plan_fqdn_change_partial_coverage_yields_group_append_alternative():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    covered_fqdn = "covered.vendor.com"
    uncovered_fqdn = "new.vendor.com"
    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry(fqdn=covered_fqdn), _fqdn_entry(fqdn=uncovered_fqdn)],
    )

    address_objects = [
        {"name": "FQDN-covered.vendor.com", "type": "fqdn", "fqdn": covered_fqdn},
    ]
    address_groups = [
        {"name": "GRP-Vendor-Co-API-DST", "member": ["FQDN-covered.vendor.com"]},
    ]
    policies = [
        {
            "policyid": 1,
            "name": "pol1",
            "status": "enable",
            "action": 1,
            "dstaddr": ["GRP-Vendor-Co-API-DST"],
            "srcaddr": [],
            "service": [],
        }
    ]
    fake_fmg = _fqdn_fmg_base(
        address_objects=address_objects,
        address_groups=address_groups,
        policies=policies,
    )
    fake_zc = _fqdn_zone_client()

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)
    fw = plan.per_firewall[0]

    assert fw.coverage == "partial_coverage"
    assert [e.fqdn for e in fw.covered_entries] == [covered_fqdn]
    assert [e.fqdn for e in fw.uncovered_entries] == [uncovered_fqdn]
    assert fw.group_append_alternative is not None
    assert fw.group_append_alternative.group == "GRP-Vendor-Co-API-DST"


def test_plan_fqdn_change_already_covered_when_all_entries_covered():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    fqdn = "covered.vendor.com"
    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry(fqdn=fqdn)],
    )
    address_objects = [
        {"name": "FQDN-covered.vendor.com", "type": "fqdn", "fqdn": fqdn}
    ]
    policies = [
        {
            "policyid": 1,
            "name": "pol1",
            "status": "enable",
            "action": 1,
            "dstaddr": ["FQDN-covered.vendor.com"],
            "srcaddr": [],
            "service": [],
        }
    ]
    fake_fmg = _fqdn_fmg_base(address_objects=address_objects, policies=policies)
    fake_zc = _fqdn_zone_client()

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)
    fw = plan.per_firewall[0]

    assert fw.verdict == "already_covered"
    assert fw.coverage == "already_covered"
    assert fw.proposed_objects == []


def test_plan_fqdn_change_blocked_verdict_not_downgraded_by_full_coverage():
    """A BLOCKED zone verdict must survive even when every entry is already
    covered by an existing rule — it must not be downgraded to
    'already_covered' (the existing `if fw.verdict != 'blocked_exception':`
    guard in _plan_fqdn_firewall)."""
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    fqdn = "covered.vendor.com"
    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry(fqdn=fqdn)],
    )
    address_objects = [
        {"name": "FQDN-covered.vendor.com", "type": "fqdn", "fqdn": fqdn}
    ]
    policies = [
        {
            "policyid": 1,
            "name": "pol1",
            "status": "enable",
            "action": 1,
            "dstaddr": ["FQDN-covered.vendor.com"],
            "srcaddr": [],
            "service": [],
        }
    ]
    fake_fmg = _fqdn_fmg_base(address_objects=address_objects, policies=policies)
    fake_zc = _fqdn_zone_client(verdict="BLOCKED")

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=fake_zc)
    fw = plan.per_firewall[0]

    assert fw.verdict == "blocked_exception"
    assert fw.coverage == "already_covered"


# ── Finding 1: object/group name sanitization ──────────────────────────────

_MALICIOUS = 'evil"\n    next\nend\nconfig system admin\n    edit "pwn\r; rm -rf /'
_ALLOWED_NAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._*-"
)


def test_fqdn_object_name_sanitizes_malicious_input():
    from app.planner.engine import _fqdn_object_name

    obj_type, name = _fqdn_object_name(_MALICIOUS)

    assert obj_type == "fqdn"
    assert name.startswith("FQDN-")
    assert '"' not in name
    assert "\n" not in name and "\r" not in name
    assert " " not in name and ";" not in name and "/" not in name
    assert set(name) <= _ALLOWED_NAME_CHARS


def test_fqdn_object_name_sanitizes_malicious_wildcard_input():
    from app.planner.engine import _fqdn_object_name

    obj_type, name = _fqdn_object_name('*.evil"\nend\nconfig system admin')

    assert obj_type == "wildcard-fqdn"
    assert name.startswith("WFQDN-")
    assert set(name) <= _ALLOWED_NAME_CHARS


def test_fqdn_object_name_preserves_legitimate_values():
    from app.planner.engine import _fqdn_object_name

    assert _fqdn_object_name("api.vendor.com") == ("fqdn", "FQDN-api.vendor.com")
    assert _fqdn_object_name("*.push.apple.com") == (
        "wildcard-fqdn",
        "WFQDN-push.apple.com",
    )


def test_fqdn_group_name_sanitizes_malicious_vendor_and_category():
    from app.planner.engine import _fqdn_group_name

    name = _fqdn_group_name(_MALICIOUS, 'cat"\nend')

    assert name.startswith("GRP-")
    assert name.endswith("-DST")
    assert '"' not in name
    assert "\n" not in name and "\r" not in name
    assert set(name) <= _ALLOWED_NAME_CHARS


def test_fqdn_group_name_preserves_legitimate_values():
    from app.planner.engine import _fqdn_group_name

    assert _fqdn_group_name("Vendor Co", "API") == "GRP-Vendor-Co-API-DST"


def test_plan_fqdn_change_generated_cli_has_no_injected_statements():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor=_MALICIOUS,
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry(fqdn='bad"\nend\nconfig system admin\n    edit "x')],
    )
    plan = plan_fqdn_change(
        req, fmg_client=_fqdn_fmg_base(), zone_client=_fqdn_zone_client()
    )
    fw = plan.per_firewall[0]

    obj_cli = fw.proposed_objects[0].cli
    lines = [ln.strip() for ln in obj_cli.splitlines()]
    assert len([ln for ln in lines if ln.startswith("edit ")]) == 1
    assert lines.count("end") == 1
    assert "config system admin" not in lines

    grp_lines = [ln.strip() for ln in fw.proposed_group.cli.splitlines()]
    assert len([ln for ln in grp_lines if ln.startswith("edit ")]) == 1
    assert "config system admin" not in grp_lines


# ── Finding 4b: 'all' source must be warned about ──────────────────────────


@pytest.mark.parametrize("src_ip", ["", "any", "all", "ANY", "  All  "])
def test_plan_fqdn_change_warns_when_source_is_builtin_all(src_ip):
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip=src_ip,
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )
    plan = plan_fqdn_change(
        req, fmg_client=_fqdn_fmg_base(), zone_client=_fqdn_zone_client()
    )
    fw = plan.per_firewall[0]

    assert fw.proposed_policy["srcaddr"] == ["all"]
    assert any("permit traffic from ANY source" in w for w in fw.warnings), fw.warnings


def test_plan_fqdn_change_no_all_source_warning_for_specific_ip():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    req = FQDNAllowlistRequest(
        vendor="V",
        category="C",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry()],
    )
    plan = plan_fqdn_change(
        req, fmg_client=_fqdn_fmg_base(), zone_client=_fqdn_zone_client()
    )
    fw = plan.per_firewall[0]

    assert not any("permit traffic from ANY source" in w for w in fw.warnings)


# ── Finding 8: group-append alternative carries no blast radius ────────────


def test_fqdn_group_append_alternative_warns_blast_radius_not_computed():
    from app.planner.engine import plan_fqdn_change
    from app.planner.models import FQDNAllowlistRequest

    covered_fqdn = "covered.vendor.com"
    uncovered_fqdn = "new.vendor.com"
    req = FQDNAllowlistRequest(
        vendor="Vendor Co",
        category="API",
        src_ip="10.0.0.5",
        ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"],
        entries=[_fqdn_entry(fqdn=covered_fqdn), _fqdn_entry(fqdn=uncovered_fqdn)],
    )
    fake_fmg = _fqdn_fmg_base(
        address_objects=[
            {"name": "FQDN-covered.vendor.com", "type": "fqdn", "fqdn": covered_fqdn},
        ],
        address_groups=[
            {"name": "GRP-Vendor-Co-API-DST", "member": ["FQDN-covered.vendor.com"]},
        ],
        policies=[
            {
                "policyid": 1,
                "name": "pol1",
                "status": "enable",
                "action": 1,
                "dstaddr": ["GRP-Vendor-Co-API-DST"],
                "srcaddr": [],
                "service": [],
            }
        ],
    )

    plan = plan_fqdn_change(req, fmg_client=fake_fmg, zone_client=_fqdn_zone_client())
    alt = plan.per_firewall[0].group_append_alternative

    assert alt is not None
    # affected_policies is empty because it is not computed on this path — the
    # warning is what stops that from reading as "no other policies affected".
    assert alt.affected_policies == []
    assert any("Blast radius not computed" in w for w in alt.warnings), alt.warnings
    assert any("GRP-Vendor-Co-API-DST" in w for w in alt.warnings)
