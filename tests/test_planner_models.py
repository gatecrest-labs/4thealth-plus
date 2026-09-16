"""
Tests for the planner models (roundtrip serialization).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.planner.matching import PortRange
from app.planner.models import (
    ChangePlan,
    FirewallPlan,
    InsertionPlan,
    NormalizedFlow,
    ObjectPlan,
    PlannerDataError,
)


def test_models_roundtrip():
    plan = ChangePlan(
        ticket_id="CHG1",
        flow=NormalizedFlow(src="10.1.1.1", dst="10.2.2.2", service="443",
                            service_ranges=[PortRange("tcp", 443, 443)]),
        zone_verdict={"verdict": "ALLOWED"},
        risk_level="high",
        firewalls=[FirewallPlan(
            firewall="FW1", adom="root", status="new_rule",
            objects=[ObjectPlan(role="source", action="create",
                                name="H_10.1.1.1", obj_type="host",
                                value="10.1.1.1/32", cli="config ...")],
            insertion=InsertionPlan(package="pkgA", insert_before_policy_id=7,
                                    rationale="precede deny"),
        )],
        cli_status="new_rule",
        recommendation="ok",
    )
    d = plan.to_dict()
    assert d["firewalls"][0]["insertion"]["insert_before_policy_id"] == 7
    assert d["flow"]["service_ranges"][0]["protocol"] == "tcp"


def test_planner_data_error_fields():
    err = PlannerDataError("fortimanager", "all hosts unreachable")
    assert err.source == "fortimanager"
    assert "unreachable" in err.detail
    assert "[fortimanager]" in str(err)


from app.planner.models import (
    FQDNAddressObject,
    FQDNAddrGroup,
    FQDNAllowlistRequest,
    FQDNChangePlan,
    FQDNEntry,
    FQDNFirewallPlan,
)


def test_fqdn_models_roundtrip():
    entry = FQDNEntry(
        fqdn="push.apple.com", is_wildcard=False, ports=[443, 5223],
        protocol="TCP", required=True, comment="APNs",
    )
    req = FQDNAllowlistRequest(
        vendor="Apple", category="APNs", src_ip="10.1.1.1", ticket_id="CHG1",
        firewalls=["FW-A:OT-ADOM"], entries=[entry],
    )
    obj = FQDNAddressObject(
        name="FQDN-push.apple.com", obj_type="fqdn", value="push.apple.com",
        comment="APNs - CHG1", cli="config firewall address\n...",
    )
    group = FQDNAddrGroup(name="GRP-Apple-APNs-DST", members=[obj.name],
                           comment="Apple APNs - CHG1", cli="config firewall addrgrp\n...")
    fw_plan = FQDNFirewallPlan(
        firewall="FW-A", adom="OT-ADOM", verdict="new_rule", src_zone="OT-LAN",
        coverage="new_rule", covered_entries=[], uncovered_entries=[entry],
        proposed_objects=[obj], proposed_group=group, proposed_policy={"name": "p"},
        group_append_alternative=None, degraded=False, warnings=[],
    )
    plan = FQDNChangePlan(request=req, per_firewall=[fw_plan])

    assert plan.per_firewall[0].proposed_group.name == "GRP-Apple-APNs-DST"
    assert plan.request.entries[0].fqdn == "push.apple.com"
