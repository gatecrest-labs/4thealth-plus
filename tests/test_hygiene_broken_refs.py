"""Tests for the broken-references hygiene check."""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from app.hygiene import check_broken_refs


def _pol(pid, srcaddr, dstaddr, service):
    return {
        "policyid": pid,
        "name": f"rule-{pid}",
        "srcaddr": srcaddr,
        "dstaddr": dstaddr,
        "service": service,
    }


def test_broken_refs_none_in_srcaddr_flagged():
    findings = check_broken_refs([_pol(1, ["none"], ["Server-Group"], ["HTTP"])])
    assert len(findings) == 1
    assert findings[0]["check"] == "broken_refs"
    assert "source" in findings[0]["detail"]


def test_broken_refs_none_in_dstaddr_flagged():
    findings = check_broken_refs([_pol(2, ["LAN"], ["none"], ["HTTPS"])])
    assert len(findings) == 1
    assert "destination" in findings[0]["detail"]


def test_broken_refs_none_in_service_flagged():
    findings = check_broken_refs([_pol(3, ["LAN"], ["DMZ"], ["none"])])
    assert len(findings) == 1
    assert "service" in findings[0]["detail"]


def test_broken_refs_none_case_insensitive():
    findings = check_broken_refs([_pol(4, ["NONE"], ["DMZ"], ["HTTP"])])
    assert len(findings) == 1


def test_broken_refs_empty_addr_group_flagged():
    addr_groups = [{"name": "Empty-Grp", "member": []}]
    findings = check_broken_refs(
        [_pol(5, ["Empty-Grp"], ["DMZ"], ["HTTP"])],
        addr_groups=addr_groups,
    )
    assert len(findings) == 1
    assert "Empty-Grp" in findings[0]["detail"]


def test_broken_refs_empty_svc_group_flagged():
    svc_groups = [{"name": "Empty-Svc", "member": []}]
    findings = check_broken_refs(
        [_pol(6, ["LAN"], ["DMZ"], ["Empty-Svc"])],
        svc_groups=svc_groups,
    )
    assert len(findings) == 1
    assert "Empty-Svc" in findings[0]["detail"]


def test_broken_refs_nonempty_group_not_flagged():
    addr_groups = [{"name": "Real-Grp", "member": [{"name": "10.0.0.0/8"}]}]
    findings = check_broken_refs(
        [_pol(7, ["Real-Grp"], ["DMZ"], ["HTTP"])],
        addr_groups=addr_groups,
    )
    assert len(findings) == 0


def test_broken_refs_clean_policy_no_findings():
    findings = check_broken_refs([_pol(8, ["LAN"], ["DMZ"], ["HTTP"])])
    assert len(findings) == 0


def test_broken_refs_policy_block_skipped():
    p = {**_pol(9, ["none"], ["none"], ["none"]), "_policy_block": "ThreatFeeds"}
    findings = check_broken_refs([p])
    assert len(findings) == 0


def test_broken_refs_multiple_issues_in_one_rule():
    findings = check_broken_refs([_pol(10, ["none"], ["none"], ["HTTP"])])
    assert len(findings) == 1
    assert "source" in findings[0]["detail"]
    assert "destination" in findings[0]["detail"]
