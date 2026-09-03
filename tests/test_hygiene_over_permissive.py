"""Tests for the over-permissive-rule hygiene check."""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from app.hygiene import check_over_permissive


def _op(policyid, srcaddr, dstaddr, service, action=1, status=1):
    return {
        "policyid": policyid,
        "name": f"rule-{policyid}",
        "action": action,
        "status": status,
        "srcaddr": srcaddr,
        "dstaddr": dstaddr,
        "service": service,
    }


def test_over_permissive_all_three_is_critical():
    p = _op(1, ["all"], ["all"], ["ALL"])
    findings = check_over_permissive([p])
    assert len(findings) == 1
    assert findings[0]["check"] == "over_permissive"
    assert findings[0]["severity"] == "critical"
    assert "Fully open" in findings[0]["detail"]


def test_over_permissive_src_and_svc_is_high():
    p = _op(1, ["all"], ["10.0.0.0/8"], ["ALL"])
    findings = check_over_permissive([p])
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "source" in findings[0]["detail"]
    assert "service" in findings[0]["detail"]


def test_over_permissive_dst_and_svc_is_high():
    p = _op(1, ["10.0.0.1"], ["all"], ["ANY"])
    findings = check_over_permissive([p])
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_over_permissive_src_and_dst_is_high():
    p = _op(1, ["any"], ["any"], ["HTTP"])
    findings = check_over_permissive([p])
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_over_permissive_only_one_dimension_not_flagged():
    p = _op(1, ["all"], ["10.0.0.1"], ["HTTP"])
    findings = check_over_permissive([p])
    assert len(findings) == 0


def test_over_permissive_deny_action_skipped():
    p = _op(1, ["all"], ["all"], ["ALL"], action=0)
    findings = check_over_permissive([p])
    assert len(findings) == 0


def test_over_permissive_disabled_rule_skipped():
    p = _op(1, ["all"], ["all"], ["ALL"], status=0)
    findings = check_over_permissive([p])
    assert len(findings) == 0


def test_over_permissive_policy_block_skipped():
    p = {**_op(1, ["all"], ["all"], ["ALL"]), "_policy_block": "ThreatFeeds-VDOMs"}
    findings = check_over_permissive([p])
    assert len(findings) == 0
