"""Tests for the redundant-rule hygiene check."""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from app.hygiene import check_redundant_rules


def _p(pid, name, src, dst, svc, action=1, status="enable"):
    return {
        "policyid": pid,
        "name": name,
        "action": action,
        "status": status,
        "srcaddr": [{"name": s} for s in src],
        "dstaddr": [{"name": d} for d in dst],
        "service": [{"name": sv} for sv in svc],
    }


def test_redundant_exact_match_flagged():
    """Two identical enabled rules — later one is flagged."""
    a = _p(1, "rule-a", ["SrcA"], ["DstA"], ["HTTP"])
    b = _p(2, "rule-b", ["SrcA"], ["DstA"], ["HTTP"])
    findings = check_redundant_rules([a, b])
    assert len(findings) == 1
    assert findings[0]["policy_id"] == "2"
    assert findings[0]["check"] == "redundant"
    assert "rule-a" in findings[0]["detail"]


def test_redundant_different_action_not_flagged():
    """Same traffic scope but different actions — not redundant."""
    a = _p(1, "rule-a", ["SrcA"], ["DstA"], ["HTTP"], action=1)
    b = _p(2, "rule-b", ["SrcA"], ["DstA"], ["HTTP"], action=0)
    findings = check_redundant_rules([a, b])
    assert findings == []


def test_redundant_superset_not_flagged():
    """A covers B but B does not cover A — this is shadowing, not redundancy."""
    a = _p(1, "rule-a", ["all"], ["DstA"], ["HTTP"])
    b = _p(2, "rule-b", ["SrcA"], ["DstA"], ["HTTP"])
    findings = check_redundant_rules([a, b])
    assert findings == []


def test_redundant_disabled_rule_skipped():
    """Disabled rules are not evaluated."""
    a = _p(1, "rule-a", ["SrcA"], ["DstA"], ["HTTP"], status="disable")
    b = _p(2, "rule-b", ["SrcA"], ["DstA"], ["HTTP"])
    findings = check_redundant_rules([a, b])
    assert findings == []


def test_redundant_policy_block_skipped():
    """Policy-block entries are skipped."""
    a = _p(1, "rule-a", ["SrcA"], ["DstA"], ["HTTP"])
    b = {
        **_p(2, "rule-b", ["SrcA"], ["DstA"], ["HTTP"]),
        "_policy_block": "ThreatBlock",
    }
    findings = check_redundant_rules([a, b])
    assert findings == []


def test_redundant_each_rule_flagged_once():
    """Three identical rules — only the 2nd and 3rd are flagged, each once."""
    a = _p(1, "rule-a", ["SrcA"], ["DstA"], ["HTTP"])
    b = _p(2, "rule-b", ["SrcA"], ["DstA"], ["HTTP"])
    c = _p(3, "rule-c", ["SrcA"], ["DstA"], ["HTTP"])
    findings = check_redundant_rules([a, b, c])
    flagged_ids = {f["policy_id"] for f in findings}
    assert "2" in flagged_ids
    assert "3" in flagged_ids
    assert "1" not in flagged_ids
