"""Tests for the "exempt" comment whitelist mechanism in run_checks()."""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from app.hygiene import _is_exempt, run_checks


def _rule(policyid, comment="", **overrides):
    base = {
        "policyid": policyid,
        "name": f"rule-{policyid}",
        "action": 1,
        "status": 1,
        "comments": comment,
        "srcaddr": ["all"],
        "dstaddr": ["all"],
        "service": ["ALL"],
        "logtraffic": 0,
    }
    base.update(overrides)
    return base


def test_is_exempt_case_insensitive_substring():
    assert _is_exempt({"comments": "Exempt -- approved by security"})
    assert _is_exempt({"comments": "EXEMPT"})
    assert _is_exempt({"comments": "reviewed, exempt per change 1234"})
    assert not _is_exempt({"comments": "Basic LAN to Internet access."})
    assert not _is_exempt({"comments": ""})
    assert not _is_exempt({})


def test_is_exempt_matches_hygiene_fix_exempt_tag():
    assert _is_exempt({"comments": "Basic LAN access [HygieneFix EXEMPT 2026-09-03]"})


def test_run_checks_skips_exempted_rule_findings():
    exempt_rule = _rule(1, comment="Exempt -- security approved wide-open rule")
    normal_rule = _rule(2, comment="")
    findings = run_checks([exempt_rule, normal_rule], ["over_permissive", "unlogged"])
    ids = {f["policy_id"] for f in findings}
    assert "1" not in ids
    assert "2" in ids


def test_run_checks_shadow_analysis_still_uses_exempted_rule_for_others():
    # Rule 1 is a broad allow-all and exempted -- it should still be counted
    # as the shadowing rule for rule 2, which is NOT exempt and must still
    # be flagged as shadowed. Removing exempted rules from the input list
    # entirely (instead of just filtering the output findings) would hide
    # this real shadow relationship.
    shadowing = _rule(1, comment="Exempt -- intentional catch-all")
    shadowed = _rule(
        2, comment="", srcaddr=["Host-A"], dstaddr=["Host-B"], service=["HTTPS"]
    )
    findings = run_checks([shadowing, shadowed], ["shadow"])
    shadow_findings = [f for f in findings if f["check"] == "shadow"]
    assert len(shadow_findings) == 1
    assert shadow_findings[0]["policy_id"] == "2"
