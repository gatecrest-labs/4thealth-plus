"""Tests for the missing-security-profile hygiene check."""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from app.hygiene import check_security_profile_gap


def test_security_profile_utm_disabled_accept_flagged():
    policies = [
        {"policyid": 1, "name": "allow-all", "action": 1, "utm-status": "disable"}
    ]
    findings = check_security_profile_gap(policies)
    assert len(findings) == 1
    assert findings[0]["check"] == "missing_security_profile"


def test_security_profile_utm_enabled_no_profiles_flagged():
    policies = [
        {
            "policyid": 2,
            "name": "allow-web",
            "action": 1,
            "utm-status": "enable",
            "ips-sensor": "",
            "av-profile": "",
            "webfilter-profile": "",
            "dnsfilter-profile": "",
            "application-list": "",
        }
    ]
    findings = check_security_profile_gap(policies)
    assert len(findings) == 1


def test_security_profile_utm_enabled_with_ips_passes():
    policies = [
        {
            "policyid": 3,
            "name": "allow-web",
            "action": 1,
            "utm-status": "enable",
            "ips-sensor": "default",
            "av-profile": "",
            "webfilter-profile": "",
            "dnsfilter-profile": "",
            "application-list": "",
        }
    ]
    findings = check_security_profile_gap(policies)
    assert len(findings) == 0


def test_security_profile_deny_action_skipped():
    policies = [
        {"policyid": 4, "name": "deny-all", "action": 0, "utm-status": "disable"}
    ]
    findings = check_security_profile_gap(policies)
    assert len(findings) == 0


def test_security_profile_policy_block_skipped():
    policies = [
        {
            "policyid": 5,
            "name": "block",
            "action": 1,
            "utm-status": "disable",
            "_policy_block": "ThreatFeeds-VDOMs",
        }
    ]
    findings = check_security_profile_gap(policies)
    assert findings == []
