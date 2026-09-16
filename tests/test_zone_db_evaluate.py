import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import app.zone_db as zdb


def _allow_only_policy(services):
    return {
        "policy_set": "Corp",
        "from_zone": "Internet",
        "to_zone": "Internal-Wifi",
        "access_type": "allow only",
        "severity": "high",
        "services": services,
        "description": "",
    }


def test_allow_only_permits_listed_service():
    policies = [_allow_only_policy(["ssh", "https"])]
    verdict, rules = zdb.evaluate(policies, ["ssh"])
    assert verdict == "ALLOWED"
    assert rules == [policies[0]]


def test_allow_only_blocks_unlisted_service():
    policies = [_allow_only_policy(["ssh", "https"])]
    verdict, rules = zdb.evaluate(policies, ["tcp/3389"])
    assert verdict == "BLOCKED"
    assert rules == [policies[0]]


def test_no_policy_returns_unknown():
    verdict, rules = zdb.evaluate([], ["ssh"])
    assert verdict == "UNKNOWN"
    assert rules == []
