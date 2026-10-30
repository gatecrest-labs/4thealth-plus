"""Tests for the Rule Lookup background cache."""

import ipaddress
from unittest.mock import patch

import pytest

import app.rule_lookup_cache as rlc


class FakeClient:
    def __init__(self, packages, policies, pblocks=None, adoms=None, fail_adom=False):
        self.packages = packages
        self.policies = policies  # pkg_path -> list | Exception
        self.pblocks = pblocks or {}
        self.adoms = adoms or []
        self.fail_adom = fail_adom

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_adoms(self):
        return self.adoms

    def get_policy_packages(self, adom):
        if self.fail_adom:
            raise RuntimeError("fmg down")
        return self.packages

    def get_policies(self, adom, path):
        val = self.policies[path]
        if isinstance(val, Exception):
            raise val
        return val

    def get_pblock_policies(self, adom, name, strict=False):
        val = self.pblocks.get(name, [])
        if isinstance(val, Exception):
            raise val
        return val

    def get_address_objects(self, adom, scope="all"):
        return [{"name": "corp", "subnet": ["10.1.0.0", "255.255.0.0"]}]

    def get_address_groups(self, adom, scope="all"):
        return []

    def get_vip_objects(self, adom):
        return []

    def get_service_objects(self, adom, scope="all"):
        return [{"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}]

    def get_service_groups(self, adom, scope="all"):
        return []


def _pkg(name, member="fw1", vdom="root"):
    return {
        "name": name,
        "path": name,
        "type": "pkg",
        "scope member": [{"name": member, "vdom": vdom}],
    }


def _policy(pid, **kw):
    base = {
        "policyid": pid,
        "name": f"rule{pid}",
        "srcaddr": ["corp"],
        "dstaddr": ["all"],
        "service": ["HTTPS"],
        "srcintf": ["port1"],
        "dstintf": ["port2"],
        "action": "accept",
        "status": "enable",
    }
    base.update(kw)
    return base


@pytest.fixture(autouse=True)
def _clean_store():
    rlc._store.clear()
    yield
    rlc._store.clear()


def _run(client, adom="Ent"):
    with patch("app.rule_lookup_cache.make_client", return_value=client):
        rlc.refresh_adom(adom)
    return rlc.get_adom(adom)


def test_rules_stored_with_firewall_and_package():
    client = FakeClient(
        [_pkg("PkgA"), _pkg("PkgB", "fw2", "dmz")],
        {"PkgA": [_policy(1)], "PkgB": [_policy(2)]},
    )
    entry = _run(client)
    assert entry["status"] == "ok"
    by_pkg = {r["package"]: r for r in entry["rules"]}
    assert by_pkg["PkgA"]["firewalls"] == ["fw1 / root"]
    assert by_pkg["PkgB"]["firewalls"] == ["fw2 / dmz"]
    assert by_pkg["PkgA"]["srcaddr"] == ["corp"]
    assert by_pkg["PkgA"]["srcaddr_negate"] is False
    assert entry["ctx"].svc_names == {"https": "HTTPS"}
    assert entry["ctx"].addr["corp"] == frozenset({ipaddress.ip_network("10.1.0.0/16")})


def test_negate_flag_is_captured():
    client = FakeClient(
        [_pkg("P")], {"P": [_policy(1, **{"srcaddr-negate": "enable"})]}
    )
    assert _run(client)["rules"][0]["srcaddr_negate"] is True


def test_package_error_is_isolated():
    client = FakeClient(
        [_pkg("Good"), _pkg("Bad")],
        {"Good": [_policy(1)], "Bad": RuntimeError("boom")},
    )
    entry = _run(client)
    assert [r["package"] for r in entry["rules"]] == ["Good"]
    assert len(entry["package_errors"]) == 1
    assert "Bad" in entry["package_errors"][0]


def test_policy_block_is_expanded():
    client = FakeClient(
        [_pkg("P")],
        {"P": [{"_policy_block": "Blk"}, _policy(2)]},
        pblocks={"Blk": [_policy(7, name="in-block")]},
    )
    rules = _run(client)["rules"]
    blk = [r for r in rules if r["policy_block"] == "Blk"]
    assert [r["name"] for r in blk] == ["in-block"]
    assert any(r["policy_block"] == "" for r in rules)


def test_folders_are_skipped():
    client = FakeClient(
        [{"name": "F", "path": "F", "type": "folder"}, _pkg("P")], {"P": [_policy(1)]}
    )
    assert [r["package"] for r in _run(client)["rules"]] == ["P"]


def test_failed_refresh_keeps_previous_data():
    good = FakeClient([_pkg("P")], {"P": [_policy(1)]})
    _run(good)
    entry = _run(FakeClient([], {}, fail_adom=True))
    assert entry["status"] == "error"
    assert "fmg down" in entry["error"]
    assert len(entry["rules"]) == 1


def test_get_adom_unknown_is_none():
    assert rlc.get_adom("Nope") is None


def test_job_skips_forti_adoms():
    client = FakeClient([], {}, adoms=[{"name": "FortiManager_x"}, {"name": "Ent"}])
    seen = []
    with (
        patch("app.rule_lookup_cache.make_client", return_value=client),
        patch("app.rule_lookup_cache.refresh_adom", side_effect=seen.append),
    ):
        rlc._run_job(None)
    assert seen == ["Ent"]


def test_failed_policy_block_is_reported_not_silently_dropped():
    client = FakeClient(
        [_pkg("P")],
        {"P": [{"_policy_block": "Blk"}, _policy(2)]},
        pblocks={"Blk": RuntimeError("pblock denied")},
    )
    entry = _run(client)
    assert [r["name"] for r in entry["rules"]] == ["rule2"]
    assert any("Blk" in e for e in entry["package_errors"])


def test_group_with_unresolvable_member_still_resolves_other_members():
    class C(FakeClient):
        def get_address_groups(self, adom, scope="all"):
            return [{"name": "g", "member": ["corp", "fqdn-obj"]}]

        def get_address_objects(self, adom, scope="all"):
            return [
                {"name": "corp", "subnet": ["10.1.0.0", "255.255.0.0"]},
                {"name": "fqdn-obj", "type": "fqdn", "fqdn": "x.example.com"},
            ]

    entry = _run(C([_pkg("P")], {"P": [_policy(1)]}))
    assert entry["ctx"].addr["g"] == frozenset({ipaddress.ip_network("10.1.0.0/16")})


def test_is_stale_respects_interval_and_running_status():
    from datetime import UTC, datetime, timedelta

    old = (datetime.now(UTC) - timedelta(minutes=120)).isoformat()
    fresh = datetime.now(UTC).isoformat()
    assert rlc.is_stale({"last_updated": old, "status": "ok"})
    assert not rlc.is_stale({"last_updated": fresh, "status": "ok"})
    assert not rlc.is_stale({"last_updated": old, "status": "running"})
    assert not rlc.is_stale({"last_updated": None, "status": "error"})
