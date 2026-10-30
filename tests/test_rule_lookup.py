"""Tests for the Rule Lookup matching engine."""

import ipaddress

import pytest

from app.planner.matching import PortRange, ServiceCatalog
from app.rule_lookup import (
    Context,
    Query,
    compare_networks,
    compare_ranges,
    match_rule,
    parse_ip_query,
    parse_port_query,
    resolve_groups,
    search,
)

N = ipaddress.ip_network


def _resolve_none(name):
    return None


# ── parse_ip_query ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("10.1.1.*", "10.1.1.0/24"),
        ("10.1.*.*", "10.1.0.0/16"),
        ("10.1.1.0/24", "10.1.1.0/24"),
        ("10.1.1.0/255.255.255.0", "10.1.1.0/24"),
        ("10.1.1.5", "10.1.1.5/32"),
    ],
)
def test_parse_ip_query_forms(text, expected):
    assert parse_ip_query(text) == [N(expected)]


@pytest.mark.parametrize(
    "text", ["10.1.1.300", "10.1.1.0/33", "abc", "10.*.1.1", "::1", ""]
)
def test_parse_ip_query_rejects_bad_input(text):
    with pytest.raises(ValueError):
        parse_ip_query(text)


# ── compare_networks ──────────────────────────────────────────────────────────


def test_compare_networks_labels():
    assert (
        compare_networks([N("10.1.1.5/32")], frozenset({N("10.1.0.0/16")})) == "broader"
    )
    assert (
        compare_networks([N("10.1.1.0/24")], frozenset({N("10.1.1.2/32")}))
        == "narrower"
    )
    assert (
        compare_networks([N("10.1.1.0/24")], frozenset({N("10.1.1.0/24")})) == "exact"
    )
    assert (
        compare_networks(
            [N("10.1.0.0/16")], frozenset({N("10.1.0.0/24"), N("10.2.0.0/24")})
        )
        == "overlap"
    )
    assert compare_networks([N("10.1.1.0/24")], frozenset({N("10.9.0.0/16")})) is None
    assert compare_networks([N("10.1.1.0/24")], None) is None


# ── parse_port_query / compare_ranges ─────────────────────────────────────────


def test_parse_port_query_bare_port_is_tcp_or_udp():
    alts = parse_port_query("443", _resolve_none)
    assert alts == [[PortRange("tcp", 443, 443)], [PortRange("udp", 443, 443)]]


def test_parse_port_query_proto_port_and_name():
    assert parse_port_query("tcp/443", _resolve_none) == [[PortRange("tcp", 443, 443)]]
    assert parse_port_query("https", _resolve_none) == [[PortRange("tcp", 443, 443)]]


def test_parse_port_query_uses_resolver_for_custom_names():
    alts = parse_port_query("My-App", lambda n: [PortRange("tcp", 8443, 8443)])
    assert alts == [[PortRange("tcp", 8443, 8443)]]


def test_parse_port_query_unknown_name_raises():
    with pytest.raises(ValueError):
        parse_port_query("no-such-svc", _resolve_none)


def test_compare_ranges():
    assert (
        compare_ranges([PortRange("tcp", 443, 443)], [PortRange("tcp", 1, 65535)])
        == "broader"
    )
    assert (
        compare_ranges([PortRange("tcp", 443, 443)], [PortRange("tcp", 443, 443)])
        == "exact"
    )
    assert (
        compare_ranges([PortRange("tcp", 443, 443)], [PortRange("icmp", 0, 65535)])
        is None
    )
    assert compare_ranges([PortRange("tcp", 443, 443)], None) is None


# ── match_rule / search ───────────────────────────────────────────────────────


def _rule(**kw):
    base = {
        "name": "r",
        "srcaddr": [],
        "dstaddr": [],
        "service": [],
        "srcaddr_negate": False,
        "dstaddr_negate": False,
    }
    base.update(kw)
    return base


def _ctx(addr=None, svc_objects=None):
    return Context(
        addr=addr or {},
        svc=ServiceCatalog(svc_objects or [], []),
    )


def test_match_rule_src_broader_and_names_detail():
    ctx = _ctx(
        addr={
            "corp": frozenset({N("10.1.0.0/16")}),
            "other": frozenset({N("9.9.9.0/24")}),
        }
    )
    q = Query(src=[N("10.1.1.5/32")], dst=None, port=None)
    m = match_rule(_rule(srcaddr=["corp", "other"]), q, ctx)
    assert m["src"]["label"] == "broader"
    assert m["src"]["names"] == {"corp": "broader"}
    assert m["skipped"] is False


def test_match_rule_all_is_skipped_not_matched():
    q = Query(src=[N("10.1.1.5/32")], dst=None, port=None)
    m = match_rule(_rule(srcaddr=["all"]), q, _ctx())
    assert m["src"]["label"] is None
    assert m["skipped"] is True


def test_match_rule_negated_is_skipped():
    ctx = _ctx(addr={"corp": frozenset({N("10.1.0.0/16")})})
    q = Query(src=[N("10.1.1.5/32")], dst=None, port=None)
    m = match_rule(_rule(srcaddr=["corp"], srcaddr_negate=True), q, ctx)
    assert m["src"]["label"] is None
    assert m["skipped"] is True


def test_match_rule_name_pattern_is_case_insensitive_fnmatch():
    q = Query(src="grp-App*", dst=None, port=None)
    ctx = _ctx()
    assert match_rule(_rule(srcaddr=["GRP-app-Web"]), q, ctx)["src"]["label"] == "name"
    assert match_rule(_rule(srcaddr=["other-grp"]), q, ctx)["src"]["label"] is None


def test_match_rule_unresolvable_and_unknown_names_do_not_raise():
    ctx = _ctx(addr={"fqdn-obj": None})
    q = Query(src=[N("10.1.1.5/32")], dst=None, port=None)
    m = match_rule(_rule(srcaddr=["fqdn-obj", "ghost"]), q, ctx)
    assert m["src"]["label"] is None


def test_match_rule_service_names_resolved_through_catalog():
    svc = [{"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}]
    q = Query(src=None, dst=None, port=[[PortRange("tcp", 443, 443)]])
    m = match_rule(_rule(service=["HTTPS"]), q, _ctx(svc_objects=svc))
    assert m["port"]["label"] == "exact"


def test_search_port_only_is_counted_not_listed():
    ctx = _ctx(
        addr={"corp": frozenset({N("10.1.0.0/16")}), "x": frozenset({N("9.9.0.0/16")})},
        svc_objects=[
            {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}
        ],
    )
    rules = [
        _rule(name="src-hit", srcaddr=["corp"], service=["HTTPS"]),
        _rule(name="port-only", srcaddr=["x"], service=["HTTPS"]),
    ]
    q = Query(src=[N("10.1.1.5/32")], dst=None, port=[[PortRange("tcp", 443, 443)]])
    res = search(rules, q, ctx, include_port_only=False)
    assert [r["name"] for r in res["rows"]] == ["src-hit"]
    assert res["port_only_count"] == 1
    res = search(rules, q, ctx, include_port_only=True)
    assert {r["name"] for r in res["rows"]} == {"src-hit", "port-only"}


def test_search_port_only_query_lists_port_matches_directly():
    ctx = _ctx(
        svc_objects=[
            {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}
        ]
    )
    q = Query(src=None, dst=None, port=[[PortRange("tcp", 443, 443)]])
    res = search(
        [_rule(name="a", service=["HTTPS"]), _rule(name="b", service=["SSH"])],
        q,
        ctx,
        False,
    )
    assert [r["name"] for r in res["rows"]] == ["a"]
    assert res["port_only_count"] == 0


def test_search_counts_skipped_and_sorts_full_matches_first():
    ctx = _ctx(
        addr={
            "corp": frozenset({N("10.1.0.0/16")}),
            "dstnet": frozenset({N("10.2.0.0/16")}),
        }
    )
    rules = [
        _rule(name="src-only", srcaddr=["corp"]),
        _rule(name="both", srcaddr=["corp"], dstaddr=["dstnet"]),
        _rule(name="any-src", srcaddr=["all"]),
    ]
    q = Query(src=[N("10.1.1.5/32")], dst=[N("10.2.0.5/32")], port=None)
    res = search(rules, q, ctx, False)
    assert [r["name"] for r in res["rows"]] == ["both", "src-only"]
    assert res["skipped_count"] == 1
    assert res["rows"][0]["match"]["dst"]["label"] == "broader"


# ── Review-pass fixes ─────────────────────────────────────────────────────────


def test_resolve_groups_keeps_resolvable_members_of_partly_unresolvable_group():
    leaves = {"n24": frozenset({N("10.1.1.0/24")}), "fq": None}
    groups = [
        {"name": "g", "member": [{"name": "n24"}, {"name": "fq"}, {"name": "gone"}]}
    ]
    out = resolve_groups(leaves, groups)
    assert out["g"] == frozenset({N("10.1.1.0/24")})
    assert out["n24"] == frozenset({N("10.1.1.0/24")})


def test_resolve_groups_handles_cycles_and_nested_groups():
    leaves = {"a": frozenset({N("10.0.0.0/24")})}
    groups = [
        {"name": "g1", "member": ["g2", "a"]},
        {"name": "g2", "member": ["g1"]},
    ]
    out = resolve_groups(leaves, groups)
    assert out["g1"] == frozenset({N("10.0.0.0/24")})
    assert out["g2"] == frozenset({N("10.0.0.0/24")})


def test_resolve_groups_drops_ipv6_networks():
    leaves = {
        "v6": frozenset({ipaddress.ip_network("2001:db8::/32")}),
        "v4": frozenset({N("10.0.0.0/8")}),
    }
    out = resolve_groups(leaves, [{"name": "g", "member": ["v6", "v4"]}])
    assert out["v6"] is None
    assert out["g"] == frozenset({N("10.0.0.0/8")})


@pytest.mark.parametrize(
    "text", ["all", "any", "ip/0", "icmp", "ping", "tcp/99999", "tcp/443-80"]
)
def test_parse_port_query_rejects_unsearchable_or_invalid(text):
    with pytest.raises(ValueError):
        parse_port_query(text, _resolve_none)


def test_parse_port_query_rejects_resolver_result_with_icmp_or_ip():
    with pytest.raises(ValueError):
        parse_port_query("PING", lambda n: [PortRange("icmp", 0, 65535)])


def test_icmp_and_ip_services_never_match_on_port_and_ip_wildcard_is_skipped():
    svc = [
        {"name": "PING", "protocol": "ICMP"},
        {"name": "ALLIP", "protocol": "IP"},
    ]
    q = Query(src=None, dst=None, port=[[PortRange("tcp", 443, 443)]])
    m = match_rule(_rule(service=["PING", "ALLIP"]), q, _ctx(svc_objects=svc))
    assert m["port"]["label"] is None
    assert m["skipped"] is True


def test_malformed_service_object_does_not_break_search():
    svc = [{"name": "BAD", "protocol": "IP", "protocol-number": ""}]
    q = Query(src=None, dst=None, port=[[PortRange("tcp", 443, 443)]])
    m = match_rule(_rule(service=["BAD"]), q, _ctx(svc_objects=svc))
    assert m["port"]["label"] is None


def test_group_match_reports_which_members_cover_the_port():
    from app.planner.matching import ServiceCatalog

    objs = [
        {"name": "SSH", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "22"},
        {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
        {"name": "span", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "20-30"},
    ]
    groups = [
        {"name": "inner", "member": ["SSH", "HTTPS"]},
        {"name": "outer", "member": ["inner", "span", "ghost"]},
        {"name": "nossh", "member": ["HTTPS"]},
    ]
    ctx = Context(addr={}, svc=ServiceCatalog(objs, groups))
    q = Query(port=parse_port_query("tcp/22", lambda n: None))
    rule = {"service": ["outer", "nossh", "SSH"]}
    port = match_rule(rule, q, ctx)["port"]
    assert set(port["names"]) == {"outer", "SSH"}  # nossh is not a hit
    assert port["via"] == {"outer": ["SSH", "span"]}  # plain objects need no via
