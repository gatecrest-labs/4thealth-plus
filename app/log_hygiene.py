"""Log-Based Rule Review check engine -- purely local FMG-data logic plus
one call out to 4tlog's log-usage API. Never writes to FortiManager,
FortiGate, or 4tlog."""

from __future__ import annotations

import ipaddress

from app.fmg_helpers import make_client
from app.hygiene import _expand_group_members
from app.log_usage_client import (
    LogUsageError,  # noqa: F401 -- staged for Task 5 (route error handling)
    get_rule_log_usage,
)


class LogHygieneError(Exception):
    """Raised for FMG-side problems this check can't proceed past: the rule
    no longer exists in the package, or the package has no device scope."""


def _addr_object_host_ip(ao: dict) -> str | None:
    """Return the single host IP string if this address object resolves to
    exactly one /32, else None (subnet, range, FQDN, or unparseable)."""
    subnet = ao.get("subnet") or ao.get("ip-range") or ""
    if isinstance(subnet, list):
        subnet = " ".join(str(x) for x in subnet)
    subnet = str(subnet).strip()
    if not subnet:
        return None
    parts = subnet.split()
    try:
        if len(parts) == 2:
            net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
        elif "/" in subnet and len(parts) == 1:
            net = ipaddress.ip_network(subnet, strict=False)
        else:
            return None  # iprange ("start-end") or other unresolvable format
    except ValueError:
        return None
    if net.num_addresses == 1:
        return str(net.network_address)
    return None


def _service_single_port(so: dict) -> tuple[str, int] | None:
    """Return (proto, port) if this service object resolves to exactly one
    discrete TCP or UDP port, else None (range, multi-entry, or a protocol
    other than TCP/UDP)."""
    tcp_r = str(so.get("tcp-portrange") or "").strip()
    udp_r = str(so.get("udp-portrange") or "").strip()
    if tcp_r and udp_r:
        return None  # both set -- ambiguous which single port was meant
    raw, proto = (tcp_r, "tcp") if tcp_r else (udp_r, "udp")
    if not raw or " " in raw:
        return None  # empty, or multiple space-separated entries
    if ":" in raw:
        raw = raw.split(":", 1)[1]  # "src:dst" -- only dst matters
    if "-" in raw:
        return None  # port range
    try:
        return proto, int(raw)
    except ValueError:
        return None


def _expand_members(
    names: list[str],
    objects: list[dict],
    groups: list[dict],
    classify,
) -> tuple[list[dict], list[dict]]:
    """Shared BFS-expansion + classification for both address and service
    fields. `classify(obj)` returns the evaluated dict's extra fields (minus
    "name") on success, or None to route the object to not_evaluated."""
    by_name = {
        o.get("name"): o for o in objects if isinstance(o, dict) and o.get("name")
    }
    group_names = {
        g.get("name") for g in groups if isinstance(g, dict) and g.get("name")
    }
    direct = {n for n in names if n}
    reachable = _expand_group_members(groups, direct)
    leaf_names = (direct | reachable) - group_names

    evaluated: list[dict] = []
    not_evaluated: list[dict] = []
    for name in sorted(leaf_names):
        obj = by_name.get(name)
        if obj is None:
            not_evaluated.append({"name": name, "type": "unresolved"})
            continue
        extra = classify(obj)
        if extra is not None:
            evaluated.append({"name": name, **extra})
        else:
            not_evaluated.append(
                {
                    "name": name,
                    "type": str(obj.get("type") or obj.get("protocol") or "ipmask"),
                }
            )
    return evaluated, not_evaluated


def _expand_addr_members(
    names: list[str], addr_objects: list[dict], addr_groups: list[dict]
) -> tuple[list[dict], list[dict]]:
    def classify(ao: dict) -> dict | None:
        host_ip = _addr_object_host_ip(ao)
        return {"value": host_ip} if host_ip is not None else None

    return _expand_members(names, addr_objects, addr_groups, classify)


def _expand_service_members(
    names: list[str], svc_objects: list[dict], svc_groups: list[dict]
) -> tuple[list[dict], list[dict]]:
    def classify(so: dict) -> dict | None:
        single = _service_single_port(so)
        return {"proto": single[0], "port": single[1]} if single is not None else None

    return _expand_members(names, svc_objects, svc_groups, classify)


def _names(val) -> list[str]:
    if not val:
        return []
    if isinstance(val, str):
        return [val]
    return [(i.get("name", str(i)) if isinstance(i, dict) else str(i)) for i in val]


def check_rule_log_usage(adom: str, pkg: str, policy_id: int, days: int) -> dict:
    days = max(1, min(60, int(days)))

    with make_client() as client:
        policies = client.get_policies(adom, pkg)
        rule = next(
            (
                p
                for p in policies
                if isinstance(p, dict) and int(p.get("policyid", -1)) == policy_id
            ),
            None,
        )
        if rule is None:
            raise LogHygieneError(
                f"Rule {policy_id} not found in package '{pkg}' -- it may have "
                "been renamed or removed since the package was last loaded"
            )

        addr_objects = client.get_address_objects(adom)
        addr_groups = client.get_address_groups(adom)
        svc_objects = client.get_service_objects(adom)
        svc_groups = client.get_service_groups(adom)
        scope = client.get_pkg_scope_members(adom, pkg)

    devices = sorted(
        {m.get("name") for m in scope if isinstance(m, dict) and m.get("name")}
    )
    if not devices:
        raise LogHygieneError(
            "Policy package is not installed on any device -- no logs to check"
        )

    src_eval, src_not_eval = _expand_addr_members(
        _names(rule.get("srcaddr") or rule.get("src_addr")), addr_objects, addr_groups
    )
    dst_eval, dst_not_eval = _expand_addr_members(
        _names(rule.get("dstaddr") or rule.get("dst_addr")), addr_objects, addr_groups
    )
    svc_eval, svc_not_eval = _expand_service_members(
        _names(rule.get("service") or rule.get("services")), svc_objects, svc_groups
    )

    usage = get_rule_log_usage(adom, devices, policy_id, days)

    observed_srcips = set(usage.get("srcips") or [])
    observed_dstips = set(usage.get("dstips") or [])
    observed_ports = set(usage.get("dstports") or [])

    def _mark(evaluated: list[dict], key: str, observed: set) -> list[dict]:
        return [
            {**m, "status": "used" if m[key] in observed else "unused"}
            for m in evaluated
        ]

    return {
        "rule": {"policy_id": policy_id, "name": rule.get("name") or ""},
        "days": days,
        "time_range": usage.get("time_range") or {},
        "log_count": usage.get("log_count", 0),
        "truncated": bool(usage.get("truncated")),
        "devices_queried": usage.get("devices_queried") or [],
        "devices_not_found": usage.get("devices_not_found") or [],
        "source": {
            "evaluated": _mark(src_eval, "value", observed_srcips),
            "not_evaluated": src_not_eval,
        },
        "destination": {
            "evaluated": _mark(dst_eval, "value", observed_dstips),
            "not_evaluated": dst_not_eval,
        },
        "service": {
            "evaluated": _mark(svc_eval, "port", observed_ports),
            "not_evaluated": svc_not_eval,
        },
    }
