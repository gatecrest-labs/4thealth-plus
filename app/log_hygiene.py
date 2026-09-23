"""Log-Based Rule Review check engine -- purely local FMG-data logic plus
one call out to 4tlog's log-usage API. Never writes to FortiManager,
FortiGate, or 4tlog."""

from __future__ import annotations

import ipaddress

from app.fmg_helpers import make_client
from app.hygiene import _expand_group_members
from app.log_usage_client import LogUsageError, get_rule_log_usage


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
    by_name = {o.get("name"): o for o in objects if isinstance(o, dict) and o.get("name")}
    group_names = {g.get("name") for g in groups if isinstance(g, dict) and g.get("name")}
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
            not_evaluated.append({"name": name, "type": str(obj.get("type") or obj.get("protocol") or "ipmask")})
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
