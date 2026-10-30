"""Rule Lookup matching engine.

Pure functions (no Flask, no FMG): compare a searched source / destination /
port against cached policy rules and label each field as

  exact    rule value equals the search
  broader  rule value contains the search
  narrower rule value lies inside the search
  overlap  ranges intersect, neither contains the other
  name     name-pattern search hit (name searches never compare IPs)

Rules whose searched field is all/any, or negated, never match that field and
are reported through ``skipped`` instead.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from app.planner.matching import PortRange, ServiceCatalog, parse_service_request

_BARE_PORT_RE = re.compile(r"^\d+(-\d+)?$")
_ALL_NAMES = ("all", "any")
_NON_PORT_PROTOCOLS = ("ip", "icmp")

# Lower is better when a field has several matching names.
_RANK = {"exact": 0, "name": 0, "broader": 1, "narrower": 2, "overlap": 3}


@dataclass
class Query:
    """Searched values. A list is a parsed IP/port search, a str a name pattern."""

    src: list | str | None = None
    dst: list | str | None = None
    port: list[list[PortRange]] | None = None  # alternatives; best label wins


@dataclass
class Context:
    addr: dict  # name -> frozenset[IPv4Network] | None (from build_addr_resolver)
    svc: ServiceCatalog
    svc_names: dict = field(default_factory=dict)  # lower-case name -> real name


def resolve_service_name(ctx: Context, text: str) -> list[PortRange] | None:
    """Resolve a service object/group name (case-insensitive) to port ranges."""
    real = ctx.svc_names.get(text.strip().lower())
    return ctx.svc.ranges_for_ref(real) if real else None


# ── Group resolution ──────────────────────────────────────────────────────────


def _v4_only(nets) -> frozenset | None:
    v4 = frozenset(n for n in (nets or ()) if n.version == 4)
    return v4 or None


def resolve_groups(leaves: dict, groups: list) -> dict:
    """Resolve address groups to the union of their resolvable member networks.

    Unlike the hygiene resolver, a member that cannot be resolved (FQDN,
    geography, deleted object) is skipped rather than poisoning the whole group,
    and cycles are tolerated. IPv6 networks are dropped (the lookup is IPv4).
    """
    out = {name: _v4_only(nets) for name, nets in leaves.items()}
    members: dict[str, list[str]] = {}
    for g in groups:
        if isinstance(g, dict) and g.get("name"):
            members[g["name"]] = [
                (m if isinstance(m, str) else m.get("name", ""))
                for m in (g.get("member") or [])
            ]
    for gname in members:
        seen: set = set()
        stack = [gname]
        nets: set = set()
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            if n in members:
                stack.extend(members[n])
            elif out.get(n):
                nets |= out[n]
        out[gname] = frozenset(nets) or None
    return out


# ── Parsing ───────────────────────────────────────────────────────────────────


def parse_ip_query(text: str) -> list[ipaddress.IPv4Network]:
    """Parse host, CIDR, dotted netmask or trailing-octet wildcard to networks."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("Empty IP query")
    try:
        if "*" in raw:
            parts = raw.split(".")
            if len(parts) != 4:
                raise ValueError(f"Invalid query {raw!r}: expected 4 octets")
            first_wild = None
            for i, p in enumerate(parts):
                if p == "*":
                    if first_wild is None:
                        first_wild = i
                elif first_wild is not None:
                    raise ValueError(
                        f"Invalid query {raw!r}: wildcards must be trailing"
                    )
                elif not p.isdigit():
                    raise ValueError(f"Invalid query {raw!r}: non-numeric octet {p!r}")
            base = ".".join(p if p != "*" else "0" for p in parts)
            return [ipaddress.IPv4Network(f"{base}/{first_wild * 8}", strict=False)]
        if "/" in raw:
            return [ipaddress.IPv4Network(raw, strict=False)]
        return [ipaddress.IPv4Network(f"{ipaddress.IPv4Address(raw)}/32")]
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid IP query {raw!r}: {exc}") from None
    except ipaddress.NetmaskValueError as exc:
        raise ValueError(f"Invalid IP query {raw!r}: {exc}") from None


def _validated(alts: list[list[PortRange]]) -> list[list[PortRange]]:
    for alt in alts:
        for r in alt:
            if r.protocol in _NON_PORT_PROTOCOLS:
                raise ValueError(
                    "Port search must be a TCP/UDP port or service "
                    "(ICMP, IP-protocol and all/any cannot be searched by port)"
                )
            if not (0 <= r.start <= r.end <= 65535):
                raise ValueError(f"Invalid port range {r.start}-{r.end}")
    return alts


def parse_port_query(
    text: str, resolve_name: Callable[[str], list[PortRange] | None]
) -> list[list[PortRange]]:
    """Parse a port search into alternatives (best label across them wins).

    A bare port / range means tcp OR udp. ``proto/port`` is one alternative.
    A name is resolved through ``resolve_name`` (ADOM service objects), then the
    well-known table. Raises ValueError when nothing recognises it.
    """
    raw = (text or "").strip()
    if not raw:
        raise ValueError("Empty port query")
    if _BARE_PORT_RE.match(raw):
        lo, _, hi = raw.partition("-")
        low, high = int(lo), int(hi or lo)
        if not (0 <= low <= high <= 65535):
            raise ValueError(f"Invalid port {raw!r}")
        return _validated(
            [[PortRange("tcp", low, high)], [PortRange("udp", low, high)]]
        )
    if "/" not in raw:
        resolved = resolve_name(raw)
        if resolved:
            return _validated([list(resolved)])
    return _validated([parse_service_request(raw)])


# ── Comparison ────────────────────────────────────────────────────────────────


def _best(labels) -> str | None:
    labels = [lb for lb in labels if lb]
    return min(labels, key=_RANK.__getitem__) if labels else None


def compare_networks(search: list, rule: frozenset | None) -> str | None:
    """Label how a rule's resolved networks relate to the searched networks."""
    if not rule:
        return None
    s_nets = list(ipaddress.collapse_addresses(search))
    r_nets = list(ipaddress.collapse_addresses(rule))
    if set(s_nets) == set(r_nets):
        return "exact"
    if all(any(s.subnet_of(r) for r in r_nets) for s in s_nets):
        return "broader"
    if all(any(r.subnet_of(s) for s in s_nets) for r in r_nets):
        return "narrower"
    if any(s.overlaps(r) for s in s_nets for r in r_nets):
        return "overlap"
    return None


def compare_ranges(search: list[PortRange], rule: list[PortRange] | None) -> str | None:
    """Label how a rule's service ranges relate to the searched ranges."""
    if not rule:
        return None
    if set(search) == set(rule):
        return "exact"
    if all(any(r.contains(s) for r in rule) for s in search):
        return "broader"
    if all(any(s.contains(r) for s in search) for r in rule):
        return "narrower"
    if any(s.overlaps(r) for s in search for r in rule):
        return "overlap"
    return None


# ── Rule matching ─────────────────────────────────────────────────────────────


def _is_all(name: str) -> bool:
    return str(name).strip().lower() in _ALL_NAMES


def _match_addr_field(
    names: list[str], negate: bool, wanted: list | str | None, ctx: Context
) -> tuple[dict, bool]:
    """Return (FieldMatch, skipped) for a source or destination field."""
    empty = {"label": None, "names": {}}
    if wanted is None:
        return empty, False
    skipped = bool(negate) or any(_is_all(n) for n in names)
    if negate:
        return empty, skipped
    hits: dict[str, str] = {}
    for name in names:
        if _is_all(name):
            continue
        if isinstance(wanted, str):
            if fnmatch.fnmatchcase(name.lower(), wanted.lower()):
                hits[name] = "name"
        else:
            label = compare_networks(wanted, ctx.addr.get(name))
            if label:
                hits[name] = label
    return {"label": _best(hits.values()), "names": hits}, skipped


def _match_port_field(
    names: list[str], wanted: list[list[PortRange]] | None, ctx: Context
) -> tuple[dict, bool]:
    empty = {"label": None, "names": {}}
    if wanted is None:
        return empty, False
    skipped = any(_is_all(n) for n in names)
    hits: dict[str, str] = {}
    via: dict[str, list[str]] = {}
    for name in names:
        if _is_all(name):
            continue
        label, ip_wild = _label_service(ctx, name, wanted)
        skipped = skipped or ip_wild
        if label:
            hits[name] = label
            leaves = [
                leaf
                for leaf in ctx.svc.leaf_names(name)
                if _label_service(ctx, leaf, wanted)[0]
            ]
            if leaves:
                via[name] = leaves
    return {"label": _best(hits.values()), "names": hits, "via": via}, skipped


def _label_service(
    ctx: Context, name: str, wanted: list[list[PortRange]]
) -> tuple[str | None, bool]:
    """Return (label, is_ip_wildcard) for one service object or group name."""
    try:
        ranges = ctx.svc.ranges_for_ref(name)
    except (ValueError, TypeError, KeyError):
        return None, False  # malformed service object: cannot be compared
    if not ranges:
        return None, False
    ip_wild = any(r.protocol == "ip" for r in ranges)  # behaves like ALL
    usable = [r for r in ranges if r.protocol not in _NON_PORT_PROTOCOLS]
    return _best(compare_ranges(alt, usable) for alt in wanted), ip_wild


def match_rule(rule: dict, q: Query, ctx: Context) -> dict:
    src, s_skip = _match_addr_field(
        rule.get("srcaddr") or [], rule.get("srcaddr_negate"), q.src, ctx
    )
    dst, d_skip = _match_addr_field(
        rule.get("dstaddr") or [], rule.get("dstaddr_negate"), q.dst, ctx
    )
    port, p_skip = _match_port_field(rule.get("service") or [], q.port, ctx)
    return {"src": src, "dst": dst, "port": port, "skipped": s_skip or d_skip or p_skip}


def search(rules: list[dict], q: Query, ctx: Context, include_port_only: bool) -> dict:
    """Run a query over cached rules.

    Rows: rules matching on source/destination (or on port when neither was
    searched), full matches first. Rules matching only on port while
    source/destination were searched are counted, and returned only when
    ``include_port_only`` (after the main rows).
    """
    searched_sd = q.src is not None or q.dst is not None
    main: list[tuple[int, dict]] = []
    port_only: list[dict] = []
    skipped = 0
    for rule in rules:
        m = match_rule(rule, q, ctx)
        if m["skipped"]:
            skipped += 1
        row = {**rule, "match": m}
        sd_hit = bool(m["src"]["label"] or m["dst"]["label"])
        if searched_sd:
            if sd_hit:
                main.append((_score(m), row))
            elif m["port"]["label"]:
                port_only.append(row)
        elif m["port"]["label"]:
            main.append((_score(m), row))
    main.sort(key=lambda t: -t[0])  # stable: cache order kept within a score
    rows = [r for _, r in main]
    if include_port_only:
        rows += port_only
    return {
        "rows": rows,
        "port_only_count": len(port_only),
        "skipped_count": skipped,
    }


def _score(m: dict) -> int:
    return sum(1 for f in ("src", "dst", "port") if m[f]["label"])
