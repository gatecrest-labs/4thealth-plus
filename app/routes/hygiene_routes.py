"""Rule Review tab — read-only policy analysis routes.

Page:
  GET  /hygiene

API (JSON, all read-only):
  GET  /api/hygiene/adoms/<adom>/packages        list policy packages
  POST /api/hygiene/run
       body: { adom, package, checks: [str, ...] }
       returns: { findings: [...], total: int, policy_count: int }
"""

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from flask import Blueprint, jsonify, render_template, request, session

from app import registry
from app.decorators import check_adom_access, tab_required
from app.fmg_client import FMGError
from app.fmg_helpers import make_client
from app.hygiene import CHECKS, _action, _status, find_unused_objects, run_checks
from app.security import internal_api_error, upstream_api_error

bp = Blueprint("hygiene", __name__)

registry.register("rule_hygiene", "Rule Review", "hygiene.hygiene_page")


# ── Page ──────────────────────────────────────────────────────────────────────


@bp.route("/hygiene")
@tab_required("rule_hygiene")
def hygiene_page():
    return render_template("hygiene.html", user=session["user"], checks=CHECKS)


# ── API: list packages ────────────────────────────────────────────────────────


@bp.route("/api/hygiene/adoms/<adom>/packages")
@tab_required("rule_hygiene")
def hygiene_packages(adom: str):
    if err := check_adom_access(adom):
        return err
    try:
        with make_client() as client:
            raw = client.get_policy_packages(adom)
        packages = []
        for pkg in raw:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            path = pkg.get("path", name)
            pkg_type = (pkg.get("type") or "").lower()
            if pkg_type != "folder" and name:
                packages.append({"name": name, "path": path})
        return jsonify(packages)
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)


# ── API: raw package list (debug) ────────────────────────────────────────────


@bp.route("/api/hygiene/adoms/<adom>/packages/raw")
@tab_required("rule_hygiene")
def hygiene_packages_raw(adom: str):
    """Return the unfiltered FMG response — useful for diagnosing missing packages."""
    if err := check_adom_access(adom):
        return err
    try:
        with make_client() as client:
            raw = client._get(f"/pm/pkg/adom/{adom}")
        return jsonify(raw)
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)


def _pkg_path(data: dict) -> str:
    """Extract the folder-qualified package path from a request body."""
    return (data.get("path") or data.get("package") or "").strip()


def _addr_subnet(ao: dict) -> str:
    """Return the best subnet string for an address object.

    Regular objects carry 'subnet' or 'ip-range' at the top level.
    FortiGate device-type objects (managed devices) store their management IP
    in dynamic_mapping[0]['subnet'] — fall back to that when the top-level
    field is absent or empty.
    """
    subnet = ao.get("subnet") or ao.get("ip-range") or ""
    if isinstance(subnet, list):
        subnet = " ".join(str(x) for x in subnet)
    subnet = str(subnet).strip()
    if subnet:
        return subnet
    # FortiGate / dynamic objects — first mapping holds the mgmt IP
    mappings = ao.get("dynamic_mapping") or []
    if isinstance(mappings, list) and mappings:
        first = mappings[0] if isinstance(mappings[0], dict) else {}
        fallback = first.get("subnet") or first.get("ip-range") or ""
        if isinstance(fallback, list):
            fallback = " ".join(str(x) for x in fallback)
        fallback = str(fallback).strip()
        if fallback:
            return fallback
    return ""


def _ip_in_range(ip_str: str, start_str: str, end_str: str) -> bool:
    """Return True if ip_str falls between start_str and end_str (inclusive)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        start = ipaddress.ip_address(start_str)
        end = ipaddress.ip_address(end_str)
        return start <= ip <= end
    except ValueError:
        return False


def _cidr_from_mask(ip_mask: str) -> str:
    """Convert 'x.x.x.x y.y.y.y' to 'x.x.x.x/prefix' for display. Returns original on failure."""
    parts = ip_mask.strip().split()
    if len(parts) == 2:
        try:
            iface = ipaddress.IPv4Interface(f"{parts[0]}/{parts[1]}")
            return str(iface)
        except ValueError:
            pass
    return ip_mask


def _parse_subnet_to_networks(subnet_str: str) -> frozenset | None:
    """Parse a FortiManager subnet/range string to a frozenset of ip_network objects.

    Handles:
      "10.1.0.0 255.255.0.0"  → ipmask
      "10.1.0.0/16"           → CIDR
      "10.1.0.1-10.1.0.254"   → iprange (expanded into /32s via summarize_address_range)
    Returns None for FQDN, geography, or any unresolvable value.
    """
    s = subnet_str.strip()
    if not s:
        return None
    # ipmask: "A.B.C.D M.M.M.M"
    parts = s.split()
    if len(parts) == 2:
        try:
            net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
            return frozenset([net])
        except ValueError:
            pass
    # CIDR or single IP
    if "/" in s or (len(parts) == 1 and s.replace(".", "").isdigit()):
        try:
            net = ipaddress.ip_network(s, strict=False)
            return frozenset([net])
        except ValueError:
            pass
    # iprange: "start-end"
    if "-" in s and len(parts) == 1:
        try:
            start_s, _, end_s = s.partition("-")
            start = ipaddress.ip_address(start_s.strip())
            end = ipaddress.ip_address(end_s.strip())
            nets = list(ipaddress.summarize_address_range(start, end))
            return frozenset(nets)
        except ValueError:
            pass
    return None


def _vip_addr_and_detail(vip: dict) -> tuple[str, str]:
    """Return (extip_str, 'extip -> mappedip' detail) for a VIP object.

    VIPs are a distinct FMG object class from firewall/address (see
    FMGClient.get_vip_objects) but FortiGate allows them to be selected as a
    policy dstaddr exactly like a normal address object, so callers that
    resolve address names need to fold VIPs in alongside addr_objects.
    """
    ext_ip_raw = vip.get("extip", "")
    if isinstance(ext_ip_raw, list):
        ext_ip_raw = ext_ip_raw[0] if ext_ip_raw else ""
    ext_ip = str(ext_ip_raw).strip()

    mapped_raw = vip.get("mappedip") or vip.get("mapped-ip") or []
    if isinstance(mapped_raw, str):
        mapped_ranges = [mapped_raw] if mapped_raw else []
    elif isinstance(mapped_raw, list):
        mapped_ranges = []
        for entry in mapped_raw:
            if isinstance(entry, dict):
                r = entry.get("range", "")
                if r:
                    mapped_ranges.append(r)
            elif isinstance(entry, str) and entry:
                mapped_ranges.append(entry)
    else:
        mapped_ranges = []
    mapped = "; ".join(mapped_ranges)

    if ext_ip and mapped:
        return ext_ip, f"{ext_ip} → {mapped}"
    return ext_ip, ext_ip or mapped or ""


def build_addr_resolver(
    addr_objects: list, addr_groups: list, vip_objects: list | None = None
) -> dict:
    """Build a name→frozenset[ip_network] resolver for address objects and groups.

    Values are frozenset of ip_network objects, or None for FQDN/geography/
    unresolvable objects (which should block the IP containment pass).
    """
    raw: dict[str, frozenset | None] = {}

    for ao in addr_objects:
        if not isinstance(ao, dict):
            continue
        name = ao.get("name", "")
        if not name:
            continue
        subnet_str = _addr_subnet(ao)
        if not subnet_str:
            raw[name] = None  # FQDN, geography, or unresolvable
            continue
        nets = _parse_subnet_to_networks(subnet_str)
        raw[name] = nets  # may be None if parse failed

    for vip in vip_objects or []:
        if not isinstance(vip, dict):
            continue
        name = vip.get("name", "")
        if not name:
            continue
        ext_ip, _detail = _vip_addr_and_detail(vip)
        raw[name] = _parse_subnet_to_networks(ext_ip) if ext_ip else None

    # Build a flat membership map first: group_name → [member_names]
    grp_members: dict[str, list[str]] = {}
    for ag in addr_groups:
        if not isinstance(ag, dict):
            continue
        name = ag.get("name", "")
        members = ag.get("member", []) or []
        if name:
            grp_members[name] = [
                (m.get("name") if isinstance(m, dict) else str(m)) for m in members
            ]

    # Recursively resolve groups; guard against cycles.
    resolved: dict[str, frozenset | None] = {}

    def _resolve_group(name: str, seen: set) -> frozenset | None:
        if name in resolved:
            return resolved[name]
        if name in seen:
            return None  # cycle
        seen = seen | {name}
        if name in raw:
            return raw[name]
        if name not in grp_members:
            return None
        union: set = set()
        for member in grp_members[name]:
            nets = _resolve_group(member, seen)
            if nets is None:
                resolved[name] = None
                return None
            union.update(nets)
        result = frozenset(union) if union else None
        resolved[name] = result
        return result

    # Resolve all group names
    for gname in grp_members:
        _resolve_group(gname, set())

    # Merge raw + resolved groups into one dict
    combined: dict[str, frozenset | None] = {}
    combined.update(raw)
    combined.update(resolved)
    return combined


def _parse_portrange(portrange_str: str, proto: str) -> frozenset | None:
    """Parse a FortiManager portrange string into frozenset of (proto, low, high) tuples.

    FortiManager portrange format: "80", "1024-65535", "80:8080" (src:dst).
    We only care about the destination port range for containment purposes.
    Returns None if the service cannot be represented as simple port ranges.
    """
    s = str(portrange_str or "").strip()
    if not s:
        return None
    p = proto.lower() if proto else "tcp"
    ranges: set = set()
    for part in s.split():
        # "src:dst" — take dst portion only
        if ":" in part:
            part = part.split(":", 1)[1]
        # "low-high" or single port
        if "-" in part:
            try:
                low, high = part.split("-", 1)
                ranges.add((p, int(low), int(high)))
            except ValueError:
                return None
        else:
            try:
                port = int(part)
                ranges.add((p, port, port))
            except ValueError:
                return None
    return frozenset(ranges) if ranges else None


def build_svc_resolver(svc_objects: list, svc_groups: list) -> dict:
    """Build a name→frozenset[(proto, low, high)] resolver for service objects/groups.

    Values are frozenset of (proto_str, low_port, high_port) tuples, or None
    for ICMP/non-TCP-UDP services that cannot be represented as port ranges.
    """
    raw: dict[str, frozenset | None] = {}

    for so in svc_objects:
        if not isinstance(so, dict):
            continue
        name = so.get("name", "")
        if not name:
            continue
        proto = str(so.get("protocol", "") or "").lower()
        # Only handle TCP and UDP for containment; ICMP/IP/etc → opaque
        if proto and proto not in ("tcp", "udp", "tcp/udp", ""):
            raw[name] = None
            continue
        tcp_r = so.get("tcp-portrange", "") or ""
        udp_r = so.get("udp-portrange", "") or ""
        all_ranges: set = set()
        if tcp_r:
            nets = _parse_portrange(tcp_r, "tcp")
            if nets is None:
                raw[name] = None
                continue
            all_ranges.update(nets)
        if udp_r:
            nets = _parse_portrange(udp_r, "udp")
            if nets is None:
                raw[name] = None
                continue
            all_ranges.update(nets)
        raw[name] = frozenset(all_ranges) if all_ranges else None

    grp_members: dict[str, list[str]] = {}
    for sg in svc_groups:
        if not isinstance(sg, dict):
            continue
        name = sg.get("name", "")
        members = sg.get("member", []) or []
        if name:
            grp_members[name] = [
                (m.get("name") if isinstance(m, dict) else str(m)) for m in members
            ]

    resolved: dict[str, frozenset | None] = {}

    def _resolve_svc_group(name: str, seen: set) -> frozenset | None:
        if name in resolved:
            return resolved[name]
        if name in seen:
            return None
        seen = seen | {name}
        if name in raw:
            return raw[name]
        if name not in grp_members:
            return None
        union: set = set()
        for member in grp_members[name]:
            nets = _resolve_svc_group(member, seen)
            if nets is None:
                resolved[name] = None
                return None
            union.update(nets)
        result = frozenset(union) if union else None
        resolved[name] = result
        return result

    for gname in grp_members:
        _resolve_svc_group(gname, set())

    combined: dict[str, frozenset | None] = {}
    combined.update(raw)
    combined.update(resolved)
    return combined


# ── API: raw policy list (debug) ─────────────────────────────────────────────


@bp.route("/api/hygiene/policies/raw", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_policies_raw():
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    path = _pkg_path(data)
    if not adom or not path:
        return jsonify({"error": "adom and package/path are required"}), 400
    if err := check_adom_access(adom):
        return err
    try:
        with make_client() as client:
            raw = client._get(f"/pm/config/adom/{adom}/pkg/{path}/firewall/policy")
        return jsonify({"adom": adom, "path": path, "data": raw})
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)


# ── API: policy list ─────────────────────────────────────────────────────────


@bp.route("/api/hygiene/policies", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_policies():
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    path = _pkg_path(data)
    if not adom or not path:
        return jsonify({"error": "adom and package/path are required"}), 400
    if err := check_adom_access(adom):
        return err
    # Phase 1: fetch ONLY the flat policy list — no pblock rules, no objects.
    # Both are deferred to separate requests so this call stays fast even for
    # large ADOMs like OT-SERVICES with many/large policy blocks.
    try:
        with make_client() as client:
            raw = client.get_policies(adom, path)
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    def _names(val):
        if not val:
            return []
        if isinstance(val, str):
            return [val]
        return [(i.get("name", str(i)) if isinstance(i, dict) else str(i)) for i in val]

    def _build_rule(p, idx):
        srcaddr = _names(p.get("srcaddr") or p.get("src_addr"))
        dstaddr = _names(p.get("dstaddr") or p.get("dst_addr"))
        service = _names(p.get("service") or p.get("services"))
        return {
            "seq": p.get("policyid", idx + 1),
            "id": str(p.get("policyid", idx + 1)),
            "name": p.get("name") or "",
            "status": _status(p),
            "action": _action(p),
            "srcaddr": srcaddr,
            "dstaddr": dstaddr,
            "service": service,
            "fsso_groups": _names(p.get("fsso-groups")),
            "comment": p.get("comments") or p.get("comment") or "",
            "srcintf": _names(p.get("srcintf")),
            "dstintf": _names(p.get("dstintf")),
        }

    try:
        policies = []
        pblock_names = []
        for idx, p in enumerate(raw):
            if not isinstance(p, dict):
                continue

            block_name = p.get("_policy_block")
            if block_name and str(block_name).strip():
                block_name = str(block_name).strip()
                # Emit a placeholder — rules are populated by the /pblocks request
                if block_name not in pblock_names:
                    pblock_names.append(block_name)
                policies.append(
                    {
                        "policy_block": block_name,
                        "assigned": None,  # unknown until pblocks load
                        "rules": [],  # populated by deferred /pblocks fetch
                    }
                )
                continue

            policies.append(_build_rule(p, idx))

        # FortiGate always has an implicit deny-all at the bottom of every policy package.
        # It is not returned by the FMG API, so we append it synthetically.
        policies.append(
            {
                "seq": "implicit",
                "id": "implicit",
                "name": "Implicit Deny",
                "status": "enable",
                "action": "deny",
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["ALL"],
                "fsso_groups": [],
                "comment": "Default implicit deny — all unmatched traffic is dropped",
                "srcintf": ["any"],
                "dstintf": ["any"],
                "implicit": True,
            }
        )

        return jsonify(
            {"policies": policies, "total": len(policies), "pblock_names": pblock_names}
        )
    except Exception as exc:
        return internal_api_error("hygiene", exc)


# ── API: pblock rules (deferred, called after policy table renders) ───────────


@bp.route("/api/hygiene/policies/pblocks", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_policy_pblocks():
    """Return rules for a list of pblock names in a given ADOM.

    Called after the policy table is already visible so large pblock sets
    don't block the initial load.  Returns:
      pblocks – {block_name: [{rule}, ...]}
    """
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    names = data.get("names") or []
    if not adom:
        return jsonify({"error": "adom is required"}), 400
    if not isinstance(names, list):
        return jsonify({"error": "names must be a list"}), 400
    if err := check_adom_access(adom):
        return err

    def _names(val):
        if not val:
            return []
        if isinstance(val, str):
            return [val]
        return [(i.get("name", str(i)) if isinstance(i, dict) else str(i)) for i in val]

    def _build_rule(p, idx):
        srcaddr = _names(p.get("srcaddr") or p.get("src_addr"))
        dstaddr = _names(p.get("dstaddr") or p.get("dst_addr"))
        service = _names(p.get("service") or p.get("services"))
        return {
            "seq": p.get("policyid", idx + 1),
            "id": str(p.get("policyid", idx + 1)),
            "name": p.get("name") or "",
            "status": _status(p),
            "action": _action(p),
            "srcaddr": srcaddr,
            "dstaddr": dstaddr,
            "service": service,
            "fsso_groups": _names(p.get("fsso-groups")),
            "comment": p.get("comments") or p.get("comment") or "",
            "srcintf": _names(p.get("srcintf")),
            "dstintf": _names(p.get("dstintf")),
        }

    try:
        pblocks: dict[str, list] = {}
        with make_client() as client:
            for block_name in names:
                block_name = str(block_name).strip()
                if not block_name:
                    continue
                try:
                    raw = client.get_pblock_policies(adom, block_name)
                    pblocks[block_name] = [
                        _build_rule(r, i)
                        for i, r in enumerate(raw)
                        if isinstance(r, dict)
                    ]
                except Exception:
                    pblocks[block_name] = []
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    return jsonify({"pblocks": pblocks})


# ── API: object expansion maps (deferred, called after policy table renders) ──


@bp.route("/api/hygiene/policies/objects", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_policy_objects():
    """Return addr/svc group and subnet maps for a given ADOM.

    Called after the policy table is already visible so large ADOMs don't
    block the initial load.  Returns:
      addr_grp_map   – {name: [member, ...]}
      svc_grp_map    – {name: [member, ...]}
      addr_detail_map – {name: "subnet/range"}
    """
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    if not adom:
        return jsonify({"error": "adom is required"}), 400
    if err := check_adom_access(adom):
        return err
    try:
        with make_client() as client:
            addr_objects = client.get_address_objects(adom)
            addr_groups = client.get_address_groups(adom)
            vip_objects = client.get_vip_objects(adom)
            svc_groups = client.get_service_groups(adom)
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    addr_grp_map: dict[str, list[str]] = {}
    for ag in addr_groups:
        if not isinstance(ag, dict):
            continue
        gname = ag.get("name", "")
        members = ag.get("member", []) or []
        if isinstance(members, list):
            addr_grp_map[gname] = [
                (m.get("name") if isinstance(m, dict) else str(m)) for m in members
            ]

    svc_grp_map: dict[str, list[str]] = {}
    for sg in svc_groups:
        if not isinstance(sg, dict):
            continue
        gname = sg.get("name", "")
        members = sg.get("member", []) or []
        if isinstance(members, list):
            svc_grp_map[gname] = [
                (m.get("name") if isinstance(m, dict) else str(m)) for m in members
            ]

    addr_detail_map: dict[str, str] = {}
    for ao in addr_objects:
        if not isinstance(ao, dict):
            continue
        n = ao.get("name", "")
        subnet = _addr_subnet(ao)
        if n and subnet:
            addr_detail_map[n] = subnet
    # VIPs are a distinct FMG object class from firewall/address but can be
    # selected as a policy dstaddr exactly like a normal address object.
    for vip in vip_objects:
        if not isinstance(vip, dict):
            continue
        n = vip.get("name", "")
        _ext_ip, detail = _vip_addr_and_detail(vip)
        if n and detail:
            addr_detail_map[n] = detail

    return jsonify(
        {
            "addr_grp_map": addr_grp_map,
            "svc_grp_map": svc_grp_map,
            "addr_detail_map": addr_detail_map,
        }
    )


# ── API: object lookup ───────────────────────────────────────────────────────


@bp.route("/api/hygiene/adoms/<adom>/objects/lookup", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_object_lookup(adom: str):
    """Search address objects, address groups, VIPs, service objects, and service groups.

    Body: { "query": "search string" }
    Returns: { "objects": [ { name, type, category, detail, members } ] }
    """
    if err := check_adom_access(adom):
        return err

    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "").strip().lower()
    if not query:
        return jsonify({"error": "query is required"}), 400

    try:
        with make_client() as client:
            addr_objects = client.get_address_objects(adom)
            addr_groups = client.get_address_groups(adom)
            vip_objects = client.get_vip_objects(adom)
            svc_objects = client.get_service_objects(adom)
            svc_groups = client.get_service_groups(adom)
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    # Build address detail map so group members can show their IPs
    addr_detail_map: dict[str, str] = {}
    for ao in addr_objects:
        if not isinstance(ao, dict):
            continue
        n = ao.get("name", "")
        subnet = _addr_subnet(ao)
        if n and subnet:
            addr_detail_map[n] = subnet
    # VIPs are a distinct FMG object class from firewall/address (see
    # FMGClient.get_vip_objects) but FortiGate allows them to be selected as
    # a policy dstaddr exactly like a normal address object, so group members
    # that are actually VIPs still need a detail string.
    for vip in vip_objects:
        if not isinstance(vip, dict):
            continue
        n = vip.get("name", "")
        _ext_ip, detail = _vip_addr_and_detail(vip)
        if n and detail:
            addr_detail_map[n] = detail

    # Build service detail map so service-group members can show port info
    svc_detail_map: dict[str, str] = {}
    for so in svc_objects:
        if not isinstance(so, dict):
            continue
        n = so.get("name", "")
        proto = so.get("protocol", "")
        tcp_port = so.get("tcp-portrange", "")
        udp_port = so.get("udp-portrange", "")
        parts = []
        if proto:
            parts.append(str(proto))
        if tcp_port:
            parts.append(f"TCP {tcp_port}")
        if udp_port:
            parts.append(f"UDP {udp_port}")
        if n and parts:
            svc_detail_map[n] = ", ".join(parts)

    results = []

    for ao in addr_objects:
        if not isinstance(ao, dict):
            continue
        name = ao.get("name", "")
        if not name or query not in name.lower():
            continue
        subnet = _addr_subnet(ao)
        obj_type = ao.get("type", "ipmask")
        results.append(
            {
                "name": name,
                "type": "object",
                "category": "address",
                "detail": subnet,
                "subtype": str(obj_type),
                "members": [],
            }
        )

    for vip in vip_objects:
        if not isinstance(vip, dict):
            continue
        name = vip.get("name", "")
        if not name or query not in name.lower():
            continue
        _ext_ip, detail = _vip_addr_and_detail(vip)
        results.append(
            {
                "name": name,
                "type": "object",
                "category": "address",
                "detail": detail,
                "subtype": "vip",
                "members": [],
            }
        )

    for ag in addr_groups:
        if not isinstance(ag, dict):
            continue
        name = ag.get("name", "")
        if not name or query not in name.lower():
            continue
        raw_members = ag.get("member", []) or []
        members = [
            {
                "name": (m.get("name") if isinstance(m, dict) else str(m)),
                "detail": addr_detail_map.get(
                    m.get("name") if isinstance(m, dict) else str(m), ""
                ),
            }
            for m in raw_members
        ]
        results.append(
            {
                "name": name,
                "type": "group",
                "category": "address",
                "detail": f"{len(members)} member{'s' if len(members) != 1 else ''}",
                "subtype": "addrgrp",
                "members": members,
            }
        )

    for so in svc_objects:
        if not isinstance(so, dict):
            continue
        name = so.get("name", "")
        if not name or query not in name.lower():
            continue
        proto = so.get("protocol", "")
        tcp_port = so.get("tcp-portrange", "")
        udp_port = so.get("udp-portrange", "")
        detail_parts = []
        if proto:
            detail_parts.append(str(proto))
        if tcp_port:
            detail_parts.append(f"TCP {tcp_port}")
        if udp_port:
            detail_parts.append(f"UDP {udp_port}")
        results.append(
            {
                "name": name,
                "type": "object",
                "category": "service",
                "detail": ", ".join(detail_parts) or "—",
                "subtype": "service",
                "members": [],
            }
        )

    for sg in svc_groups:
        if not isinstance(sg, dict):
            continue
        name = sg.get("name", "")
        if not name or query not in name.lower():
            continue
        raw_members = sg.get("member", []) or []
        members = [
            {
                "name": (m.get("name") if isinstance(m, dict) else str(m)),
                "detail": svc_detail_map.get(
                    m.get("name") if isinstance(m, dict) else str(m), ""
                ),
            }
            for m in raw_members
        ]
        results.append(
            {
                "name": name,
                "type": "group",
                "category": "service",
                "detail": f"{len(members)} member{'s' if len(members) != 1 else ''}",
                "subtype": "svcgrp",
                "members": members,
            }
        )

    results.sort(key=lambda r: r["name"].lower())
    return jsonify({"objects": results, "total": len(results)})


# ── API: object where-used ────────────────────────────────────────────────────


@bp.route("/api/hygiene/adoms/<adom>/objects/where-used", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_object_where_used(adom: str):
    """Find all groups and policy rules that reference a named object.

    Body: { "name": "OBJECT-NAME", "category": "address" | "service" }
    Returns: { name, category, groups, rules, packages_scanned }
    """
    if err := check_adom_access(adom):
        return err

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    category = (data.get("category") or "").strip().lower()

    if not name:
        return jsonify({"error": "name is required"}), 400
    if category not in ("address", "service"):
        return jsonify({"error": "category must be 'address' or 'service'"}), 400

    try:
        with make_client() as client:
            packages = client.get_policy_packages(adom)
            if category == "address":
                groups_raw = client.get_address_groups(adom)
            else:
                groups_raw = client.get_service_groups(adom)

            # Find groups that directly contain this object
            containing_groups: list[str] = []
            for grp in groups_raw:
                if not isinstance(grp, dict):
                    continue
                members = grp.get("member") or []
                member_names = {
                    (m.get("name") if isinstance(m, dict) else str(m)) for m in members
                }
                if name in member_names:
                    containing_groups.append(grp.get("name", ""))

            # Scan all policies across all packages — parallel fetch, one client per worker
            import concurrent.futures

            pkg_paths = [
                pkg.get("path") or pkg.get("name", "")
                for pkg in packages
                if pkg.get("path") or pkg.get("name", "")
            ]

            def _scan_pkg(pkg_path: str) -> tuple[list[dict], int, int]:
                """Fetch and scan one package; returns (rules, scanned, skipped)."""
                try:
                    with make_client() as c:
                        policies = c.get_policies(adom, pkg_path)
                except Exception:
                    return [], 0, 1

                rules: list[dict] = []
                for pol in policies:
                    if not isinstance(pol, dict):
                        continue
                    pol_id = str(pol.get("policyid", ""))
                    pol_name = pol.get("name", "")
                    action = _action(pol)

                    if category == "address":
                        fields = list(pol.get("srcaddr") or []) + list(
                            pol.get("dstaddr") or []
                        )
                    else:
                        fields = list(pol.get("service") or [])

                    field_names = {
                        (f.get("name") if isinstance(f, dict) else str(f))
                        for f in fields
                    }

                    if name in field_names:
                        rules.append(
                            {
                                "package": pkg_path,
                                "rule_id": pol_id,
                                "rule_name": pol_name,
                                "action": action,
                                "via": "direct",
                            }
                        )

                    for grp_name in containing_groups:
                        if grp_name in field_names:
                            rules.append(
                                {
                                    "package": pkg_path,
                                    "rule_id": pol_id,
                                    "rule_name": pol_name,
                                    "action": action,
                                    "via": grp_name,
                                }
                            )
                return rules, 1, 0

            matched_rules: list[dict] = []
            packages_scanned = 0
            skipped_packages = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for rules, scanned, skipped in pool.map(_scan_pkg, pkg_paths):
                    matched_rules.extend(rules)
                    packages_scanned += scanned
                    skipped_packages += skipped

    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    return jsonify(
        {
            "name": name,
            "category": category,
            "groups": [{"name": g} for g in containing_groups if g],
            "rules": matched_rules,
            "packages_scanned": packages_scanned,
            "skipped_packages": skipped_packages,
        }
    )


# ── API: interface lookup ─────────────────────────────────────────────────────


@bp.route("/api/hygiene/adoms/<adom>/interfaces/lookup", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_interface_lookup(adom: str):
    """Search firewall interfaces across all devices in an ADOM by IP address.

    Body: { "ips": ["10.1.2.3", "10.1.2.4"] }
    Returns: { results, total, searched_ips, skipped_devices }
    """
    if err := check_adom_access(adom):
        return err

    data = request.get_json(silent=True) or {}
    raw_ips = data.get("ips") or []
    if not raw_ips:
        return jsonify({"error": "ips is required"}), 400

    # Validate each IP
    searched_ips = []
    for raw in raw_ips:
        s = str(raw).strip()
        try:
            ipaddress.ip_address(s)
            searched_ips.append(s)
        except ValueError:
            return jsonify({"error": f"Invalid IP address: {s!r}"}), 400

    if not searched_ips:
        return jsonify({"error": "ips is required"}), 400

    searched_set = set(searched_ips)
    results = []
    skipped_devices = []

    try:
        with make_client() as client:
            devices = client.get_devices(adom) or []
            for device in devices:
                device_name = (
                    device.get("name", "") if isinstance(device, dict) else str(device)
                )
                if not device_name:
                    continue
                try:
                    interfaces = client.get_device_interfaces_all_vdoms(
                        adom, device_name
                    )
                except Exception:
                    skipped_devices.append(device_name)
                    continue

                for iface in interfaces:
                    if not isinstance(iface, dict):
                        continue
                    raw_ip = iface.get("ip", "")
                    if not raw_ip:
                        continue
                    # FortiGate format: "10.1.2.3 255.255.255.0" — extract IP part
                    ip_part = raw_ip.split()[0] if " " in raw_ip else raw_ip
                    if ip_part in searched_set:
                        results.append(
                            {
                                "device": device_name,
                                "interface": iface.get("name", ""),
                                "vdom": iface.get("vdom", "root"),
                                "ip": _cidr_from_mask(raw_ip),
                                "type": iface.get("type", ""),
                                "status": iface.get("status", ""),
                            }
                        )
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    results.sort(key=lambda r: (r["device"].lower(), r["interface"].lower()))
    return jsonify(
        {
            "results": results,
            "total": len(results),
            "searched_ips": searched_ips,
            "skipped_devices": skipped_devices,
        }
    )


# ── API: NAT lookup ───────────────────────────────────────────────────────────


@bp.route("/api/hygiene/adoms/<adom>/nat/lookup", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_nat_lookup(adom: str):
    """Search VIP and IP pool objects in an ADOM for a given IP address.

    Matches: VIP extip, VIP mappedip ranges, IP pool startip-endip ranges.
    Body: { "ip": "203.0.113.10" }
    Returns: { results, total, searched_ip }
    """
    if err := check_adom_access(adom):
        return err

    data = request.get_json(silent=True) or {}
    raw_ip = (data.get("ip") or "").strip()
    if not raw_ip:
        return jsonify({"error": "ip is required"}), 400
    try:
        searched_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return jsonify({"error": f"Invalid IP address: {raw_ip!r}"}), 400

    results = []

    # ── Phase 1: fetch ADOM-level shared VIPs and IP pools ──────────────────────
    try:
        with make_client() as client:
            shared_vips = client.get_vip_objects(adom)
            pools = client.get_ippool_objects(adom)
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    # ── Phase 2: fetch per-device VIPs in parallel ───────────────────────────────
    # ADOM shared-object VIPs (above) miss VIPs that are installed on individual
    # devices but not promoted to the shared object database.  Query each device's
    # own VIP table via the per-device DB path to catch them.
    # VDOMs are queried explicitly per device (not from the dvmdb device list,
    # which often omits the vdom field) so multi-VDOM devices are fully covered.
    device_names: list[str] = []
    try:
        with make_client() as client:
            devices = client.get_devices(adom)
        for dev in devices:
            if not isinstance(dev, dict):
                continue
            dev_name = dev.get("name", "")
            if dev_name:
                device_names.append(dev_name)
    except Exception:
        pass

    def _fetch_dev_vips(dev_name: str) -> list:
        try:
            with make_client() as c:
                vdoms_data = c.get_device_vdoms(adom, dev_name)
                vdoms = (
                    [
                        v.get("name", "root")
                        for v in vdoms_data
                        if isinstance(v, dict) and v.get("name")
                    ]
                    if vdoms_data
                    else ["root"]
                )
                all_entries: list = []
                for vdom in vdoms:
                    try:
                        entries = c.get_device_vip_objects(dev_name, vdom)
                        for e in entries:
                            if isinstance(e, dict):
                                e["_source_device"] = dev_name
                        all_entries.extend(entries)
                    except Exception:
                        pass
            return all_entries
        except Exception:
            return []

    device_vips: list = []
    if device_names:
        with ThreadPoolExecutor(max_workers=10) as pool_ex:
            for chunk in pool_ex.map(_fetch_dev_vips, device_names):
                device_vips.extend(chunk)

    # Tag ADOM-level VIPs with an empty source device marker before merging.
    for v in shared_vips:
        if isinstance(v, dict):
            v.setdefault("_source_device", "")

    all_vips = shared_vips + device_vips
    shared_vips_count = len(shared_vips)
    device_vips_count = len(device_vips)
    devices_scanned = len(device_names)

    # ── Phase 3: match VIPs ───────────────────────────────────────────────────────
    for vip in all_vips:
        if not isinstance(vip, dict):
            continue
        name = vip.get("name", "")
        if not name:
            continue
        ext_ip_raw = vip.get("extip", "")
        # FMG may return extip as a list (["1.2.3.4"]) or a plain string ("1.2.3.4").
        if isinstance(ext_ip_raw, list):
            ext_ip_raw = ext_ip_raw[0] if ext_ip_raw else ""
        ext_ip = str(ext_ip_raw)
        # Normalise extip for display; derive start/end for range matching.
        # FMG may return a single IP ("1.2.3.4") or a range ("1.2.3.4-1.2.3.9").
        try:
            ext_ip = str(ipaddress.ip_address(ext_ip))
            ext_ip_start = ext_ip_end = ext_ip
        except ValueError:
            if "-" in ext_ip:
                ext_ip_start, _, ext_ip_end = ext_ip.partition("-")
                ext_ip_start = ext_ip_start.strip()
                ext_ip_end = ext_ip_end.strip()
            else:
                ext_ip_start = ext_ip_end = ext_ip
        # FMG may return the field as "mappedip" or "mapped-ip" depending on version/context.
        # Normalise to a flat list of range strings: handles list-of-dicts, list-of-strings,
        # and plain string (all observed FMG variants).
        mapped_raw = vip.get("mappedip") or vip.get("mapped-ip") or []
        if isinstance(mapped_raw, str):
            mapped_ranges_strs = [mapped_raw] if mapped_raw else []
        elif isinstance(mapped_raw, list):
            mapped_ranges_strs = []
            for _e in mapped_raw:
                if isinstance(_e, dict):
                    _r = _e.get("range", "")
                    if _r:
                        mapped_ranges_strs.append(_r)
                elif isinstance(_e, str) and _e:
                    mapped_ranges_strs.append(_e)
        else:
            mapped_ranges_strs = []

        matched = False
        if _ip_in_range(searched_ip, ext_ip_start, ext_ip_end):
            matched = True
        if not matched:
            for rng in mapped_ranges_strs:
                if "-" in rng:
                    start, _, end = rng.partition("-")
                else:
                    start = end = rng
                if _ip_in_range(searched_ip, start.strip(), end.strip()):
                    matched = True
                    break

        if not matched:
            continue

        mapped_display = "; ".join(mapped_ranges_strs) or "—"

        ext_intf_raw = vip.get("extintf", "")
        if isinstance(ext_intf_raw, list):
            ext_intf_raw = ext_intf_raw[0] if ext_intf_raw else ""

        port_forward = vip.get("portforward", "disable") == "enable"
        results.append(
            {
                "nat_type": "VIP",
                "name": name,
                "device": vip.get("_source_device", ""),
                "ext_ip": ext_ip,
                "ext_intf": ext_intf_raw,
                "mapped_ip": mapped_display,
                "port_forward": port_forward,
                "protocol": vip.get("protocol", "") if port_forward else "",
                "ext_port": vip.get("extport", "") if port_forward else "",
                "mapped_port": vip.get("mappedport", "") if port_forward else "",
                "comments": vip.get("comment", "") or vip.get("comments", ""),
            }
        )

    # ── Phase 4: match IP pools ───────────────────────────────────────────────────
    for pool in pools:
        if not isinstance(pool, dict):
            continue
        name = pool.get("name", "")
        start_ip = pool.get("startip", "")
        end_ip = pool.get("endip", "")
        if not name or not start_ip or not end_ip:
            continue
        if not _ip_in_range(searched_ip, start_ip, end_ip):
            continue
        results.append(
            {
                "nat_type": "IP Pool",
                "name": name,
                "device": "",
                "start_ip": start_ip,
                "end_ip": end_ip,
                "pool_type": pool.get("type", ""),
                "comments": pool.get("comments", "") or pool.get("comment", ""),
            }
        )

    return jsonify(
        {
            "results": results,
            "total": len(results),
            "searched_ip": searched_ip,
            "objects_checked": {
                "shared_vips": shared_vips_count,
                "device_vips": device_vips_count,
                "devices": devices_scanned,
                "pools": len(pools),
            },
        }
    )


# ── AI Explain ─────────────────────────────────────────────────────────────


@bp.route("/api/hygiene/ai-explain-status")
@tab_required("rule_hygiene")
def hygiene_ai_explain_status():
    from app.app_settings import get_setting

    return jsonify({"available": get_setting("ai_assist_enabled", False)})


@bp.route("/api/hygiene/explain-finding", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_explain_finding():
    """Explain one already-computed Rule Hygiene finding. The LLM never
    re-runs a check — app.hygiene.run_checks() already produced this
    finding. Best-effort: any failure degrades to narrative=None, never
    a 500."""
    from app.app_settings import get_setting

    if not get_setting("ai_assist_enabled", False):
        return jsonify({"error": "AI Assist is not enabled"}), 503

    finding = request.get_json(silent=True) or {}
    if not isinstance(finding, dict):
        return jsonify({"error": "body must be a finding object"}), 400
    if not finding.get("check"):
        return jsonify({"error": "check is required"}), 400

    from app.hygiene_ai import explain_finding

    narrative = None
    narrative_error = None
    try:
        narrative = explain_finding(finding, user=session.get("user"))
    except Exception as exc:
        narrative_error = str(exc)

    return jsonify({"narrative": narrative, "narrative_error": narrative_error})


# ── API: run checks ───────────────────────────────────────────────────────────


@bp.route("/api/hygiene/run", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_run():
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    path = _pkg_path(data)
    checks = data.get("checks", list(CHECKS.keys()))

    if not adom or not path:
        return jsonify({"error": "adom and package are required"}), 400
    if err := check_adom_access(adom):
        return err

    valid_checks = [c for c in checks if c in CHECKS]
    if not valid_checks:
        return jsonify({"error": "No valid check keys provided"}), 400

    addr_resolver = None
    svc_resolver = None

    try:
        with make_client() as client:
            policies = client.get_policies(adom, path)
            pkg_settings = client.get_pkg_settings(adom, path)

            # For the unhit check, FMG's stored _hitcount is only updated when
            # FMG syncs stats from the device — which may be stale or never run.
            # Fetch live hit counts from each device in scope and overlay them so
            # the check always reflects what the device actually sees.
            if "unhit" in valid_checks:
                scope = client.get_pkg_scope_members(adom, path)
                live_hits: dict[int, int] = {}
                for member in scope[:10]:
                    dev = (
                        member.get("name", "")
                        if isinstance(member, dict)
                        else str(member)
                    )
                    vdom = (
                        member.get("vdom", "root")
                        if isinstance(member, dict)
                        else "root"
                    )
                    if not dev:
                        continue
                    for pid, count in client.get_live_policy_hits(
                        adom, dev, vdom
                    ).items():
                        live_hits[pid] = live_hits.get(pid, 0) + count
                if live_hits:
                    for p in policies:
                        pid = p.get("policyid")
                        if pid is not None:
                            p["_hitcount"] = live_hits.get(
                                int(pid), p.get("_hitcount") or 0
                            )

            # For the shadow check, fetch address and service objects so the
            # check engine can detect IP-containment shadowing in addition to
            # exact name-match shadowing.
            if "shadow" in valid_checks:
                try:
                    addr_objects = client.get_address_objects(adom)
                    addr_groups = client.get_address_groups(adom)
                    vip_objects = client.get_vip_objects(adom)
                    svc_objects = client.get_service_objects(adom)
                    svc_groups = client.get_service_groups(adom)
                    addr_resolver = build_addr_resolver(
                        addr_objects, addr_groups, vip_objects
                    )
                    svc_resolver = build_svc_resolver(svc_objects, svc_groups)
                except Exception:
                    # Object fetch failure is non-fatal — fall back to name-only matching.
                    addr_resolver = None
                    svc_resolver = None

    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    findings = run_checks(
        policies,
        valid_checks,
        pkg_settings=pkg_settings,
        addr_resolver=addr_resolver,
        svc_resolver=svc_resolver,
    )

    # Build a lookup so each finding can carry its rule's detail fields.
    # Shadow findings already carry shadow_rule/shadowing_rule; all others get rule_detail.
    _policy_by_id: dict[str, dict] = {}
    for p in policies:
        if isinstance(p, dict):
            pid = str(p.get("policyid", ""))
            if pid:
                _policy_by_id[pid] = p

    def _names(val) -> list[str]:
        if not val:
            return []
        if isinstance(val, str):
            return [val]
        return [(i.get("name", str(i)) if isinstance(i, dict) else str(i)) for i in val]

    for f in findings:
        if "shadow_rule" in f or "rule_detail" in f:
            continue
        p = _policy_by_id.get(f["policy_id"])
        if not p:
            continue
        f["rule_detail"] = {
            "id": str(p.get("policyid", "?")),
            "name": str(p.get("name") or ""),
            "status": _status(p),
            "action": _action(p),
            "srcaddr": _names(p.get("srcaddr") or p.get("src_addr")),
            "dstaddr": _names(p.get("dstaddr") or p.get("dst_addr")),
            "service": _names(p.get("service") or p.get("services")),
            "srcintf": _names(p.get("srcintf")),
            "dstintf": _names(p.get("dstintf")),
            "fsso_groups": _names(p.get("fsso-groups")),
            "comment": str(p.get("comments") or p.get("comment") or ""),
        }

    pkg_display = path.rsplit("/", 1)[-1]
    return jsonify(
        {
            "adom": adom,
            "package": pkg_display,
            "checks_run": valid_checks,
            "policy_count": len(policies),
            "total": len(findings),
            "findings": findings,
        }
    )


@bp.route("/api/hygiene/unused-objects")
@tab_required("rule_hygiene")
def hygiene_unused_objects():
    """Return address/service objects not referenced by any rule in the given package."""
    adom = (request.args.get("adom") or "").strip()
    path = (request.args.get("pkg") or "").strip()
    scope = (request.args.get("scope") or "all").strip()
    if scope not in ("all", "local", "global"):
        scope = "all"
    if not adom or not path:
        return jsonify({"error": "adom and pkg are required"}), 400
    if err := check_adom_access(adom):
        return err
    try:
        with make_client() as client:
            policies = client.get_policies(adom, path) or []
            addresses = client.get_address_objects(adom, scope=scope) or []
            addr_groups = client.get_address_groups(adom, scope=scope) or []
            services = client.get_service_objects(adom, scope=scope) or []
            svc_groups = client.get_service_groups(adom, scope=scope) or []
    except FMGError as exc:
        return upstream_api_error("hygiene", exc)
    except Exception as exc:
        return internal_api_error("hygiene", exc)

    result = find_unused_objects(policies, addresses, addr_groups, services, svc_groups)
    return jsonify(
        {
            "adom": adom,
            "pkg": path,
            "unused_addresses": result["unused_addresses"],
            "unused_services": result["unused_services"],
            "total_addresses": len(addresses) + len(addr_groups),
            "total_services": len(services) + len(svc_groups),
            "checked_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        }
    )
