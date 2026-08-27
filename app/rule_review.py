"""Rule Validation analysis engine.

Takes a list of requested flows (src IPs, dst IPs, ports/services) and one or
more FortiGate policy packages, then determines:
  - Whether each flow is already permitted by existing rules
  - Whether an existing rule could be modified to permit it
  - Whether a new rule is needed, and where to insert it
  - What FortiOS CLI syntax to generate for each device
  - Zone policy segmentation verdict (via local policy_db.json)
  - Whether this firewall is actually in the traffic path (routing check)
"""

from __future__ import annotations

import ipaddress

# ── Zone policy integration ───────────────────────────────────────────────────
# Uses app.zone_db — the embedded segmentation policy engine that reads
# policy_db.json directly from the project root. No external service required.


def zone_script_available() -> bool:
    import app.zone_db as zdb

    return zdb.db_available()


def _zone_unavailable() -> dict:
    return {
        "available": False,
        "source": "none",
        "verdict": "UNAVAILABLE",
        "src_zones": [],
        "dst_zones": [],
        "governing": [],
        "all_policies": [],
    }


def query_zone_policy(src: str, dst: str, service: str) -> dict:
    """Run zone policy flow query using local policy_db.json."""
    import app.zone_db as zdb

    if not zdb.db_available():
        return _zone_unavailable()
    try:
        r = zdb.query_single(src, dst, service)
        if not r:
            return _zone_unavailable()
        return {
            "available": True,
            "source": "local",
            "verdict": r.get("verdict", "UNKNOWN"),
            "src_zones": r.get("src_zones", []),
            "dst_zones": r.get("dst_zones", []),
            "governing": r.get("governing", []),
            "all_policies": r.get("all_policies", []),
        }
    except Exception as exc:
        return {
            "available": True,
            "source": "local",
            "verdict": "ERROR",
            "src_zones": [],
            "dst_zones": [],
            "governing": [],
            "all_policies": [],
            "error": str(exc),
        }


# ── Address / subnet helpers ──────────────────────────────────────────────────


def _parse_addr(raw: str):
    raw = raw.strip()
    if not raw:
        return None
    try:
        if "/" in raw:
            return ipaddress.ip_network(raw, strict=False)
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def _ip_in_network(ip_str: str, net_str: str) -> bool:
    try:
        ip_part = ip_str.split("/")[0]
        ip = ipaddress.ip_address(ip_part)
        net = ipaddress.ip_network(net_str, strict=False)
        return ip in net
    except ValueError:
        return False


def _nets_overlap(a: str, b: str) -> bool:
    try:
        na = ipaddress.ip_network(a, strict=False)
        nb = ipaddress.ip_network(b, strict=False)
        return na.overlaps(nb)
    except ValueError:
        return False


def _addr_matches(query: str, net_str: str) -> bool:
    """True if query (IP or CIDR) overlaps with net_str."""
    if "/" in query:
        return _nets_overlap(query, net_str)
    return _ip_in_network(query, net_str)


def _is_broad_match(query: str, net_str: str) -> bool:
    """True if a single-host query is covered only via a subnet broader
    than /24 — the match is valid but may be incidental; callers should warn."""
    if "/" in query:
        return False
    try:
        ip = ipaddress.ip_address(query.strip())
        net = ipaddress.ip_network(net_str, strict=False)
        return ip in net and 0 < net.prefixlen < 24
    except ValueError:
        return False


# ── Address object resolution ─────────────────────────────────────────────────


def _build_addr_map(addr_objects: list, addr_groups: list) -> dict[str, list[str]]:
    obj_map: dict[str, list[str]] = {}
    for obj in addr_objects:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name", "")
        if not name:
            continue
        subnets: list[str] = []
        subnet_raw = obj.get("subnet") or obj.get("ip") or ""
        if isinstance(subnet_raw, str) and subnet_raw:
            parts = subnet_raw.split()
            if len(parts) == 2:
                try:
                    net = ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
                    subnets.append(str(net))
                except ValueError:
                    pass
            elif len(parts) == 1 and "/" in parts[0]:
                subnets.append(parts[0])
        elif isinstance(subnet_raw, list):
            # FMG returns subnet as either ["ip", "mask"] (two elements) or
            # a list of CIDR strings — handle both forms.
            strs = [str(e) for e in subnet_raw if e]
            if len(strs) == 2 and "/" not in strs[0] and "/" not in strs[1]:
                try:
                    net = ipaddress.IPv4Network(f"{strs[0]}/{strs[1]}", strict=False)
                    subnets.append(str(net))
                except ValueError:
                    pass
            else:
                for s in strs:
                    if "/" in s:
                        subnets.append(s)
        obj_map[name] = subnets

    # Build a member list lookup keyed by group name, then expand iteratively.
    # Two-pass expansion fails when groups are nested more than two levels deep
    # or when parent groups appear before child groups in the API response.
    grp_members: dict[str, list[str]] = {}
    for grp in addr_groups:
        if not isinstance(grp, dict):
            continue
        name = grp.get("name", "")
        members = grp.get("member") or []
        if isinstance(members, str):
            members = [members]
        grp_members[name] = [
            m.get("name", m) if isinstance(m, dict) else str(m) for m in members
        ]

    grp_map: dict[str, list[str]] = {}
    for name, members in grp_members.items():
        subnets: list[str] = []
        for m_name in members:
            subnets.extend(obj_map.get(m_name, []))
        grp_map[name] = subnets

    # Expand group-in-group iteratively until no new subnets are added.
    # Handles arbitrary nesting depth regardless of ordering in the API response.
    for _ in range(20):
        changed = False
        for name, members in grp_members.items():
            existing = grp_map.get(name, [])
            expanded = list(existing)
            for m_name in members:
                for s in grp_map.get(m_name, []):
                    if s not in expanded:
                        expanded.append(s)
                        changed = True
            grp_map[name] = expanded
        if not changed:
            break

    return {**obj_map, **grp_map}


def _resolve_addrs(names: list, addr_map: dict[str, list[str]]) -> list[str]:
    subnets: list[str] = []
    for n in names:
        name = n.get("name", n) if isinstance(n, dict) else str(n)
        if name.lower() == "all":
            subnets.append("0.0.0.0/0")
        else:
            subnets.extend(addr_map.get(name, []))
    return list(dict.fromkeys(subnets))


# ── Service port helpers ──────────────────────────────────────────────────────

_SVC_WELL_KNOWN: dict[str, list[int]] = {
    "http": [80],
    "https": [443],
    "ssh": [22],
    "telnet": [23],
    "ftp": [21],
    "smtp": [25],
    "dns": [53],
    "snmp": [161],
    "rdp": [3389],
    "mssql": [1433],
    "mysql": [3306],
    "ntp": [123],
    "tftp": [69],
    "syslog": [514],
    "ldap": [389],
    "ldaps": [636],
    "smb": [445],
    "vnc": [5900],
    "http-alt": [8080],
    "https-alt": [8443],
}


def _svc_to_ports(token: str) -> list[tuple[str, int]]:
    token = token.strip()
    if not token:
        return []
    if "/" in token:
        parts = token.split("/", 1)
        proto = parts[0].lower()
        try:
            return [(proto, int(parts[1]))]
        except ValueError:
            return []
    if token.isdigit():
        return [("tcp", int(token))]
    return [("tcp", p) for p in _SVC_WELL_KNOWN.get(token.lower(), [])]


def _build_svc_map(
    svc_objects: list, svc_groups: list
) -> dict[str, list[tuple[str, int]]]:
    obj_map: dict[str, list[tuple[str, int]]] = {}
    for obj in svc_objects:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name", "")
        if not name:
            continue
        ports: list[tuple[str, int]] = []
        for proto in ("tcp", "udp"):
            field = obj.get(f"{proto}-portrange") or ""
            if not field:
                continue
            for part in str(field).split():
                dst_part = part.split(":")[0]
                if "-" in dst_part:
                    try:
                        lo, hi = dst_part.split("-", 1)
                        for p in range(int(lo), min(int(hi) + 1, int(lo) + 100)):
                            ports.append((proto, p))
                    except ValueError:
                        pass
                else:
                    try:
                        ports.append((proto, int(dst_part)))
                    except ValueError:
                        pass
        obj_map[name] = ports

    grp_map: dict[str, list[tuple[str, int]]] = {}
    for grp in svc_groups:
        if not isinstance(grp, dict):
            continue
        name = grp.get("name", "")
        members = grp.get("member") or []
        if isinstance(members, str):
            members = [members]
        ports: list[tuple[str, int]] = []
        for m in members:
            m_name = m.get("name", m) if isinstance(m, dict) else str(m)
            ports.extend(obj_map.get(m_name, []))
        grp_map[name] = ports

    return {**obj_map, **grp_map}


def _resolve_services(
    names: list, svc_map: dict[str, list[tuple[str, int]]]
) -> list[tuple[str, int]]:
    ports: list[tuple[str, int]] = []
    for n in names:
        name = n.get("name", n) if isinstance(n, dict) else str(n)
        if name.upper() in ("ALL", "ANY"):
            return [("any", 0)]
        custom = svc_map.get(name)
        if custom:
            ports.extend(custom)
        else:
            # Fall through to well-known table whether the name is absent OR
            # present but resolved to an empty list (custom object with no
            # parseable port range shadows the well-known entry otherwise).
            for p in _SVC_WELL_KNOWN.get(name.lower(), []):
                ports.append(("tcp", p))
    return list(dict.fromkeys(ports))


def _port_covered(
    requested: list[tuple[str, int]], rule_ports: list[tuple[str, int]]
) -> bool:
    if not requested:
        return True
    if not rule_ports:
        return False
    for rp_proto, rp_port in requested:
        covered = False
        for rule_proto, rule_port in rule_ports:
            if rule_proto == "any" or rule_port == 0:
                covered = True
                break
            proto_ok = rule_proto == rp_proto or rp_proto == "any"
            port_ok = rule_port == rp_port
            if proto_ok and port_ok:
                covered = True
                break
        if not covered:
            return False
    return True


# ── Routing / path-relevance check ───────────────────────────────────────────


def _cidr_prefix(net_str: str) -> int:
    try:
        return ipaddress.ip_network(net_str, strict=False).prefixlen
    except Exception:
        return -1


def check_path_relevance(
    src: str,
    dst: str,
    interfaces: list,
    routes: list,
) -> dict:
    """Determine whether a firewall is likely in the traffic path.

    Returns::
        {
            "in_path":       True | False | None,   # None = unknown (no data)
            "confidence":    "high" | "medium" | "low",
            "src_reachable": bool,
            "dst_reachable": bool,
            "src_iface":     str | None,
            "dst_iface":     str | None,
            "src_route":     dict | None,
            "dst_route":     dict | None,
            "notes":         [str, ...],
        }
    """
    result: dict = {
        "in_path": None,
        "confidence": "low",
        "src_reachable": False,
        "dst_reachable": False,
        "src_iface": None,
        "dst_iface": None,
        "src_route": None,
        "dst_route": None,
        "notes": [],
    }

    if not interfaces and not routes:
        result["notes"].append(
            "No interface or routing data available from this device."
        )
        return result

    # Build a list of (network, interface_name, ip) from interface data
    iface_nets: list[tuple[ipaddress.IPv4Network, str, str]] = []
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        name = iface.get("name", "")
        ip_raw = iface.get("ip", iface.get("ipv4_address", ""))
        mask = iface.get("mask", iface.get("netmask", ""))
        link = iface.get("link", iface.get("status", ""))

        if not ip_raw or ip_raw in ("0.0.0.0", ""):
            continue
        if isinstance(link, int):
            link = "up" if link else "down"
        if str(link).lower() in ("down", "0", "false"):
            continue
        try:
            # CMDB returns ip as "A.B.C.D M.M.M.M" (space-separated) or "A.B.C.D/M.M.M.M"
            if isinstance(ip_raw, str) and " " in ip_raw:
                parts = ip_raw.split()
                ip_raw, mask = parts[0], parts[1]
            if ip_raw in ("0.0.0.0", ""):
                continue
            if mask and mask != "0.0.0.0":
                net = ipaddress.IPv4Network(f"{ip_raw}/{mask}", strict=False)
            elif "/" in ip_raw:
                net = ipaddress.IPv4Network(ip_raw, strict=False)
            else:
                continue
            iface_nets.append((net, name, ip_raw))
        except ValueError:
            continue

    def best_iface_match(addr: str):
        addr_part = addr.split("/")[0]
        try:
            ip = ipaddress.ip_address(addr_part)
        except ValueError:
            return None, None
        best_prefix = -1
        best_name = None
        for net, iface_name, _ in iface_nets:
            if ip in net and net.prefixlen > best_prefix:
                best_prefix = net.prefixlen
                best_name = iface_name
        return best_name, best_prefix

    src_iface, _src_prefix = best_iface_match(src)
    dst_iface, _dst_prefix = best_iface_match(dst)

    if src_iface:
        result["src_iface"] = src_iface
        result["src_reachable"] = True
    if dst_iface:
        result["dst_iface"] = dst_iface
        result["dst_reachable"] = True

    # Route table lookup
    def best_route(addr: str) -> dict | None:
        addr_part = addr.split("/")[0]
        try:
            target_ip = ipaddress.ip_address(addr_part)
        except ValueError:
            return None
        best_pfx = -1
        best_entry = None
        for route in routes:
            if not isinstance(route, dict):
                continue
            pfx_raw = route.get(
                "ip_mask", route.get("network", route.get("prefix", ""))
            )
            gw = route.get("gateway", route.get("nexthop", ""))
            iface_r = route.get("interface", route.get("dev", route.get("ifname", "")))
            try:
                net = ipaddress.ip_network(pfx_raw, strict=False)
                if target_ip in net and net.prefixlen > best_pfx:
                    best_pfx = net.prefixlen
                    best_entry = {
                        "network": str(net),
                        "gateway": gw,
                        "interface": iface_r,
                        "prefix": net.prefixlen,
                    }
            except ValueError:
                continue
        return best_entry

    src_route = best_route(src)
    dst_route = best_route(dst)
    result["src_route"] = src_route
    result["dst_route"] = dst_route

    if src_route:
        result["src_reachable"] = True
        if not result["src_iface"]:
            result["src_iface"] = src_route.get("interface")
    if dst_route:
        result["dst_reachable"] = True
        if not result["dst_iface"]:
            result["dst_iface"] = dst_route.get("interface")

    src_ok = result["src_reachable"]
    dst_ok = result["dst_reachable"]

    if src_ok and dst_ok:
        same_iface = (
            result["src_iface"]
            and result["dst_iface"]
            and result["src_iface"] == result["dst_iface"]
        )
        if same_iface:
            result["in_path"] = False
            result["confidence"] = "medium"
            result["notes"].append(
                f"Both source and destination resolve to the same interface "
                f"({result['src_iface']}) — traffic may stay within one segment; "
                f"proceed with caution, rule may not be needed on this device."
            )
        else:
            result["in_path"] = True
            result["confidence"] = "high"
            result["notes"].append(
                f"Source routes via {result['src_iface'] or '?'}, "
                f"destination via {result['dst_iface'] or '?'} — "
                f"firewall appears to be in the traffic path."
            )
    elif src_ok and not dst_ok:
        result["in_path"] = False
        result["confidence"] = "medium"
        result["notes"].append(
            f"Source ({src}) is reachable via {result['src_iface'] or 'an interface'} "
            f"but destination ({dst}) has no route on this device — "
            f"this firewall may not be in the path for the destination; proceed with caution."
        )
    elif not src_ok and dst_ok:
        result["in_path"] = False
        result["confidence"] = "medium"
        result["notes"].append(
            f"Destination ({dst}) is reachable via {result['dst_iface'] or 'an interface'} "
            f"but source ({src}) has no route — "
            f"this firewall may not be in the path for the source; proceed with caution."
        )
    else:
        result["in_path"] = False
        result["confidence"] = "low"
        result["notes"].append(
            f"Neither source ({src}) nor destination ({dst}) resolve to "
            f"any interface or route on this device — "
            f"this firewall is likely NOT in the traffic path; proceed with caution."
        )

    return result


# ── FortiOS CLI generator ─────────────────────────────────────────────────────


def _fortios_cli(
    device_name: str, pkg_path: str, flow: dict, insert_after: int | None = None
) -> str:
    src = flow.get("src", "any")
    dst = flow.get("dst", "any")
    svc = flow.get("service", "ANY")
    comment = flow.get("comment", f"Rule Validation: {src} -> {dst} {svc}")

    lines = [
        f"# Device: {device_name}  |  Package: {pkg_path}",
        "config firewall policy",
    ]
    if insert_after is not None:
        lines.append(f"    # Insert after policy ID {insert_after}")
    lines += [
        "    edit 0",
        f'        set name "{comment[:35]}"',
        '        set srcintf "any"',
        '        set dstintf "any"',
        f'        set srcaddr "{src}"',
        f'        set dstaddr "{dst}"',
        f'        set service "{svc.upper()}"',
        "        set action accept",
        "        set logtraffic all",
        '        set comments "Created via Rule Validation"',
        "    next",
        "end",
    ]
    return "\n".join(lines)


# ── Main analysis function ────────────────────────────────────────────────────


def analyze_flows(
    requested_flows: list[dict],
    packages: list[dict],
    policies_by_pkg: dict[str, list],
    addr_objects: list,
    addr_groups: list,
    svc_objects: list,
    svc_groups: list,
    routing_by_device: dict[str, dict] | None = None,
) -> list[dict]:
    """Analyse each requested flow against the selected policy packages.

    Args:
        requested_flows:    [{src, dst, service, comment}, ...]
        packages:           [{adom, name, path, device}, ...]
        policies_by_pkg:    {f"{adom}/{path}": [policy, ...]}
        addr_objects/groups: firewall address objects (merged from all ADOMs)
        svc_objects/groups:  service objects
        routing_by_device:  {device_name: {"interfaces": [...], "routes": [...]}}
                            Optional — when provided enables path-relevance check.
    """
    addr_map = _build_addr_map(addr_objects, addr_groups)
    svc_map = _build_svc_map(svc_objects, svc_groups)
    routing = routing_by_device or {}

    results: list[dict] = []

    for flow in requested_flows:
        src_raw = flow.get("src", "").strip()
        dst_raw = flow.get("dst", "").strip()
        svc_raw = flow.get("service", "").strip()
        comment = flow.get("comment", "")

        svc_tokens = _svc_to_ports(svc_raw) if svc_raw else []

        # Zone-script verdict — called once per flow (not per package)
        zone_result = query_zone_policy(src_raw, dst_raw, svc_raw)

        for pkg in packages:
            adom = pkg["adom"]
            pkg_path = pkg["path"]
            pkg_name = pkg["name"]
            device = pkg.get("device", "")
            pkg_key = f"{adom}/{pkg_path}"
            policies = policies_by_pkg.get(pkg_key, [])

            # Path-relevance check for this device
            dev_key = device or pkg_name
            if dev_key in routing:
                path_check = check_path_relevance(
                    src_raw,
                    dst_raw,
                    routing[dev_key].get("interfaces", []),
                    routing[dev_key].get("routes", []),
                )
            else:
                path_check = {
                    "in_path": None,
                    "confidence": "low",
                    "src_reachable": False,
                    "dst_reachable": False,
                    "src_iface": None,
                    "dst_iface": None,
                    "src_route": None,
                    "dst_route": None,
                    "notes": ["Routing data not available for this device."],
                }

            result: dict = {
                "src": src_raw,
                "dst": dst_raw,
                "service": svc_raw,
                "comment": comment,
                "adom": adom,
                "pkg_path": pkg_path,
                "pkg_name": pkg_name,
                "device": device,
                # Zone-script
                "zone_verdict": zone_result["verdict"],
                "zone_source": zone_result.get("source", "none"),
                "zone_src": zone_result.get("src_zones", []),
                "zone_dst": zone_result.get("dst_zones", []),
                "zone_governing": zone_result.get("governing", []),
                "zone_all_policies": zone_result.get("all_policies", []),
                "zone_available": zone_result.get("available", False),
                # Path-relevance
                "path_in_path": path_check["in_path"],
                "path_confidence": path_check["confidence"],
                "path_src_iface": path_check["src_iface"],
                "path_dst_iface": path_check["dst_iface"],
                "path_src_route": path_check["src_route"],
                "path_dst_route": path_check["dst_route"],
                "path_notes": path_check["notes"],
                # Policy analysis
                "verdict": "NEW_RULE_NEEDED",
                "matching_rules": [],
                "modifiable_rules": [],
                "suggested_position": None,
                "fortios_cli": "",
                "notes": [],
            }

            matching: list[dict] = []
            modifiable: list[dict] = []
            last_permit_seq: int | None = None

            for idx, pol in enumerate(policies):
                if not isinstance(pol, dict):
                    continue

                pol_id = pol.get("policyid", idx + 1)
                pol_name = pol.get("name") or ""
                action_raw = pol.get("action", 1)
                action = "accept" if action_raw in (1, "accept") else "deny"
                status_raw = pol.get("status", 1)
                enabled = status_raw in (1, "enable")

                if not enabled:
                    continue

                src_names = pol.get("srcaddr") or []
                dst_names = pol.get("dstaddr") or []
                svc_names = pol.get("service") or []

                if isinstance(src_names, str):
                    src_names = [src_names]
                if isinstance(dst_names, str):
                    dst_names = [dst_names]
                if isinstance(svc_names, str):
                    svc_names = [svc_names]

                src_nets = _resolve_addrs(src_names, addr_map)
                dst_nets = _resolve_addrs(dst_names, addr_map)
                rule_ports = _resolve_services(svc_names, svc_map)

                src_any = any(
                    (m.get("name", m) if isinstance(m, dict) else m).lower()
                    in ("all", "any")
                    for m in src_names
                )
                dst_any = any(
                    (m.get("name", m) if isinstance(m, dict) else m).lower()
                    in ("all", "any")
                    for m in dst_names
                )
                svc_any = any((p == "any" or port == 0) for p, port in rule_ports)

                src_matched_nets = [
                    net for net in src_nets if net and _addr_matches(src_raw, net)
                ]
                dst_matched_nets = [
                    net for net in dst_nets if net and _addr_matches(dst_raw, net)
                ]
                src_match = src_any or bool(src_matched_nets)
                dst_match = dst_any or bool(dst_matched_nets)
                src_broad = not src_any and any(
                    _is_broad_match(src_raw, net) for net in src_matched_nets
                )
                dst_broad = not dst_any and any(
                    _is_broad_match(dst_raw, net) for net in dst_matched_nets
                )
                svc_match = (
                    svc_any or not svc_tokens or _port_covered(svc_tokens, rule_ports)
                )

                if action == "accept":
                    last_permit_seq = pol_id

                if src_match and dst_match:
                    if svc_match:
                        entry = {
                            "id": pol_id,
                            "name": pol_name,
                            "action": action,
                            "seq": idx + 1,
                        }
                        if src_broad or dst_broad:
                            entry["broad_cover"] = True
                            result["notes"].append(
                                f"⚠ Rule ID {pol_id} ({pol_name or 'unnamed'}) covers "
                                "this flow only via a subnet broader than /24 — verify "
                                "the host is intentionally in scope."
                            )
                        matching.append(entry)
                    elif action == "accept":
                        modifiable.append(
                            {
                                "id": pol_id,
                                "name": pol_name,
                                "action": action,
                                "seq": idx + 1,
                                "suggestion": f"Add service '{svc_raw}' to this rule's service list",
                            }
                        )

            result["matching_rules"] = matching
            result["modifiable_rules"] = modifiable

            permit_rules = [r for r in matching if r["action"] == "accept"]
            deny_rules = [r for r in matching if r["action"] == "deny"]

            if permit_rules:
                result["verdict"] = "PERMITTED"
                result["notes"].append(
                    f"Flow already permitted by rule ID {permit_rules[0]['id']} "
                    f"({permit_rules[0]['name'] or 'unnamed'})"
                )
            elif deny_rules:
                result["verdict"] = "EXPLICITLY_DENIED"
                result["notes"].append(
                    f"Flow explicitly denied by rule ID {deny_rules[0]['id']} "
                    f"({deny_rules[0]['name'] or 'unnamed'})"
                )
            elif modifiable:
                result["verdict"] = "MODIFIABLE"
                result["notes"].append(
                    f"Rule ID {modifiable[0]['id']} covers src/dst — add service to permit"
                )
            else:
                result["verdict"] = "NEW_RULE_NEEDED"
                if last_permit_seq:
                    result["suggested_position"] = last_permit_seq
                    result["notes"].append(
                        f"Suggest inserting new rule after ID {last_permit_seq}"
                    )
                else:
                    result["notes"].append(
                        "No existing permit rules found — insert at top of package"
                    )

            # Zone policy warnings
            if zone_result["available"]:
                zv = zone_result["verdict"]
                if zv == "BLOCKED":
                    result["notes"].append(
                        f"⚠ ZONE POLICY BLOCKED: "
                        f"{', '.join(zone_result.get('src_zones', [])) or '(no zone)'} → "
                        f"{', '.join(zone_result.get('dst_zones', [])) or '(no zone)'} "
                        f"is blocked by segmentation policy"
                    )
                elif zv == "UNKNOWN":
                    result["notes"].append(
                        "Zone policy: no rule covers this zone pair — treat as implicit deny"
                    )

            # Path-relevance warnings
            if path_check["in_path"] is False:
                result["notes"].append(
                    f"⚠ PATH CHECK: {path_check['notes'][0] if path_check['notes'] else 'Device may not be in traffic path'}"
                )
            elif path_check["in_path"] is True:
                result["notes"].append(
                    f"✓ PATH CHECK: {path_check['notes'][0] if path_check['notes'] else 'Device appears in traffic path'}"
                )

            # CLI snippet
            if result["verdict"] in ("NEW_RULE_NEEDED", "EXPLICITLY_DENIED"):
                result["fortios_cli"] = _fortios_cli(
                    device_name=device or pkg_name,
                    pkg_path=pkg_path,
                    flow={
                        "src": src_raw,
                        "dst": dst_raw,
                        "service": svc_raw or "ANY",
                        "comment": comment,
                    },
                    insert_after=result.get("suggested_position"),
                )

            results.append(result)

    return results
