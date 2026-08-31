"""Network segmentation policy database — query, edit, and validate logic.

The policy database lives at ``policy_db.json`` in the project root.
This module is the single source of truth for all zone/policy operations
inside 4THealth; the external zone-script service is no longer used.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from app.atomic_io import atomic_write_json

# policy_db.json sits at the project root (one level above app/)
DB_PATH = Path(__file__).parent.parent / "policy_db.json"

VALID_ACCESS_TYPES: set[str] = {"allow all", "block all", "block only", "allow only"}
VALID_SEVERITIES: set[str] = {"high", "critical"}
ZONE_MUTABLE_FIELDS: set[str] = {"domain", "description", "is_shared", "trust_level"}
POLICY_MUTABLE_FIELDS: set[str] = {
    "policy_set",
    "from_domain",
    "from_zone",
    "to_domain",
    "to_zone",
    "severity",
    "access_type",
    "services",
    "rule_properties",
    "flows",
    "description",
}

# Port → well-known service name(s)
_PORT_TO_NAMES: dict[int, list[str]] = {
    20: ["ftp-data", "ftp"],
    21: ["ftp"],
    22: ["ssh"],
    23: ["telnet"],
    25: ["smtp"],
    53: ["dns"],
    80: ["http"],
    110: ["pop3"],
    143: ["imap"],
    161: ["snmp"],
    162: ["snmp-trap", "snmp"],
    389: ["ldap"],
    443: ["https"],
    445: ["smb", "cifs"],
    514: ["syslog"],
    636: ["ldaps"],
    1433: ["mssql", "sql"],
    1521: ["oracle"],
    3306: ["mysql"],
    3389: ["rdp", "RDP"],
    5432: ["postgresql", "postgres"],
    5900: ["vnc"],
    8080: ["http-alt", "http"],
    8443: ["https-alt", "https"],
}


# ── I/O ───────────────────────────────────────────────────────────────────────


def load_db() -> dict:
    if not DB_PATH.exists():
        raise FileNotFoundError(f"policy_db.json not found at {DB_PATH}")
    with open(DB_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_db(db: dict) -> None:
    atomic_write_json(DB_PATH, db)


def db_available() -> bool:
    return DB_PATH.exists()


# ── Service helpers ───────────────────────────────────────────────────────────

_WILDCARD_SERVICES: frozenset[str] = frozenset({"any", "all"})


def _is_wildcard(token: str) -> bool:
    return token.lower() in _WILDCARD_SERVICES


def _service_aliases(token: str) -> list[str]:
    aliases: list[str] = [token]
    m = re.fullmatch(r"(?:tcp|udp|icmp)/(\d+)", token, re.IGNORECASE)
    port_str = m.group(1) if m else (token if token.isdigit() else None)
    if port_str is not None:
        port = int(port_str)
        if m and str(port) not in aliases:
            aliases.append(str(port))
        for name in _PORT_TO_NAMES.get(port, []):
            if name not in aliases:
                aliases.append(name)
    return aliases


def parse_service_tokens(raw: str | None) -> list[str]:
    if not raw:
        return []
    tokens = [t.strip() for t in re.split(r"[\s,]+", raw.strip()) if t.strip()]
    return ["any" if _is_wildcard(t) else t for t in tokens]


def normalize_service_list(services: list[str]) -> list[str]:
    """Normalize a stored services list, canonicalising Any/All → 'any'."""
    return ["any" if _is_wildcard(s) else s for s in services]


# ── IP / zone resolution ──────────────────────────────────────────────────────


def parse_endpoint(raw: str):
    raw = raw.strip()
    if "/" in raw:
        host, mask = raw.split("/", 1)
        if "." in mask:
            try:
                prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                raw = f"{host}/{prefix_len}"
            except ValueError:
                pass
        return ipaddress.ip_network(raw, strict=False)
    return ipaddress.ip_address(raw)


def _overlaps(query, zone_net) -> bool:
    if isinstance(query, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return query in zone_net
    return query.overlaps(zone_net)


def zones_for_endpoint(raw: str, zones: dict) -> list[str]:
    """Return all zone names whose subnets overlap with the given IP/CIDR (most-specific first)."""
    endpoint = parse_endpoint(raw)
    matches: list[tuple[int, str]] = []
    for name, zone in zones.items():
        for entry in zone.get("subnets", []):
            try:
                network = ipaddress.ip_network(entry["subnet"], strict=False)
            except ValueError:
                continue
            if _overlaps(endpoint, network):
                matches.append((network.prefixlen, name))

    if not matches:
        if isinstance(endpoint, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            is_public = endpoint.is_global and not endpoint.is_private
        else:
            is_public = not endpoint.is_private
        if is_public:
            return ["Internet"]
        return []

    matches.sort(key=lambda x: x[0], reverse=True)
    seen: set[str] = set()
    result: list[str] = []
    for _, name in matches:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


# ── Zone hierarchy ────────────────────────────────────────────────────────────


def ancestor_zones(zone_name: str, zones: dict) -> list[str]:
    result: list[str] = []
    visited: set[str] = set()
    queue = [zone_name]
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        result.append(current)
        queue.extend(zones.get(current, {}).get("parents", []))
    return result


# ── Policy matching ───────────────────────────────────────────────────────────


def find_matching_policies(
    src_zones: list[str],
    dst_zones: list[str],
    zones: dict,
    policies: list[dict],
) -> list[dict]:
    src_candidates: list[str] = []
    dst_candidates: list[str] = []

    for z in src_zones:
        for ancestor in ancestor_zones(z, zones):
            if ancestor not in src_candidates:
                src_candidates.append(ancestor)

    for z in dst_zones:
        for ancestor in ancestor_zones(z, zones):
            if ancestor not in dst_candidates:
                dst_candidates.append(ancestor)

    matched: list[dict] = []
    seen: set[tuple] = set()
    for policy in policies:
        for src_name in src_candidates:
            if policy["from_zone"] != src_name:
                continue
            for dst_name in dst_candidates:
                if policy["to_zone"] != dst_name:
                    continue
                key = (policy["policy_set"], src_name, dst_name, policy["access_type"])
                if key in seen:
                    continue
                seen.add(key)
                matched.append(
                    {
                        **policy,
                        "matched_from_zone": src_name,
                        "matched_to_zone": dst_name,
                    }
                )

    return matched


# ── Verdict ───────────────────────────────────────────────────────────────────


def evaluate(
    policies: list[dict],
    services: list[str],
) -> tuple[str, list[dict]]:
    """Return (verdict, governing_rules). Verdict: 'ALLOWED', 'BLOCKED', or 'UNKNOWN'."""
    if not policies:
        return "UNKNOWN", []

    for p in policies:
        if p["access_type"] == "block all":
            return "BLOCKED", [p]

    allow_only_policies = [p for p in policies if p["access_type"] == "allow only"]

    if services:
        alias_sets = [_service_aliases(t) for t in services]
        for p in policies:
            if p["access_type"] == "block only":
                policy_svcs = p.get("services", [])
                if any(_is_wildcard(s) for s in policy_svcs):
                    return "BLOCKED", [p]
                rn = [s.lower() for s in policy_svcs]
                if any(
                    alias.lower() in rn for aliases in alias_sets for alias in aliases
                ):
                    return "BLOCKED", [p]

        for p in policies:
            if p["access_type"] == "allow only":
                policy_svcs = p.get("services", [])
                if any(_is_wildcard(s) for s in policy_svcs):
                    return "ALLOWED", [p]
                rn = [s.lower() for s in policy_svcs]
                if any(
                    alias.lower() in rn for aliases in alias_sets for alias in aliases
                ):
                    return "ALLOWED", [p]

    for p in policies:
        if p["access_type"] == "allow all":
            return "ALLOWED", [p]

    if services and allow_only_policies:
        return "BLOCKED", allow_only_policies

    return "ALLOWED", policies


# ── High-level query (used by routes and rule_review) ─────────────────────────


def run_query(
    src_list: list[str],
    dst_list: list[str],
    service: str | None,
    verbose: bool = False,
) -> list[dict]:
    """Evaluate all src×dst combinations and return structured results."""
    db = load_db()
    zones = db["zones"]
    policies = db["policies"]

    src_zone_map: dict[str, list[str]] = {
        s: zones_for_endpoint(s, zones) for s in src_list
    }
    dst_zone_map: dict[str, list[str]] = {
        d: zones_for_endpoint(d, zones) for d in dst_list
    }
    svc_tokens = parse_service_tokens(service)

    results = []
    for src in src_list:
        for dst in dst_list:
            src_zones = src_zone_map[src]
            dst_zones = dst_zone_map[dst]
            all_matched = find_matching_policies(src_zones, dst_zones, zones, policies)
            verdict, governing = evaluate(all_matched, svc_tokens)
            results.append(
                {
                    "src": src,
                    "dst": dst,
                    "service": ", ".join(svc_tokens),
                    "verdict": verdict,
                    "src_zones": src_zones,
                    "dst_zones": dst_zones,
                    "governing": governing,
                    "all_policies": all_matched if verbose else [],
                }
            )
    return results


def query_single(src: str, dst: str, service: str) -> dict:
    """Single-flow query used by rule_review integration."""
    results = run_query([src], [dst], service or None, verbose=True)
    return results[0] if results else {}


# ── Validation ────────────────────────────────────────────────────────────────


def validate_db(db: dict) -> dict:
    """Return a structured validation report dict."""
    errors: list[str] = []
    warnings: list[str] = []
    zones = db.get("zones", {})
    policies = db.get("policies", [])

    if not isinstance(zones, dict):
        errors.append("'zones' must be a dict")
    if not isinstance(policies, list):
        errors.append("'policies' must be a list")

    for name, zone in zones.items():
        for entry in zone.get("subnets", []):
            try:
                ipaddress.ip_network(entry.get("subnet", ""), strict=False)
            except ValueError:
                errors.append(f"Zone '{name}': invalid subnet '{entry.get('subnet')}'")
        for child in zone.get("children", []):
            if child not in zones:
                warnings.append(f"Zone '{name}': child '{child}' not in zones")
        for parent in zone.get("parents", []):
            if parent not in zones:
                warnings.append(f"Zone '{name}': parent '{parent}' not in zones")

    for i, p in enumerate(policies):
        at = p.get("access_type", "")
        if at not in VALID_ACCESS_TYPES:
            errors.append(f"Policy #{i}: invalid access_type '{at}'")
        if p.get("severity", "") not in VALID_SEVERITIES:
            warnings.append(f"Policy #{i}: unexpected severity '{p.get('severity')}'")
        for zf in ("from_zone", "to_zone"):
            zn = p.get(zf, "")
            if zn and zn not in zones:
                warnings.append(f"Policy #{i}: {zf} '{zn}' not in zones")
        if at in ("block only", "allow only") and not p.get("services"):
            warnings.append(f"Policy #{i}: '{at}' has empty services list")

    total_subnets = sum(len(z.get("subnets", [])) for z in zones.values())
    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "zone_count": len(zones),
        "policy_count": len(policies),
        "subnet_count": total_subnets,
    }


# ── Zone mutations ────────────────────────────────────────────────────────────


def zone_add(
    db: dict,
    name: str,
    domain: str = "Default",
    description: str = "",
    is_shared: bool = False,
) -> str:
    if name in db["zones"]:
        raise ValueError(f"Zone '{name}' already exists.")
    db["zones"][name] = {
        "domain": domain,
        "is_shared": is_shared,
        "description": description,
        "subnets": [],
        "children": [],
        "parents": [],
    }
    save_db(db)
    return f"Zone '{name}' added."


def zone_remove(db: dict, name: str) -> str:
    if name not in db["zones"]:
        raise KeyError(f"Zone '{name}' not found.")
    for z in db["zones"].values():
        z.get("children", []).remove(name) if name in z.get("children", []) else None
        z.get("parents", []).remove(name) if name in z.get("parents", []) else None
    del db["zones"][name]
    save_db(db)
    return f"Zone '{name}' removed."


def zone_modify(db: dict, name: str, field: str, value: str) -> str:
    if name not in db["zones"]:
        raise KeyError(f"Zone '{name}' not found.")
    if field not in ZONE_MUTABLE_FIELDS:
        raise ValueError(f"Field '{field}' is not editable.")
    if field == "is_shared":
        coerced = value.lower() == "true"
    elif field == "trust_level":
        if value == "":
            coerced = None
        else:
            try:
                coerced = int(value)
            except ValueError:
                raise ValueError("trust_level must be an integer 0–100.")
            if not (0 <= coerced <= 100):
                raise ValueError("trust_level must be between 0 and 100.")
    else:
        coerced = value
    db["zones"][name][field] = coerced
    save_db(db)
    return f"Zone '{name}' — {field} updated."


def subnet_add(db: dict, zone_name: str, subnet: str, description: str = "") -> str:
    if zone_name not in db["zones"]:
        raise KeyError(f"Zone '{zone_name}' not found.")
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        raise ValueError(f"'{subnet}' is not a valid subnet.")
    if any(e["subnet"] == subnet for e in db["zones"][zone_name]["subnets"]):
        raise ValueError(f"Subnet '{subnet}' already exists in '{zone_name}'.")
    db["zones"][zone_name]["subnets"].append(
        {"subnet": subnet, "description": description}
    )
    save_db(db)
    return f"Subnet '{subnet}' added to '{zone_name}'."


def subnet_remove(db: dict, zone_name: str, subnet: str) -> str:
    if zone_name not in db["zones"]:
        raise KeyError(f"Zone '{zone_name}' not found.")
    before = len(db["zones"][zone_name]["subnets"])
    db["zones"][zone_name]["subnets"] = [
        e for e in db["zones"][zone_name]["subnets"] if e["subnet"] != subnet
    ]
    if len(db["zones"][zone_name]["subnets"]) == before:
        raise ValueError(f"Subnet '{subnet}' not found in '{zone_name}'.")
    save_db(db)
    return f"Subnet '{subnet}' removed from '{zone_name}'."


# ── Policy mutations ──────────────────────────────────────────────────────────


def policy_add(
    db: dict,
    policy_set: str,
    from_zone: str,
    to_zone: str,
    access_type: str,
    severity: str = "high",
    services: list[str] | None = None,
    description: str = "",
) -> str:
    if access_type not in VALID_ACCESS_TYPES:
        raise ValueError(f"Invalid access_type '{access_type}'.")
    services = normalize_service_list(services or [])
    if access_type in ("block only", "allow only") and not services:
        raise ValueError(f"'{access_type}' requires at least one service.")
    db["policies"].append(
        {
            "policy_set": policy_set,
            "from_domain": "All Domains",
            "from_zone": from_zone,
            "to_domain": "All Domains",
            "to_zone": to_zone,
            "severity": severity,
            "access_type": access_type,
            "services": services,
            "rule_properties": "",
            "flows": "",
            "description": description,
        }
    )
    save_db(db)
    return f"Policy added: {from_zone} → {to_zone} ({access_type})."


def policy_remove(db: dict, index: int) -> str:
    if index < 0 or index >= len(db["policies"]):
        raise IndexError(f"Index {index} out of range.")
    removed = db["policies"].pop(index)
    save_db(db)
    return f"Removed policy #{index}: {removed.get('from_zone')} → {removed.get('to_zone')}."


def policy_modify(db: dict, index: int, field: str, value: str) -> str:
    if index < 0 or index >= len(db["policies"]):
        raise IndexError(f"Index {index} out of range.")
    if field not in POLICY_MUTABLE_FIELDS:
        raise ValueError(f"Field '{field}' is not editable.")
    coerced = (
        normalize_service_list([s.strip() for s in value.split(",") if s.strip()])
        if field == "services"
        else value
    )
    db["policies"][index][field] = coerced
    save_db(db)
    return f"Policy #{index}: {field} updated."


# ── Segmentation health report ────────────────────────────────────────────────

_TRUST_MISMATCH_THRESHOLD = 40
_OPEN_ACCESS_TYPES = {"allow all", "allow only"}


def compute_segmentation_report(db: dict) -> dict:
    """Compute a segmentation effectiveness report for the zone database.

    Returns:
        score            — float 0–100; higher = more segmented
        total_zones      — int
        total_pairs      — int; ordered zone pairs (A→B where A≠B)
        open_pair_count  — int; pairs with at least one allow-all policy
        open_pairs       — list of {from_zone, to_zone, policy_count}
        trust_mismatches — list of {from_zone, to_zone, from_trust, to_trust,
                           delta, policy_count}; only when both zones have
                           trust_level set and delta >= threshold
        has_trust_levels — bool; True if any zone has trust_level set
    """
    zones: dict = db.get("zones", {})
    policies: list = db.get("policies", [])

    zone_names = list(zones.keys())
    n = len(zone_names)
    total_pairs = n * (n - 1)

    # Index policies by (from_zone, to_zone)
    pair_policies: dict[tuple, list] = {}
    for p in policies:
        key = (p.get("from_zone"), p.get("to_zone"))
        if key[0] and key[1]:
            pair_policies.setdefault(key, []).append(p)

    # Open pairs: any pair with at least one allow-all policy
    open_pair_set: set[tuple] = set()
    for (fz, tz), pols in pair_policies.items():
        if (
            fz in zones
            and tz in zones
            and fz != tz
            and any(p.get("access_type") == "allow all" for p in pols)
        ):
            open_pair_set.add((fz, tz))

    open_pairs = [
        {
            "from_zone": fz,
            "to_zone": tz,
            "policy_count": sum(
                1
                for p in pair_policies.get((fz, tz), [])
                if p.get("access_type") == "allow all"
            ),
        }
        for fz, tz in sorted(open_pair_set)
    ]

    score = (
        max(0.0, round((1 - len(open_pair_set) / total_pairs) * 100, 1))
        if total_pairs > 0
        else 100.0
    )

    # Trust mismatches
    has_trust_levels = any(z.get("trust_level") is not None for z in zones.values())
    trust_mismatches = []
    for (fz, tz), pols in pair_policies.items():
        fz_data = zones.get(fz, {})
        tz_data = zones.get(tz, {})
        fz_trust = fz_data.get("trust_level")
        tz_trust = tz_data.get("trust_level")
        if fz_trust is None or tz_trust is None:
            continue
        delta = tz_trust - fz_trust
        if abs(delta) < _TRUST_MISMATCH_THRESHOLD:
            continue
        concerning = [p for p in pols if p.get("access_type") in _OPEN_ACCESS_TYPES]
        if not concerning:
            continue
        trust_mismatches.append(
            {
                "from_zone": fz,
                "to_zone": tz,
                "from_trust": fz_trust,
                "to_trust": tz_trust,
                "delta": delta,
                "policy_count": len(concerning),
            }
        )

    trust_mismatches.sort(key=lambda m: abs(m["delta"]), reverse=True)

    return {
        "score": score,
        "total_zones": n,
        "total_pairs": total_pairs,
        "open_pair_count": len(open_pair_set),
        "open_pairs": open_pairs,
        "trust_mismatches": trust_mismatches,
        "has_trust_levels": has_trust_levels,
    }
