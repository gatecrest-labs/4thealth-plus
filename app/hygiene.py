"""Rule hygiene checks — all logic is purely local; no writes to FortiManager or devices.

Each check function receives the full policy list and returns a list of finding dicts:
  {
    "policy_id":   str,
    "policy_name": str,
    "seq":         int,    # sequence number / index (1-based)
    "check":       str,    # check key
    "detail":      str,    # human-readable explanation
  }

CHECKS maps key -> display name.  Order here controls the dropdown order in the UI.

run_checks() additionally filters any rule whose comment contains "exempt"
(case-insensitive, see _is_exempt()) out of the returned findings -- a
whitelist mechanism for reviewed-and-accepted rules, applied after all
checks run so shadow/redundant analysis for other rules stays correct.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime

log = logging.getLogger(__name__)


# ── Check registry ────────────────────────────────────────────────────────────

CHECKS: dict[str, str] = {
    "unnamed": "Unnamed Rules (no comment/name)",
    "unlogged": "Unlogged Rules (logging disabled)",
    "shadow": "Shadow Rules (hidden by broader rule above)",
    "disabled": "Disabled / Inactive Rules",
    "expired": "Expired Rules (past schedule end-date)",
    "unhit": "Unused / Un-Hit Rules (zero hit count)",
    "missing_security_profile": "Missing Security Profiles (accept rules without UTM)",
    "redundant": "Redundant Rules (duplicate scope of an earlier rule)",
    "over_permissive": "Over-Permissive Rules (accept rules with 2+ unrestricted dimensions)",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

# FMG returns many policy fields as integers rather than strings.
_STATUS_MAP = {0: "disable", 1: "enable"}
_ACTION_MAP = {0: "deny", 1: "accept", 2: "ipsec"}
_LOGTRAFFIC_MAP = {0: "disable", 1: "utm", 2: "all"}


def _fstr(val, default: str = "") -> str:
    """Safely convert any FMG field value to a lower-cased string."""
    if val is None:
        return default.lower()
    if isinstance(val, int):
        return str(val)
    return str(val).lower()


def _status(p: dict) -> str:
    """Return 'enable' or 'disable' regardless of whether FMG sent int or str."""
    v = p.get("status")
    if isinstance(v, int):
        return _STATUS_MAP.get(v, "enable")
    return (v or "enable").lower()


def _action(p: dict) -> str:
    """Return canonical action string regardless of whether FMG sent int or str."""
    v = p.get("action")
    if isinstance(v, int):
        return _ACTION_MAP.get(v, "accept")
    return (v or "accept").lower()


def _logtraffic(p: dict) -> str:
    """Return canonical logtraffic string regardless of whether FMG sent int or str."""
    v = p.get("logtraffic")
    if isinstance(v, int):
        return _LOGTRAFFIC_MAP.get(v, "disable")
    return (v or "").lower()


def _name(p: dict) -> str:
    return str(p.get("name") or p.get("policyid") or p.get("policyid", ""))


def _is_exempt(p: dict) -> bool:
    """Whitelist mechanism: a rule is exempted from every hygiene check when
    its comment field contains "exempt" (case-insensitive substring match --
    this deliberately also matches the "[HygieneFix EXEMPT YYYY-MM-DD]" tag
    that Hygiene Fix's over_permissive "Exempt (keep enabled)" option writes,
    closing the loop so a reviewed-and-accepted rule stops being re-flagged
    on the next run)."""
    comment = str(p.get("comments") or p.get("comment") or "")
    return "exempt" in comment.lower()


def _seq(p: dict, idx: int) -> int:
    return p.get("policyid", idx + 1)


def _addr_list(val) -> list[str]:
    """Normalize address fields: may be list of strings or list of dicts."""
    if not val:
        return []
    if isinstance(val, str):
        return [val]
    result = []
    for item in val:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            result.append(item.get("name", str(item)))
    return result


def _is_any(val) -> bool:
    names = _addr_list(val)
    return any(n.lower() == "all" or n.lower() == "any" for n in names)


def _svc_is_any(val) -> bool:
    names = _addr_list(val)
    return any(n.lower() in ("all", "any") for n in names)


def _is_policy_block(p: dict) -> bool:
    """Return True if this entry is a global policy-block, not a regular rule.

    FMG marks these with a non-empty '_policy_block' field (e.g. 'ThreatFeeds-VDOMs').
    They have empty src/dst/service and should not be evaluated by any hygiene check.
    """
    val = p.get("_policy_block")
    return bool(val and str(val).strip())


def _identity_set(p: dict) -> frozenset:
    """Return a frozenset of identity-match strings from fsso-groups, groups, users."""
    result: set[str] = set()
    for field in ("fsso-groups", "groups", "users"):
        val = p.get(field) or []
        if isinstance(val, str):
            result.add(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    result.add(item)
                elif isinstance(item, dict):
                    result.add(item.get("name", str(item)))
    return frozenset(result)


def _rule_summary(p: dict) -> dict:
    """Return a compact summary of a policy for use in shadow-finding detail payloads."""
    return {
        "id": str(p.get("policyid", "?")),
        "name": str(p.get("name") or ""),
        "status": _status(p),
        "action": _action(p),
        "srcaddr": _addr_list(p.get("srcaddr") or p.get("src_addr")),
        "dstaddr": _addr_list(p.get("dstaddr") or p.get("dst_addr")),
        "service": _addr_list(p.get("service") or p.get("services")),
        "fsso_groups": _addr_list(p.get("fsso-groups")),
        "comment": str(p.get("comments") or p.get("comment") or ""),
    }


def _covers(
    a_names: set[str],
    b_names: set[str],
    resolver: dict[str, frozenset | None] | None = None,
) -> bool:
    """Return True if address/service set A fully covers set B.

    Pass 1 — wildcards: True if A contains 'any' or 'all'.
    Pass 2 — exact name subset: True if every name in B is also in A.
    Pass 3 — IP containment (requires resolver): expand each name to a
    frozenset of ip_network objects and check that every network in B is
    contained within at least one network in A.  Names that resolve to None
    (FQDN, geography, parse failure) cause this pass to be skipped for safety.
    """
    if not b_names:
        return True
    if any(n.lower() in ("any", "all") for n in a_names):
        return True
    if b_names <= a_names:
        return True
    if resolver is None:
        return False

    # IP containment pass — resolve every name to a set of ip_network objects.
    try:
        a_nets: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for name in a_names:
            resolved = resolver.get(name)
            if resolved is None:
                return False  # opaque (FQDN/geo) — cannot guarantee containment
            a_nets.update(resolved)

        b_nets: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for name in b_names:
            resolved = resolver.get(name)
            if resolved is None:
                return False
            b_nets.update(resolved)

        if not a_nets or not b_nets:
            return False

        # Dispatch on value type: tuples → port-range containment; ip_network → subnet containment.
        sample = next(iter(a_nets))
        if isinstance(sample, tuple):
            # Service containment: (proto, low, high) in B must fit inside some A range.
            return all(
                any(
                    isinstance(a_t, tuple)
                    and a_t[0] == b_t[0]  # same protocol
                    and a_t[1] <= b_t[1]  # A low <= B low
                    and b_t[2] <= a_t[2]  # B high <= A high
                    for a_t in a_nets
                )
                for b_t in b_nets
            )
        return all(
            any(
                b_net.version == a_net.version and b_net.subnet_of(a_net)
                for a_net in a_nets
            )
            for b_net in b_nets
        )
    except Exception as exc:
        log.debug("_covers IP containment check failed: %s", exc)
        return False


# ── Individual check functions ────────────────────────────────────────────────


def check_unnamed(policies: list[dict]) -> list[dict]:
    """Rules that lack a name, a comment/description, or both."""
    findings = []
    for idx, p in enumerate(policies):
        if _is_policy_block(p):
            continue
        name = str(p.get("name") or "").strip()
        comment = str(p.get("comments") or p.get("comment") or "").strip()
        pid = p.get("policyid", idx + 1)
        if not name and not comment:
            findings.append(
                {
                    "policy_id": str(pid),
                    "policy_name": f"Policy #{pid}",
                    "seq": _seq(p, idx),
                    "check": "unnamed",
                    "detail": "Rule has no name and no comment.",
                }
            )
        elif not name:
            findings.append(
                {
                    "policy_id": str(pid),
                    "policy_name": f"Policy #{pid}",
                    "seq": _seq(p, idx),
                    "check": "unnamed",
                    "detail": f"Rule has no name (only a comment: '{comment[:80]}').",
                }
            )
        elif not comment:
            findings.append(
                {
                    "policy_id": str(pid),
                    "policy_name": name,
                    "seq": _seq(p, idx),
                    "check": "unnamed",
                    "detail": "Rule has a name but no comment/description.",
                }
            )
    return findings


def check_unlogged(policies: list[dict]) -> list[dict]:
    """Rules where logtraffic is 'disable' or missing."""
    findings = []
    for idx, p in enumerate(policies):
        if _is_policy_block(p):
            continue
        log = _logtraffic(p)
        # FortiOS values: "all", "utm", "disable" (or int 0/1/2)
        if log in ("disable", "disabled", "") or not log:
            findings.append(
                {
                    "policy_id": str(p.get("policyid", idx + 1)),
                    "policy_name": _name(p),
                    "seq": _seq(p, idx),
                    "check": "unlogged",
                    "detail": f"logtraffic = '{log or 'not set'}' — no traffic logging.",
                }
            )
    return findings


def check_shadow(
    policies: list[dict],
    addr_resolver: dict[str, frozenset | None] | None = None,
    svc_resolver: dict[str, frozenset | None] | None = None,
) -> list[dict]:
    """Flag rules that will never be hit because an earlier rule already matches
    every connection that could reach them.

    Rule B (later) is fully shadowed by rule A (earlier) when all three traffic
    dimensions are covered:
      - A's source addresses cover all of B's source addresses
      - A's destination addresses cover all of B's destination addresses
      - A's services cover all of B's services

    Coverage is checked in three passes per dimension:
      1. Wildcard: A uses 'any'/'all'
      2. Exact name subset: every name in B is also in A
      3. IP containment (when addr_resolver/svc_resolver provided): every
         network in B's resolved IP set is contained within A's resolved set.
         Names resolving to None (FQDN, geography) block this pass safely.

    Action is intentionally NOT required to match — when A fully covers B's
    traffic scope, B is unreachable regardless of action.  A difference in
    action is called out in the detail message as it often signals a policy
    ordering mistake.

    Only enabled rules are evaluated. Each shadowed rule is reported once,
    against the first shadowing rule found above it.
    """
    findings = []
    enabled = [
        p for p in policies if _status(p) != "disable" and not _is_policy_block(p)
    ]

    for j, b in enumerate(enabled):
        b_src = set(_addr_list(b.get("srcaddr") or b.get("src_addr")))
        b_dst = set(_addr_list(b.get("dstaddr") or b.get("dst_addr")))
        b_svc = set(_addr_list(b.get("service") or b.get("services")))
        b_action = _action(b)
        b_identity = _identity_set(b)

        for a in enabled[:j]:
            a_src = set(_addr_list(a.get("srcaddr") or a.get("src_addr")))
            a_dst = set(_addr_list(a.get("dstaddr") or a.get("dst_addr")))
            a_svc = set(_addr_list(a.get("service") or a.get("services")))
            a_action = _action(a)
            a_identity = _identity_set(a)

            if not (
                _covers(a_src, b_src, resolver=addr_resolver)
                and _covers(a_dst, b_dst, resolver=addr_resolver)
                and _covers(a_svc, b_svc, resolver=svc_resolver)
            ):
                continue

            # Identity mismatch: if either rule restricts to specific AD/FSSO groups
            # and they don't match, the rules are NOT functionally equivalent.
            if a_identity != b_identity:
                continue

            action_note = (
                f" Note: actions differ (shadowing={a_action}, shadowed={b_action}) — possible policy ordering mistake."
                if a_action != b_action
                else ""
            )
            findings.append(
                {
                    "policy_id": str(b.get("policyid", j + 1)),
                    "policy_name": _name(b),
                    "seq": _seq(b, j),
                    "check": "shadow",
                    "detail": (
                        f"Fully shadowed by rule '{_name(a)}' (id {a.get('policyid', '?')}) "
                        f"which appears earlier and covers the same src/dst/service scope.{action_note}"
                    ),
                    "shadow_rule": _rule_summary(b),
                    "shadowing_rule": _rule_summary(a),
                }
            )
            break  # report only the first shadowing rule
    return findings


def check_redundant_rules(
    policies: list[dict],
    addr_resolver: dict[str, frozenset | None] | None = None,
    svc_resolver: dict[str, frozenset | None] | None = None,
) -> list[dict]:
    """Flag enabled rules whose traffic scope is mutually equivalent to an earlier rule.

    Unlike shadowing (where A covers B one-way), redundancy requires both
    _covers(A, B) AND _covers(B, A) — i.e., the rules match exactly the same
    traffic.  Action must also match; a permit and a deny covering the same
    scope serve different purposes and are not redundant.

    Each later rule is reported at most once, against the first equivalent
    earlier rule found above it.
    """
    findings = []
    enabled = [
        p for p in policies if _status(p) != "disable" and not _is_policy_block(p)
    ]

    for j, b in enumerate(enabled):
        b_src = set(_addr_list(b.get("srcaddr") or b.get("src_addr")))
        b_dst = set(_addr_list(b.get("dstaddr") or b.get("dst_addr")))
        b_svc = set(_addr_list(b.get("service") or b.get("services")))
        b_action = _action(b)
        b_identity = _identity_set(b)

        for a in enabled[:j]:
            if _action(a) != b_action:
                continue
            if _identity_set(a) != b_identity:
                continue
            a_src = set(_addr_list(a.get("srcaddr") or a.get("src_addr")))
            a_dst = set(_addr_list(a.get("dstaddr") or a.get("dst_addr")))
            a_svc = set(_addr_list(a.get("service") or a.get("services")))

            if not (
                _covers(a_src, b_src, resolver=addr_resolver)
                and _covers(b_src, a_src, resolver=addr_resolver)
                and _covers(a_dst, b_dst, resolver=addr_resolver)
                and _covers(b_dst, a_dst, resolver=addr_resolver)
                and _covers(a_svc, b_svc, resolver=svc_resolver)
                and _covers(b_svc, a_svc, resolver=svc_resolver)
            ):
                continue

            findings.append(
                {
                    "policy_id": str(b.get("policyid", j + 1)),
                    "policy_name": _name(b),
                    "seq": _seq(b, j),
                    "check": "redundant",
                    "detail": (
                        f"Matches the same traffic scope as rule '{_name(a)}' "
                        f"(id {a.get('policyid', '?')}) which appears earlier"
                        f" — consider consolidating."
                    ),
                    "redundant_rule": _rule_summary(b),
                    "duplicate_of": _rule_summary(a),
                }
            )
            break  # report only the first equivalent rule

    return findings


def check_security_profile_gap(policies: list[dict]) -> list[dict]:
    """Flag accept rules with no UTM security profiles attached.

    Flags if: action=accept AND (utm-status=disable OR all profile fields are empty).
    Skips deny/ipsec actions and _policy_block entries.
    """
    _PROFILE_FIELDS = (
        "ips-sensor",
        "av-profile",
        "webfilter-profile",
        "dnsfilter-profile",
        "application-list",
    )
    findings = []
    for idx, p in enumerate(policies):
        if _is_policy_block(p):
            continue
        if _action(p) != "accept":
            continue
        utm = str(p.get("utm-status") or p.get("utm_status") or "disable").lower()
        if utm != "enable":
            findings.append(
                {
                    "policy_id": str(p.get("policyid", idx + 1)),
                    "policy_name": _name(p),
                    "seq": _seq(p, idx),
                    "check": "missing_security_profile",
                    "detail": "Accept rule has utm-status disabled — no security profiles active",
                }
            )
            continue
        has_profile = any(str(p.get(f) or "").strip() for f in _PROFILE_FIELDS)
        if not has_profile:
            findings.append(
                {
                    "policy_id": str(p.get("policyid", idx + 1)),
                    "policy_name": _name(p),
                    "seq": _seq(p, idx),
                    "check": "missing_security_profile",
                    "detail": (
                        "UTM enabled but no security profiles attached "
                        "(IPS, AV, webfilter, dnsfilter, app-control all empty)"
                    ),
                }
            )
    return findings


def check_disabled(policies: list[dict]) -> list[dict]:
    """Rules where status == 'disable'."""
    findings = []
    for idx, p in enumerate(policies):
        if _is_policy_block(p):
            continue
        if _status(p) == "disable":
            findings.append(
                {
                    "policy_id": str(p.get("policyid", idx + 1)),
                    "policy_name": _name(p),
                    "seq": _seq(p, idx),
                    "check": "disabled",
                    "detail": f"Rule status = '{_status(p)}'.",
                }
            )
    return findings


def check_expired(policies: list[dict]) -> list[dict]:
    """Rules whose schedule has an end date in the past.

    FortiOS stores schedule as a string name reference; we can only inspect if
    the policy carries inline schedule-stop fields (schedule-timeout, expiry,
    or a 'schedule' field that looks like an end-date).  If the policy references
    a named schedule object we report it as 'has a time-based schedule — verify
    expiry' since we don't pull schedule objects here.
    """
    findings = []
    now = datetime.now(UTC)

    for idx, p in enumerate(policies):
        if _is_policy_block(p):
            continue
        sched = p.get("schedule") or p.get("schedule_timeout") or ""
        if isinstance(sched, list) and sched:
            sched = (
                sched[0]
                if isinstance(sched[0], str)
                else (sched[0].get("name", "") if isinstance(sched[0], dict) else "")
            )

        sched_str = str(sched).strip().lower()
        if not sched_str or sched_str in ("always", "", "none"):
            continue

        # Try to parse as a date (FMG may return "YYYY/MM/DD HH:MM:SS" or "YYYY-MM-DD")
        parsed = None
        for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(sched_str, fmt).replace(tzinfo=UTC)
                break
            except ValueError:
                continue

        if parsed:
            if parsed < now:
                findings.append(
                    {
                        "policy_id": str(p.get("policyid", idx + 1)),
                        "policy_name": _name(p),
                        "seq": _seq(p, idx),
                        "check": "expired",
                        "detail": f"Schedule end-date '{sched_str}' is in the past.",
                    }
                )
        else:
            # Named schedule — flag for manual review
            findings.append(
                {
                    "policy_id": str(p.get("policyid", idx + 1)),
                    "policy_name": _name(p),
                    "seq": _seq(p, idx),
                    "check": "expired",
                    "detail": f"References time-based schedule '{sched}' — verify it has not expired.",
                }
            )
    return findings


def check_unhit(policies: list[dict]) -> list[dict]:
    """Rules with a hit count of zero.

    FMG stores hit counters with a leading underscore: _hitcount, _pkts, _bytes.
    Plain names (hitcount, hit_count, pkts) are also checked for compatibility.
    If no hit-count field is present the rule is skipped silently.
    """
    findings = []
    for idx, p in enumerate(policies):
        if _is_policy_block(p):
            continue
        # FMG uses underscore-prefixed names; also check plain names for safety
        hit = (
            p.get("_hitcount")
            if p.get("_hitcount") is not None
            else p.get("_pkts")
            if p.get("_pkts") is not None
            else p.get("hitcount")
            if p.get("hitcount") is not None
            else p.get("hit_count")
            if p.get("hit_count") is not None
            else p.get("pkts")
            if p.get("pkts") is not None
            else p.get("bytes")
        )
        if hit is None:
            continue
        try:
            if int(hit) == 0:
                findings.append(
                    {
                        "policy_id": str(p.get("policyid", idx + 1)),
                        "policy_name": _name(p),
                        "seq": _seq(p, idx),
                        "check": "unhit",
                        "detail": "Hit count is 0 — rule has never matched traffic.",
                    }
                )
        except (TypeError, ValueError):
            pass
    return findings


def check_over_permissive(policies: list[dict]) -> list[dict]:
    """Flag enabled accept rules where 2 or more of the 3 traffic dimensions
    (source, destination, service) are set to ANY/ALL.

    Severity:
      critical — all 3 dimensions are unrestricted
      high     — exactly 2 dimensions are unrestricted
    """
    findings = []
    for idx, p in enumerate(policies):
        if _is_policy_block(p):
            continue
        if _status(p) != "enable":
            continue
        if _action(p) != "accept":
            continue

        src_any = _is_any(p.get("srcaddr") or p.get("src_addr"))
        dst_any = _is_any(p.get("dstaddr") or p.get("dst_addr"))
        svc_any = _svc_is_any(p.get("service") or p.get("services"))

        open_dims = [
            label
            for label, flag in (
                ("source", src_any),
                ("destination", dst_any),
                ("service", svc_any),
            )
            if flag
        ]
        count = len(open_dims)

        if count < 2:
            continue

        if count == 3:
            severity = "critical"
            detail = (
                "Fully open — source, destination, and service are all unrestricted"
            )
        else:
            severity = "high"
            detail = f"Over-permissive — {' and '.join(open_dims)} are unrestricted"

        findings.append(
            {
                "policy_id": str(p.get("policyid", idx + 1)),
                "policy_name": _name(p),
                "seq": _seq(p, idx),
                "check": "over_permissive",
                "severity": severity,
                "detail": detail,
            }
        )
    return findings


# ── Dispatcher ────────────────────────────────────────────────────────────────

_CHECK_FNS = {
    "unnamed": check_unnamed,
    "unlogged": check_unlogged,
    "shadow": check_shadow,
    "disabled": check_disabled,
    "expired": check_expired,
    "unhit": check_unhit,
    "missing_security_profile": check_security_profile_gap,
    "redundant": check_redundant_rules,
    "over_permissive": check_over_permissive,
}


def run_checks(
    policies: list[dict],
    checks: list[str],
    pkg_settings: dict | None = None,
    addr_resolver: dict[str, frozenset | None] | None = None,
    svc_resolver: dict[str, frozenset | None] | None = None,
) -> list[dict]:
    """Run the requested checks against the policy list.  Returns combined findings.

    Exempted rules (see `_is_exempt`) are filtered out of the returned
    findings, not the input policy list -- shadow/redundant analysis needs
    every rule present to correctly determine shadowing relationships among
    the *other*, non-exempted rules.
    """
    results = []
    for key in checks:
        fn = _CHECK_FNS.get(key)
        if not fn:
            continue
        if key == "shadow":
            results.extend(
                check_shadow(
                    policies, addr_resolver=addr_resolver, svc_resolver=svc_resolver
                )
            )
        elif key == "redundant":
            results.extend(
                check_redundant_rules(
                    policies, addr_resolver=addr_resolver, svc_resolver=svc_resolver
                )
            )
        else:
            results.extend(fn(policies))

    exempt_ids = {
        str(p.get("policyid", idx + 1))
        for idx, p in enumerate(policies)
        if _is_exempt(p)
    }
    if exempt_ids:
        results = [r for r in results if r.get("policy_id") not in exempt_ids]
    return results


# ── Unused object detection ───────────────────────────────────────────────────

_BUILTIN_EXCLUSIONS: frozenset[str] = frozenset(
    {
        "all",
        "ALL",
        "any",
        "ANY",
        "none",
        "NONE",
    }
)
_FORTIGUARD_PREFIXES: tuple[str, ...] = ("g-", "G-", "isdb-", "ISDB-")


def _is_builtin_obj(name: str) -> bool:
    return name in _BUILTIN_EXCLUSIONS or any(
        name.startswith(p) for p in _FORTIGUARD_PREFIXES
    )


def _collect_policy_refs(policies: list[dict]) -> tuple[set[str], set[str]]:
    addr_refs: set[str] = set()
    svc_refs: set[str] = set()
    for p in policies:
        if _is_policy_block(p):
            continue
        for field in ("srcaddr", "dstaddr", "src_addr", "dst_addr"):
            for item in _addr_list(p.get(field) or []):
                addr_refs.add(item)
        for item in _addr_list(p.get("service") or p.get("services") or []):
            svc_refs.add(item)
    return addr_refs, svc_refs


def _expand_group_members(groups: list[dict], direct_refs: set[str]) -> set[str]:
    """BFS-expand group members reachable from any directly-referenced group name."""
    group_map: dict[str, list[str]] = {}
    for g in groups:
        if not isinstance(g, dict):
            continue
        gname = g.get("name", "")
        members: list[str] = []
        for m in g.get("member") or []:
            if isinstance(m, str):
                members.append(m)
            elif isinstance(m, dict):
                n = m.get("name", "")
                if n:
                    members.append(n)
        group_map[gname] = members

    visited: set[str] = set()
    queue = [n for n in direct_refs if n in group_map]
    while queue:
        name = queue.pop()
        if name in visited:
            continue
        visited.add(name)
        for member in group_map.get(name, []):
            visited.add(member)
            if member in group_map:
                queue.append(member)
    return visited


def find_unused_objects(
    policies: list[dict],
    addresses: list[dict],
    addr_groups: list[dict],
    services: list[dict],
    svc_groups: list[dict],
) -> dict:
    """Return address and service objects not referenced by any policy.

    Objects used only inside a group that IS referenced by a policy are
    considered used (via group membership expansion).

    Returns:
        {
            "unused_addresses": [{"name": str, "type": str}, ...],
            "unused_services":  [{"name": str, "type": str}, ...],
        }
    """
    addr_refs, svc_refs = _collect_policy_refs(policies)
    addr_member_refs = _expand_group_members(addr_groups, addr_refs)
    svc_member_refs = _expand_group_members(svc_groups, svc_refs)
    all_addr_refs = addr_refs | addr_member_refs
    all_svc_refs = svc_refs | svc_member_refs

    unused_addresses: list[dict] = []
    for obj in addresses:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name", "")
        if not name or _is_builtin_obj(name) or name in all_addr_refs:
            continue
        unused_addresses.append(
            {"name": name, "type": str(obj.get("type") or "ipmask")}
        )
    for obj in addr_groups:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name", "")
        if not name or _is_builtin_obj(name) or name in all_addr_refs:
            continue
        unused_addresses.append({"name": name, "type": "group"})

    unused_services: list[dict] = []
    for obj in services:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name", "")
        if not name or _is_builtin_obj(name) or name in all_svc_refs:
            continue
        unused_services.append(
            {"name": name, "type": str(obj.get("protocol") or "tcp/udp")}
        )
    for obj in svc_groups:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name", "")
        if not name or _is_builtin_obj(name) or name in all_svc_refs:
            continue
        unused_services.append({"name": name, "type": "group"})

    return {
        "unused_addresses": sorted(unused_addresses, key=lambda x: x["name"].lower()),
        "unused_services": sorted(unused_services, key=lambda x: x["name"].lower()),
    }
