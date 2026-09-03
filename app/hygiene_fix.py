"""Deterministic FortiOS CLI remediation generator for Rule Hygiene findings.

Given a completed Rule Hygiene run's findings (pasted or uploaded) and the
live policy package fetched fresh from FortiManager, computes one or more
concrete remediation options per finding -- CLI plus an updated comment.
This module never calls FortiManager or an LLM itself; it is a pure
function library, mirroring the compute/narrate split used throughout
app/planner/ and app/hygiene_ai.py.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime

from app.hygiene import _addr_list, _name

_TAG_RE = re.compile(r"\[HygieneFix(?: EXEMPT)? (\d{4}-\d{2}-\d{2})\]")
_MAX_COMMENT_LEN = 255
_MAX_NAME_LEN = 35


def _find_tag(comment: str) -> date | None:
    """Return the date embedded in a prior [HygieneFix ...] tag, or None."""
    match = _TAG_RE.search(comment or "")
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d").date()
    except ValueError:
        return None


def _append_tag(comment: str, today: date, exempt: bool = False) -> str:
    """Append a [HygieneFix YYYY-MM-DD] traceability tag to a comment.

    Truncates the *original* comment content (never the tag itself) so the
    result never exceeds FortiOS's 255-character comment field limit.
    """
    tag = f"[HygieneFix{' EXEMPT' if exempt else ''} {today.isoformat()}]"
    base = (comment or "").strip()
    if not base:
        return tag
    room = _MAX_COMMENT_LEN - len(tag) - 1  # -1 for the joining space
    if room < 0:
        room = 0
    if len(base) > room:
        base = base[:room].rstrip()
    return f"{base} {tag}" if base else tag


def _safe(s: str) -> str:
    """Escape a string for embedding in a double-quoted FortiGate CLI field."""
    return s.replace('"', "''").replace("\n", "").replace("\r", "")


def _comment_field(p: dict) -> str:
    return str(p.get("comments") or p.get("comment") or "")


def _policy_cli(policy_id: str, sets: list[str]) -> str:
    body = "\n".join(f"        {s}" for s in sets)
    return f"config firewall policy\n    edit {policy_id}\n{body}\n    next\nend"


def _fix_unlogged(finding: dict, live: dict, today: date) -> list[dict]:
    cli = _policy_cli(live.get("policyid"), ["set logtraffic all"])
    return [
        {
            "option_id": "enable_logging",
            "label": "Enable logging",
            "description": "Set logtraffic to 'all' so this rule's traffic is logged.",
            "cli": [cli],
            "new_comment": None,
        }
    ]


def _fix_unnamed(finding: dict, live: dict, today: date) -> list[dict]:
    src_names = [
        n for n in _addr_list(live.get("srcaddr") or live.get("src_addr"))
        if n.lower() not in ("any", "all")
    ]
    dst_names = [
        n for n in _addr_list(live.get("dstaddr") or live.get("dst_addr"))
        if n.lower() not in ("any", "all")
    ]
    if src_names and dst_names:
        new_name = f"Allow {src_names[0]} to {dst_names[0]}"[:_MAX_NAME_LEN]
    else:
        new_name = "Unknown -- Requires additional research"
    new_comment = _append_tag(_comment_field(live), today)
    cli = _policy_cli(
        live.get("policyid"),
        [f'set name "{_safe(new_name)}"', f'set comments "{_safe(new_comment)}"'],
    )
    return [
        {
            "option_id": "rename",
            "label": "Set name",
            "description": f'Suggested name: "{new_name}".',
            "cli": [cli],
            "new_comment": new_comment,
        }
    ]


def _fix_expired(finding: dict, live: dict, today: date) -> list[dict]:
    new_comment = _append_tag(_comment_field(live), today)
    cli = _policy_cli(
        live.get("policyid"),
        ["set status disable", f'set comments "{_safe(new_comment)}"'],
    )
    return [
        {
            "option_id": "disable",
            "label": "Disable rule",
            "description": "Schedule has expired -- disable the rule and record the date it was flagged.",
            "cli": [cli],
            "new_comment": new_comment,
        }
    ]


def _fix_unhit(finding: dict, live: dict, today: date) -> list[dict]:
    new_comment = _append_tag(_comment_field(live), today)
    cli = _policy_cli(
        live.get("policyid"),
        ["set status disable", f'set comments "{_safe(new_comment)}"'],
    )
    return [
        {
            "option_id": "disable",
            "label": "Disable rule",
            "description": "Zero hit count -- disable the rule and record the date it was flagged for later removal.",
            "cli": [cli],
            "new_comment": new_comment,
        }
    ]


def _fix_missing_security_profile(finding: dict, live: dict, today: date) -> list[dict]:
    return []


def _fix_disabled(finding: dict, live: dict, today: date) -> list[dict]:
    comment = _comment_field(live)
    tag_date = _find_tag(comment)
    if tag_date is None:
        new_comment = _append_tag(comment, today)
        cli = _policy_cli(live.get("policyid"), [f'set comments "{_safe(new_comment)}"'])
        return [
            {
                "option_id": "tag",
                "label": "Record disabled date",
                "description": "No prior HygieneFix tag found -- record today's date so age can be tracked.",
                "cli": [cli],
                "new_comment": new_comment,
            }
        ]
    age_days = (today - tag_date).days
    if age_days <= 90:
        return []
    cli = f"config firewall policy\n    delete {live.get('policyid')}\nend"
    return [
        {
            "option_id": "delete",
            "label": "Delete rule",
            "description": f"Disabled and tagged {age_days} days ago (over 90) -- recommend deletion.",
            "cli": [cli],
            "new_comment": None,
        }
    ]


def _fix_over_permissive(finding: dict, live: dict, today: date) -> list[dict]:
    disable_comment = _append_tag(_comment_field(live), today)
    disable_cli = _policy_cli(
        live.get("policyid"),
        ["set status disable", f'set comments "{_safe(disable_comment)}"'],
    )
    exempt_comment = _append_tag(_comment_field(live), today, exempt=True)
    exempt_cli = _policy_cli(live.get("policyid"), [f'set comments "{_safe(exempt_comment)}"'])
    return [
        {
            "option_id": "disable",
            "label": "Disable rule",
            "description": "Disable the over-permissive rule.",
            "cli": [disable_cli],
            "new_comment": disable_comment,
        },
        {
            "option_id": "exempt",
            "label": "Exempt (keep enabled)",
            "description": "Mark the rule as reviewed and exempted, keeping it enabled.",
            "cli": [exempt_cli],
            "new_comment": exempt_comment,
        },
    ]


def _fix_redundant(finding: dict, live: dict, today: date) -> list[dict]:
    dup = finding.get("duplicate_of") or {}
    dup_desc = (
        f" (duplicate of rule '{dup.get('name', '?')}' id {dup.get('id', '?')})" if dup else ""
    )
    new_comment = _append_tag(_comment_field(live), today)
    cli = _policy_cli(
        live.get("policyid"),
        ["set status disable", f'set comments "{_safe(new_comment)}"'],
    )
    return [
        {
            "option_id": "disable",
            "label": "Disable rule",
            "description": f"Disable the redundant rule{dup_desc}.",
            "cli": [cli],
            "new_comment": new_comment,
        }
    ]


_SHADOW_DIMS = ("srcaddr", "dstaddr", "service")


def _diff_dims(shadow_rule: dict, shadowing_rule: dict) -> list[str]:
    return [
        dim
        for dim in _SHADOW_DIMS
        if set(shadow_rule.get(dim, [])) != set(shadowing_rule.get(dim, []))
    ]


def _fix_shadow(finding: dict, live: dict, today: date) -> list[dict]:
    shadow_rule = finding.get("shadow_rule") or {}
    shadowing_rule = finding.get("shadowing_rule") or {}
    pid = live.get("policyid")

    disable_comment = _append_tag(_comment_field(live), today)
    disable_cli = _policy_cli(
        pid, ["set status disable", f'set comments "{_safe(disable_comment)}"']
    )
    options = [
        {
            "option_id": "disable",
            "label": "Disable shadowed rule",
            "description": "This rule can never match traffic -- disable it.",
            "cli": [disable_cli],
            "new_comment": disable_comment,
        }
    ]

    if not shadow_rule or not shadowing_rule:
        return options

    if shadow_rule.get("action") != shadowing_rule.get("action"):
        shadowing_id = shadowing_rule.get("id")
        options.append(
            {
                "option_id": "reorder",
                "label": "Reorder above shadowing rule",
                "description": (
                    f"Actions differ (shadowed={shadow_rule.get('action')}, "
                    f"shadowing={shadowing_rule.get('action')}) -- move this rule "
                    "above the shadowing rule so it can take effect."
                ),
                "cli": [f"move {pid} before {shadowing_id}"],
                "new_comment": None,
            }
        )

    diffs = _diff_dims(shadow_rule, shadowing_rule)
    if diffs:
        shadowing_id = shadowing_rule.get("id")
        if len(diffs) == 1:
            dim = diffs[0]
            shadowing_vals = set(shadowing_rule.get(dim, []))
            shadow_vals = set(shadow_rule.get(dim, []))
            narrowed = shadowing_vals - shadow_vals
            is_wildcard = any(v.lower() in ("any", "all") for v in shadowing_vals)
            if narrowed and not is_wildcard and shadowing_id:
                quoted = " ".join(f'"{_safe(v)}"' for v in sorted(narrowed))
                cli = [_policy_cli(shadowing_id, [f"set {dim} {quoted}"])]
                description = (
                    f"Restrict rule '{shadowing_rule.get('name', '?')}' "
                    f"(id {shadowing_id}) to exclude this rule's traffic, so "
                    "both rules become independently reachable."
                )
            else:
                cli = []
                description = (
                    f"Rule '{shadowing_rule.get('name', '?')}' (id {shadowing_id}) "
                    "uses a wildcard/group in the differing dimension that can't "
                    "be safely split automatically -- manual review required."
                )
        else:
            cli = []
            description = (
                f"Rule '{shadowing_rule.get('name', '?')}' (id {shadowing_id}) "
                "differs from this rule in more than one dimension -- manual "
                "review required to narrow its scope safely."
            )
        options.append(
            {
                "option_id": "narrow",
                "label": "Narrow shadowing rule's scope",
                "description": description,
                "cli": cli,
                "new_comment": None,
            }
        )

    return options


_FIX_FNS = {
    "unlogged": _fix_unlogged,
    "unnamed": _fix_unnamed,
    "expired": _fix_expired,
    "unhit": _fix_unhit,
    "missing_security_profile": _fix_missing_security_profile,
    "disabled": _fix_disabled,
    "over_permissive": _fix_over_permissive,
    "redundant": _fix_redundant,
    "shadow": _fix_shadow,
}


def build_fixes(
    live_policies: list[dict],
    pasted_findings: list[dict],
    now: datetime | None = None,
) -> dict:
    """Match pasted findings to live policies by policy_id and generate fixes.

    Findings whose policy_id has no match in live_policies are returned in
    stale_findings (with a "reason") instead of fixes. Findings whose check
    key has no registered generator are silently skipped (defensive -- the
    check set is fixed and every key should eventually have a generator).
    """
    today = (now or datetime.now(UTC)).date()
    live_by_id = {str(p.get("policyid")): p for p in live_policies}

    fixes: list[dict] = []
    stale: list[dict] = []
    for finding in pasted_findings:
        pid = str(finding.get("policy_id", ""))
        live = live_by_id.get(pid)
        if live is None:
            stale.append(
                {
                    **finding,
                    "reason": (
                        "policy_id not found in live package -- may have been "
                        "deleted or renumbered since the hygiene run"
                    ),
                }
            )
            continue
        fn = _FIX_FNS.get(finding.get("check"))
        if fn is None:
            continue
        options = fn(finding, live, today)
        fixes.append(
            {
                "policy_id": pid,
                "policy_name": finding.get("policy_name") or _name(live),
                "check": finding.get("check"),
                "detail": finding.get("detail", ""),
                "options": options,
            }
        )
    return {"fixes": fixes, "stale_findings": stale}


def to_hygiene_fix_report_payload(result: dict) -> dict:
    """Flatten build_fixes()'s result to the default (first) option per
    finding, for one-shot LLM narration. Never used to compute anything --
    purely a reshaping of already-computed data."""
    payload_fixes = []
    for fix in result["fixes"]:
        default = fix["options"][0] if fix["options"] else None
        payload_fixes.append(
            {
                "policy_id": fix["policy_id"],
                "policy_name": fix["policy_name"],
                "check": fix["check"],
                "detail": fix["detail"],
                "selected_option": default["label"] if default else "No automated fix",
                "description": default["description"] if default else fix["detail"],
            }
        )
    return {"fixes": payload_fixes, "stale_findings": result["stale_findings"]}
