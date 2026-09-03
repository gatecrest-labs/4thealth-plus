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

from app.hygiene import _action, _addr_list, _name, _svc_is_any  # noqa: F401 (re-exported for generators added in later tasks)

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


_FIX_FNS = {
    "unlogged": _fix_unlogged,
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
