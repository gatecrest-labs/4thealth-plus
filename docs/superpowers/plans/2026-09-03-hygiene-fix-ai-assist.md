# Hygiene Fix AI Assist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third AI Assist mode ("Hygiene Fix") to the Rule Validation tab that turns a completed Rule Hygiene run's findings into deterministic, per-finding FortiOS CLI remediations plus an LLM-narrated peer-review summary and a downloadable standalone HTML report.

**Architecture:** A new pure-function module `app/hygiene_fix.py` computes remediation options (never calls FortiManager or an LLM); a new route `POST /api/rule-review/ai-assist-hygiene-fix` parses the pasted/uploaded findings, re-fetches the live policy package from FortiManager, calls the module, then narrates the result with the existing LLM provider layer. A third mode toggle in the existing AI Assist panel (`rule_review.html`/`rule_review.js`) drives it, following the exact pattern already established by the "FQDN Allowlist" mode.

**Tech Stack:** Python 3 (Flask), vanilla JS, pytest, existing `app/llm/` provider layer, existing `app/fmg_client.FMGClient`.

**Spec:** [docs/superpowers/specs/2026-09-03-hygiene-fix-ai-assist-design.md](../specs/2026-09-03-hygiene-fix-ai-assist-design.md)

## Global Constraints

- No writes to FortiManager or devices anywhere in this feature — every CLI output is a human-reviewed, copy-pasted suggestion (project-wide rule, restated in the spec's "Explicitly Out of Scope").
- Every comment-appending fix uses the exact tag format `[HygieneFix YYYY-MM-DD]` (or `[HygieneFix EXEMPT YYYY-MM-DD]` for the Over-Permissive "exempt" option), truncating the *original* comment content (never the tag) to fit FortiOS's 255-character comment limit.
- `app/hygiene_fix.py` must not import Flask, FMGClient, or the LLM provider — it is a pure function library (compute/narrate split), mirroring `app/planner/` and `app/hygiene_ai.py`.
- The route gate is the existing `ai_assist_enabled` app-settings flag (503 when disabled) — no new feature flag.
- Reuse existing helpers rather than duplicating: `app.hygiene._status`, `_action`, `_logtraffic`, `_name`, `_addr_list`, `_is_any`, `_svc_is_any`, and `app.hygiene.CHECKS` (already imported cross-module by `app/routes/hygiene_routes.py`, so this is an established pattern in this codebase).
- All downloads (CLI copy, HTML report) are client-side (`Blob` + `URL.createObjectURL`), no server round trip — matches every other export in this app.

---

## File Structure

- **Create** `app/hygiene_fix.py` — deterministic fix-generation engine (tag helpers, one `_fix_<check>` function per check key, `build_fixes()`, `to_hygiene_fix_report_payload()`).
- **Modify** `app/routes/rule_review_routes.py` — add `POST /api/rule-review/ai-assist-hygiene-fix`.
- **Modify** `app/templates/rule_review.html` — add the third mode button, its form, and its result container.
- **Modify** `app/static/js/rule_review.js` — add the third mode's ADOM/package loaders, submit handler, per-finding render logic, and HTML report download.
- **Modify** `CLAUDE.md` — document the new mode under "Rule Validation tab → AI Assist mode".
- **Create** `tests/test_hygiene_fix.py` — unit tests for every `_fix_<check>` generator and `build_fixes()`.
- **Create** `tests/test_rule_review_ai_assist_hygiene_fix.py` — route-level tests.

---

### Task 1: `hygiene_fix.py` — tag helpers, dispatcher skeleton, `build_fixes()`, and the `unlogged` generator

**Files:**
- Create: `app/hygiene_fix.py`
- Test: `tests/test_hygiene_fix.py`

**Interfaces:**
- Produces: `_find_tag(comment: str) -> date | None`, `_append_tag(comment: str, today: date, exempt: bool = False) -> str`, `_policy_cli(policy_id: str, sets: list[str]) -> str`, `_safe(s: str) -> str`, `_comment_field(p: dict) -> str`, `build_fixes(live_policies: list[dict], pasted_findings: list[dict], now: datetime | None = None) -> dict` returning `{"fixes": list[dict], "stale_findings": list[dict]}`. A `PolicyFix` dict has keys `policy_id, policy_name, check, detail, options`; a `FixOption` dict has keys `option_id, label, description, cli (list[str]), new_comment (str | None)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_hygiene_fix.py
import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from datetime import date
from app.hygiene_fix import _append_tag, _find_tag, build_fixes


def test_append_tag_no_prior_comment():
    result = _append_tag("", date(2026, 9, 3))
    assert result == "[HygieneFix 2026-09-03]"


def test_append_tag_preserves_prior_comment():
    result = _append_tag("Allow vendor access", date(2026, 9, 3))
    assert result == "Allow vendor access [HygieneFix 2026-09-03]"


def test_append_tag_exempt_marker():
    result = _append_tag("Reviewed", date(2026, 9, 3), exempt=True)
    assert result == "Reviewed [HygieneFix EXEMPT 2026-09-03]"


def test_append_tag_truncates_long_comment_to_255_chars():
    long_comment = "x" * 300
    result = _append_tag(long_comment, date(2026, 9, 3))
    assert len(result) <= 255
    assert result.endswith("[HygieneFix 2026-09-03]")


def test_find_tag_returns_date_when_present():
    assert _find_tag("Old note [HygieneFix 2026-06-01]") == date(2026, 6, 1)


def test_find_tag_returns_none_when_absent():
    assert _find_tag("No tag here") is None


def test_find_tag_matches_exempt_variant():
    assert _find_tag("Reviewed [HygieneFix EXEMPT 2026-06-01]") == date(2026, 6, 1)


def _live_policy(policyid, logtraffic="disable", comments=""):
    return {"policyid": policyid, "name": "rule-1", "logtraffic": logtraffic, "comments": comments}


def test_build_fixes_unlogged_generates_cli():
    live = [_live_policy(10)]
    findings = [{"policy_id": "10", "policy_name": "rule-1", "check": "unlogged", "detail": "no logging"}]
    result = build_fixes(live, findings, now=None)
    assert result["stale_findings"] == []
    assert len(result["fixes"]) == 1
    fix = result["fixes"][0]
    assert fix["check"] == "unlogged"
    assert len(fix["options"]) == 1
    assert "set logtraffic all" in fix["options"][0]["cli"][0]
    assert "edit 10" in fix["options"][0]["cli"][0]


def test_build_fixes_flags_stale_finding():
    live = [_live_policy(10)]
    findings = [{"policy_id": "999", "policy_name": "ghost", "check": "unlogged", "detail": "no logging"}]
    result = build_fixes(live, findings, now=None)
    assert result["fixes"] == []
    assert len(result["stale_findings"]) == 1
    assert "policy_id not found" in result["stale_findings"][0]["reason"]


def test_build_fixes_skips_unknown_check_key():
    live = [_live_policy(10)]
    findings = [{"policy_id": "10", "policy_name": "rule-1", "check": "not_a_real_check", "detail": "x"}]
    result = build_fixes(live, findings, now=None)
    assert result["fixes"] == []
    assert result["stale_findings"] == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hygiene_fix.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.hygiene_fix'`

- [ ] **Step 3: Write the implementation**

```python
# app/hygiene_fix.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hygiene_fix.py -v`
Expected: PASS (all tests in this file)

- [ ] **Step 5: Commit**

```bash
git add app/hygiene_fix.py tests/test_hygiene_fix.py
git commit -m "$(cat <<'EOF'
feat: add Hygiene Fix tag helpers, dispatcher, and unlogged generator

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 2: `unnamed`, `expired`, `unhit` generators

**Files:**
- Modify: `app/hygiene_fix.py`
- Test: `tests/test_hygiene_fix.py`

**Interfaces:**
- Consumes: `_policy_cli`, `_safe`, `_comment_field`, `_append_tag` from Task 1.
- Produces: `_fix_unnamed`, `_fix_expired`, `_fix_unhit` — each `(finding: dict, live: dict, today: date) -> list[dict]`, registered in `_FIX_FNS` under keys `"unnamed"`, `"expired"`, `"unhit"`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_hygiene_fix.py
from datetime import date
from app.hygiene_fix import build_fixes


def test_unnamed_suggests_name_from_src_and_dst():
    live = [{"policyid": 5, "name": "", "srcaddr": ["Vendor-API"], "dstaddr": ["Internal-DB"], "comments": ""}]
    findings = [{"policy_id": "5", "policy_name": "Policy #5", "check": "unnamed", "detail": "no name"}]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert 'set name "Allow Vendor-API to Internal-DB"' in opt["cli"][0]
    assert "[HygieneFix" in opt["new_comment"]


def test_unnamed_falls_back_to_unknown_when_no_specific_reference():
    live = [{"policyid": 6, "name": "", "srcaddr": ["all"], "dstaddr": ["any"], "comments": ""}]
    findings = [{"policy_id": "6", "policy_name": "Policy #6", "check": "unnamed", "detail": "no name"}]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert 'set name "Unknown -- Requires additional research"' in opt["cli"][0]


def test_expired_disables_and_tags():
    live = [{"policyid": 7, "name": "old-rule", "comments": ""}]
    findings = [{"policy_id": "7", "policy_name": "old-rule", "check": "expired", "detail": "past end date"}]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert "set status disable" in opt["cli"][0]
    assert "[HygieneFix" in opt["new_comment"]


def test_unhit_disables_and_tags():
    live = [{"policyid": 8, "name": "unused-rule", "comments": "orig note"}]
    findings = [{"policy_id": "8", "policy_name": "unused-rule", "check": "unhit", "detail": "zero hits"}]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert "set status disable" in opt["cli"][0]
    assert opt["new_comment"].startswith("orig note")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hygiene_fix.py -v -k "unnamed or expired or unhit"`
Expected: FAIL — `unnamed`/`expired`/`unhit` findings currently produce no fixes (no registered generator), so `result["fixes"]` is empty and indexing `[0]` raises `IndexError`.

- [ ] **Step 3: Write the implementation**

```python
# add to app/hygiene_fix.py, after _fix_unlogged

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
```

```python
# update _FIX_FNS in app/hygiene_fix.py
_FIX_FNS = {
    "unlogged": _fix_unlogged,
    "unnamed": _fix_unnamed,
    "expired": _fix_expired,
    "unhit": _fix_unhit,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hygiene_fix.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add app/hygiene_fix.py tests/test_hygiene_fix.py
git commit -m "$(cat <<'EOF'
feat: add unnamed, expired, and unhit Hygiene Fix generators

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 3: `missing_security_profile` and `disabled` generators (90-day logic)

**Files:**
- Modify: `app/hygiene_fix.py`
- Test: `tests/test_hygiene_fix.py`

**Interfaces:**
- Produces: `_fix_missing_security_profile`, `_fix_disabled` — same signature as Task 2's generators, registered under `"missing_security_profile"` and `"disabled"`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_hygiene_fix.py
from datetime import UTC, datetime


def test_missing_security_profile_returns_no_options():
    live = [{"policyid": 9, "name": "no-utm", "comments": ""}]
    findings = [{"policy_id": "9", "policy_name": "no-utm", "check": "missing_security_profile", "detail": "no UTM"}]
    result = build_fixes(live, findings, now=None)
    assert result["fixes"][0]["options"] == []


def test_disabled_with_no_prior_tag_proposes_adding_one():
    live = [{"policyid": 11, "name": "old-disabled", "comments": "manually turned off"}]
    findings = [{"policy_id": "11", "policy_name": "old-disabled", "check": "disabled", "detail": "status=disable"}]
    result = build_fixes(live, findings, now=datetime(2026, 9, 3, tzinfo=UTC))
    opt = result["fixes"][0]["options"][0]
    assert opt["option_id"] == "tag"
    assert "[HygieneFix 2026-09-03]" in opt["new_comment"]


def test_disabled_with_tag_under_90_days_needs_no_action():
    live = [{"policyid": 12, "name": "recently-disabled", "comments": "note [HygieneFix 2026-08-01]"}]
    findings = [{"policy_id": "12", "policy_name": "recently-disabled", "check": "disabled", "detail": "status=disable"}]
    result = build_fixes(live, findings, now=datetime(2026, 9, 3, tzinfo=UTC))
    assert result["fixes"][0]["options"] == []


def test_disabled_with_tag_over_90_days_proposes_delete():
    live = [{"policyid": 13, "name": "stale-disabled", "comments": "note [HygieneFix 2026-01-01]"}]
    findings = [{"policy_id": "13", "policy_name": "stale-disabled", "check": "disabled", "detail": "status=disable"}]
    result = build_fixes(live, findings, now=datetime(2026, 9, 3, tzinfo=UTC))
    opt = result["fixes"][0]["options"][0]
    assert opt["option_id"] == "delete"
    assert "delete 13" in opt["cli"][0]
    assert opt["new_comment"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hygiene_fix.py -v -k "missing_security_profile or disabled"`
Expected: FAIL — no registered generator for these checks yet, `result["fixes"][0]["options"]` indexing raises `IndexError`.

- [ ] **Step 3: Write the implementation**

```python
# add to app/hygiene_fix.py

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
```

```python
# update _FIX_FNS in app/hygiene_fix.py
_FIX_FNS = {
    "unlogged": _fix_unlogged,
    "unnamed": _fix_unnamed,
    "expired": _fix_expired,
    "unhit": _fix_unhit,
    "missing_security_profile": _fix_missing_security_profile,
    "disabled": _fix_disabled,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hygiene_fix.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add app/hygiene_fix.py tests/test_hygiene_fix.py
git commit -m "$(cat <<'EOF'
feat: add missing_security_profile and disabled Hygiene Fix generators

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 4: `over_permissive` and `redundant` generators

**Files:**
- Modify: `app/hygiene_fix.py`
- Test: `tests/test_hygiene_fix.py`

**Interfaces:**
- Produces: `_fix_over_permissive` (returns 2 options), `_fix_redundant` (returns 1 option, reads `finding["duplicate_of"]` when present), registered under `"over_permissive"` and `"redundant"`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_hygiene_fix.py

def test_over_permissive_returns_disable_and_exempt_options():
    live = [{"policyid": 14, "name": "wide-open", "comments": ""}]
    findings = [{"policy_id": "14", "policy_name": "wide-open", "check": "over_permissive", "detail": "fully open"}]
    result = build_fixes(live, findings, now=None)
    options = result["fixes"][0]["options"]
    assert [o["option_id"] for o in options] == ["disable", "exempt"]
    assert "set status disable" in options[0]["cli"][0]
    assert "EXEMPT" in options[1]["new_comment"]
    assert "set status disable" not in options[1]["cli"][0]


def test_redundant_disables_later_rule_and_names_duplicate():
    live = [{"policyid": 15, "name": "later-rule", "comments": ""}]
    findings = [{
        "policy_id": "15", "policy_name": "later-rule", "check": "redundant",
        "detail": "matches earlier rule",
        "duplicate_of": {"id": "3", "name": "earlier-rule"},
    }]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert "set status disable" in opt["cli"][0]
    assert "earlier-rule" in opt["description"]
    assert "id 3" in opt["description"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hygiene_fix.py -v -k "over_permissive or redundant"`
Expected: FAIL — no registered generator for these checks, `options` list is empty so indexing/assertions fail.

- [ ] **Step 3: Write the implementation**

```python
# add to app/hygiene_fix.py

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
```

```python
# update _FIX_FNS in app/hygiene_fix.py
_FIX_FNS = {
    "unlogged": _fix_unlogged,
    "unnamed": _fix_unnamed,
    "expired": _fix_expired,
    "unhit": _fix_unhit,
    "missing_security_profile": _fix_missing_security_profile,
    "disabled": _fix_disabled,
    "over_permissive": _fix_over_permissive,
    "redundant": _fix_redundant,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hygiene_fix.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add app/hygiene_fix.py tests/test_hygiene_fix.py
git commit -m "$(cat <<'EOF'
feat: add over_permissive and redundant Hygiene Fix generators

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 5: `shadow` generator (Disable / Reorder / Narrow-scope options)

**Files:**
- Modify: `app/hygiene_fix.py`
- Test: `tests/test_hygiene_fix.py`

**Interfaces:**
- Produces: `_diff_dims(shadow_rule: dict, shadowing_rule: dict) -> list[str]`, `_fix_shadow(finding, live, today) -> list[dict]`, registered under `"shadow"`.
- Consumes: the finding's own embedded `shadow_rule`/`shadowing_rule` dicts (shape from `app.hygiene._rule_summary`: `{id, name, status, action, srcaddr, dstaddr, service, fsso_groups, comment}`), which may be **absent** when the pasted findings came from a CSV export.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_hygiene_fix.py

def _shadow_finding(shadow_rule=None, shadowing_rule=None):
    f = {"policy_id": "20", "policy_name": "shadowed-rule", "check": "shadow", "detail": "fully shadowed"}
    if shadow_rule is not None:
        f["shadow_rule"] = shadow_rule
    if shadowing_rule is not None:
        f["shadowing_rule"] = shadowing_rule
    return f


def test_shadow_always_offers_disable():
    live = [{"policyid": 20, "name": "shadowed-rule", "comments": ""}]
    findings = [_shadow_finding(
        shadow_rule={"id": "20", "name": "shadowed-rule", "action": "accept", "srcaddr": ["A"], "dstaddr": ["B"], "service": ["ALL"]},
        shadowing_rule={"id": "5", "name": "earlier-rule", "action": "accept", "srcaddr": ["A"], "dstaddr": ["B"], "service": ["ALL"]},
    )]
    result = build_fixes(live, findings, now=None)
    options = result["fixes"][0]["options"]
    assert options[0]["option_id"] == "disable"
    assert "set status disable" in options[0]["cli"][0]
    # identical scope -> no narrow option, and same action -> no reorder option
    assert [o["option_id"] for o in options] == ["disable"]


def test_shadow_offers_reorder_when_actions_differ():
    live = [{"policyid": 20, "name": "shadowed-rule", "comments": ""}]
    findings = [_shadow_finding(
        shadow_rule={"id": "20", "name": "shadowed-rule", "action": "deny", "srcaddr": ["A"], "dstaddr": ["B"], "service": ["ALL"]},
        shadowing_rule={"id": "5", "name": "earlier-rule", "action": "accept", "srcaddr": ["A"], "dstaddr": ["B"], "service": ["ALL"]},
    )]
    result = build_fixes(live, findings, now=None)
    options = result["fixes"][0]["options"]
    reorder = next(o for o in options if o["option_id"] == "reorder")
    assert reorder["cli"] == ["move 20 before 5"]


def test_shadow_offers_narrow_when_one_dimension_differs_and_not_wildcard():
    live = [{"policyid": 20, "name": "shadowed-rule", "comments": ""}]
    findings = [_shadow_finding(
        shadow_rule={"id": "20", "name": "shadowed-rule", "action": "accept", "srcaddr": ["A"], "dstaddr": ["B"], "service": ["ALL"]},
        shadowing_rule={"id": "5", "name": "earlier-rule", "action": "accept", "srcaddr": ["A", "C"], "dstaddr": ["B"], "service": ["ALL"]},
    )]
    result = build_fixes(live, findings, now=None)
    options = result["fixes"][0]["options"]
    narrow = next(o for o in options if o["option_id"] == "narrow")
    assert narrow["cli"] == ['config firewall policy\n    edit 5\n        set srcaddr "C"\n    next\nend']


def test_shadow_narrow_option_has_no_cli_when_dimension_is_wildcard():
    live = [{"policyid": 20, "name": "shadowed-rule", "comments": ""}]
    findings = [_shadow_finding(
        shadow_rule={"id": "20", "name": "shadowed-rule", "action": "accept", "srcaddr": ["A"], "dstaddr": ["B"], "service": ["ALL"]},
        shadowing_rule={"id": "5", "name": "earlier-rule", "action": "accept", "srcaddr": ["all"], "dstaddr": ["B"], "service": ["ALL"]},
    )]
    result = build_fixes(live, findings, now=None)
    options = result["fixes"][0]["options"]
    narrow = next(o for o in options if o["option_id"] == "narrow")
    assert narrow["cli"] == []
    assert "manual" in narrow["description"].lower()


def test_shadow_without_embedded_rule_summaries_offers_only_disable():
    # CSV-sourced findings have no shadow_rule/shadowing_rule -- degrade gracefully.
    live = [{"policyid": 20, "name": "shadowed-rule", "comments": ""}]
    findings = [_shadow_finding()]
    result = build_fixes(live, findings, now=None)
    options = result["fixes"][0]["options"]
    assert [o["option_id"] for o in options] == ["disable"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hygiene_fix.py -v -k shadow`
Expected: FAIL — no registered generator for `"shadow"`, `options` is empty.

- [ ] **Step 3: Write the implementation**

```python
# add to app/hygiene_fix.py

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
```

```python
# update _FIX_FNS in app/hygiene_fix.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hygiene_fix.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add app/hygiene_fix.py tests/test_hygiene_fix.py
git commit -m "$(cat <<'EOF'
feat: add shadow Hygiene Fix generator with disable/reorder/narrow options

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 6: `to_hygiene_fix_report_payload()` and full-batch test

**Files:**
- Modify: `app/hygiene_fix.py`
- Test: `tests/test_hygiene_fix.py`

**Interfaces:**
- Produces: `to_hygiene_fix_report_payload(result: dict) -> dict` — `result` is `build_fixes()`'s return value; output shape `{"fixes": [{"policy_id", "policy_name", "check", "detail", "selected_option", "description"}, ...], "stale_findings": [...]}` for LLM narration in Task 7.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_hygiene_fix.py
from app.hygiene_fix import to_hygiene_fix_report_payload


def test_report_payload_uses_first_option_as_default():
    live = [{"policyid": 21, "name": "wide-open", "comments": ""}]
    findings = [{"policy_id": "21", "policy_name": "wide-open", "check": "over_permissive", "detail": "fully open"}]
    result = build_fixes(live, findings, now=None)
    payload = to_hygiene_fix_report_payload(result)
    assert payload["fixes"][0]["selected_option"] == "Disable rule"
    assert payload["fixes"][0]["description"] == "Disable the over-permissive rule."


def test_report_payload_handles_no_automated_fix():
    live = [{"policyid": 22, "name": "no-utm", "comments": ""}]
    findings = [{"policy_id": "22", "policy_name": "no-utm", "check": "missing_security_profile", "detail": "no UTM configured"}]
    result = build_fixes(live, findings, now=None)
    payload = to_hygiene_fix_report_payload(result)
    assert payload["fixes"][0]["selected_option"] == "No automated fix"
    assert payload["fixes"][0]["description"] == "no UTM configured"


def test_build_fixes_handles_full_mixed_batch():
    live = [
        {"policyid": 1, "name": "r1", "comments": "", "srcaddr": ["all"], "dstaddr": ["all"]},
        {"policyid": 2, "name": "r2", "comments": "", "logtraffic": "disable"},
        {"policyid": 3, "name": "r3", "comments": ""},
    ]
    findings = [
        {"policy_id": "1", "policy_name": "r1", "check": "unnamed", "detail": "no name"},
        {"policy_id": "2", "policy_name": "r2", "check": "unlogged", "detail": "no logging"},
        {"policy_id": "999", "policy_name": "ghost", "check": "expired", "detail": "gone"},
    ]
    result = build_fixes(live, findings, now=None)
    assert len(result["fixes"]) == 2
    assert len(result["stale_findings"]) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hygiene_fix.py -v -k "report_payload or mixed_batch"`
Expected: FAIL with `ImportError: cannot import name 'to_hygiene_fix_report_payload'`

- [ ] **Step 3: Write the implementation**

```python
# add to app/hygiene_fix.py

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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hygiene_fix.py -v`
Expected: PASS (all tests in the file)

- [ ] **Step 5: Commit**

```bash
git add app/hygiene_fix.py tests/test_hygiene_fix.py
git commit -m "$(cat <<'EOF'
feat: add Hygiene Fix report payload builder for LLM narration

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 7: Backend route `POST /api/rule-review/ai-assist-hygiene-fix`

**Files:**
- Modify: `app/routes/rule_review_routes.py`
- Test: `tests/test_rule_review_ai_assist_hygiene_fix.py`

**Interfaces:**
- Consumes: `app.hygiene_fix.build_fixes`, `app.hygiene_fix.to_hygiene_fix_report_payload` (Tasks 1-6); `app.hygiene.CHECKS` (existing); `make_client`, `check_adom_access`, `internal_api_error`, `upstream_api_error` (existing, already imported at the top of this file).
- Produces: route accepting `multipart/form-data` with fields `adom`, `pkg`, and one of `findings_text` (raw JSON or CSV text) / `findings_file` (an uploaded `.json` or `.csv` file — file wins if both given). Response JSON: `{adom, pkg, generated_at, fixes, stale_findings, narrative, narrative_error}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_rule_review_ai_assist_hygiene_fix.py
"""Tests for POST /api/rule-review/ai-assist-hygiene-fix."""
import io
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")


@pytest.fixture
def app():
    from app import create_app
    return create_app()


_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def client(app):
    with app.test_client() as c, \
         patch("app.auth._load_users", return_value=_TEST_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def _post_form(client, form, files=None):
    data = {**form}
    if files:
        data.update(files)
    return client.post(
        "/api/rule-review/ai-assist-hygiene-fix",
        data=data,
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": "test-csrf"},
    )


def test_hygiene_fix_disabled_by_default_returns_503(client):
    with patch("app.app_settings.get_setting", return_value=False):
        resp = _post_form(client, {"adom": "OT-ADOM", "pkg": "OT-Package", "findings_text": "[]"})
    assert resp.status_code == 503


def test_hygiene_fix_missing_adom_returns_400(client):
    with patch("app.app_settings.get_setting", return_value=True):
        resp = _post_form(client, {"pkg": "OT-Package", "findings_text": "[]"})
    assert resp.status_code == 400


def test_hygiene_fix_no_findings_returns_400(client):
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.decorators.check_adom_access", return_value=None):
        resp = _post_form(client, {"adom": "OT-ADOM", "pkg": "OT-Package", "findings_text": "[]"})
    assert resp.status_code == 400


def test_hygiene_fix_json_success_returns_fixes_and_narrative(client):
    findings = json.dumps([
        {"policy_id": "10", "policy_name": "r1", "check": "unlogged", "detail": "no logging"},
    ])
    live_policies = [{"policyid": 10, "name": "r1", "logtraffic": "disable", "comments": ""}]

    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.decorators.check_adom_access", return_value=None), \
         patch("app.routes.rule_review_routes.make_client") as mock_make_client, \
         patch("app.llm.get_provider") as mock_get_provider:
        mock_client = MagicMock()
        mock_client.get_policies.return_value = live_policies
        mock_make_client.return_value.__enter__.return_value = mock_client
        mock_get_provider.return_value.narrate.return_value = "Narrative text."

        resp = _post_form(client, {"adom": "OT-ADOM", "pkg": "OT-Package", "findings_text": findings})

    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["fixes"]) == 1
    assert data["fixes"][0]["check"] == "unlogged"
    assert data["stale_findings"] == []
    assert data["narrative"] == "Narrative text."
    assert data["narrative_error"] is None


def test_hygiene_fix_csv_upload_normalizes_check_label_to_key(client):
    csv_text = (
        "Seq,Policy ID,Policy Name,Check,Detail\r\n"
        "1,10,r1,Unlogged Rules (logging disabled),no logging\r\n"
    )
    live_policies = [{"policyid": 10, "name": "r1", "logtraffic": "disable", "comments": ""}]

    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.decorators.check_adom_access", return_value=None), \
         patch("app.routes.rule_review_routes.make_client") as mock_make_client, \
         patch("app.llm.get_provider") as mock_get_provider:
        mock_client = MagicMock()
        mock_client.get_policies.return_value = live_policies
        mock_make_client.return_value.__enter__.return_value = mock_client
        mock_get_provider.return_value.narrate.return_value = "Narrative text."

        resp = _post_form(
            client,
            {"adom": "OT-ADOM", "pkg": "OT-Package"},
            files={"findings_file": (io.BytesIO(csv_text.encode()), "findings.csv")},
        )

    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["fixes"]) == 1
    assert data["fixes"][0]["check"] == "unlogged"


def test_hygiene_fix_narration_failure_still_returns_fixes(client):
    findings = json.dumps([
        {"policy_id": "10", "policy_name": "r1", "check": "unlogged", "detail": "no logging"},
    ])
    live_policies = [{"policyid": 10, "name": "r1", "logtraffic": "disable", "comments": ""}]

    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.decorators.check_adom_access", return_value=None), \
         patch("app.routes.rule_review_routes.make_client") as mock_make_client, \
         patch("app.llm.get_provider", side_effect=RuntimeError("no provider configured")):
        mock_client = MagicMock()
        mock_client.get_policies.return_value = live_policies
        mock_make_client.return_value.__enter__.return_value = mock_client

        resp = _post_form(client, {"adom": "OT-ADOM", "pkg": "OT-Package", "findings_text": findings})

    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["fixes"]) == 1
    assert data["narrative"] is None
    assert "no provider configured" in data["narrative_error"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_rule_review_ai_assist_hygiene_fix.py -v`
Expected: FAIL with 404 (route does not exist yet)

- [ ] **Step 3: Write the implementation**

Add near the top of `app/routes/rule_review_routes.py`, in the module docstring's endpoint list:

```python
#   POST /api/rule-review/ai-assist-hygiene-fix — Rule Hygiene findings -> deterministic CLI fixes (planner + LLM narration)
```

Add the route itself, after `rr_ai_assist_fqdn` (end of file):

```python
@bp.route("/api/rule-review/ai-assist-hygiene-fix", methods=["POST"])
@tab_required("rule_review")
def rr_ai_assist_hygiene_fix():
    """AI Assist (Hygiene Fix mode): parse a pasted/uploaded Rule Hygiene
    export, re-fetch the live policy package, generate deterministic CLI
    remediations, then narrate the batch with the configured LLM. Same
    guarantees as rr_ai_assist -- the deterministic result always returns;
    narration is best-effort."""
    from datetime import UTC, datetime

    from app.app_settings import get_setting
    from app.hygiene import CHECKS
    from app.hygiene_fix import build_fixes, to_hygiene_fix_report_payload

    if not get_setting("ai_assist_enabled", False):
        return jsonify({"error": "AI Assist is not enabled"}), 503

    adom = (request.form.get("adom") or "").strip()
    pkg = (request.form.get("pkg") or "").strip()
    if not adom or not pkg:
        return jsonify({"error": "adom and pkg are required"}), 400
    if err := check_adom_access(adom):
        return err

    label_to_key = {v: k for k, v in CHECKS.items()}

    def _normalize_check_key(raw: str) -> str:
        return raw if raw in CHECKS else label_to_key.get(raw, raw)

    findings_file = request.files.get("findings_file")
    is_csv = False
    if findings_file and findings_file.filename:
        raw = findings_file.read().decode("utf-8", errors="replace")
        is_csv = findings_file.filename.lower().endswith(".csv")
    else:
        raw = request.form.get("findings_text", "")
        stripped = raw.strip()
        is_csv = bool(stripped) and not stripped.startswith(("{", "["))

    if not raw.strip():
        return jsonify({"error": "No findings provided"}), 400

    try:
        if is_csv:
            reader = csv.DictReader(io.StringIO(raw))
            pasted_findings = [
                {
                    "policy_id": row.get("Policy ID", ""),
                    "policy_name": row.get("Policy Name", ""),
                    "seq": row.get("Seq", ""),
                    "check": _normalize_check_key(row.get("Check", "")),
                    "detail": row.get("Detail", ""),
                }
                for row in reader
                if row.get("Policy ID")
            ]
        else:
            parsed = _json.loads(raw)
            pasted_findings = parsed.get("findings", []) if isinstance(parsed, dict) else parsed
            if not isinstance(pasted_findings, list):
                raise ValueError(
                    "Expected a list of findings or an object with a 'findings' array"
                )
            for f in pasted_findings:
                if isinstance(f, dict) and "check" in f:
                    f["check"] = _normalize_check_key(f["check"])
    except Exception as exc:
        return jsonify({"error": f"Could not parse findings: {exc}"}), 400

    if not pasted_findings:
        return jsonify({"error": "No findings found in the provided data"}), 400

    try:
        with make_client() as client:
            live_policies = client.get_policies(adom, pkg)
    except FMGError as exc:
        return upstream_api_error("rule_review", exc)
    except Exception as exc:
        return internal_api_error("rule_review", exc)

    result = build_fixes(live_policies, pasted_findings)

    narrative = None
    narrative_error = None
    try:
        from app.llm import get_provider

        provider = get_provider()
        narrative = provider.narrate(
            system_prompt=(
                "You are a firewall rule hygiene assistant. You are given a "
                "structured, already-computed set of remediation options for a "
                "batch of Rule Hygiene findings (unnamed, unlogged, shadow, "
                "disabled, expired, unhit, missing security profile, "
                "redundant, over-permissive) as JSON. Write a clear, concise "
                "report for a peer reviewer: summarize counts by check, and "
                "call out anything notable (e.g. a rule recommended for "
                "deletion). Never invent or change any value -- only explain "
                "the already-selected default option for each finding in "
                "prose."
            ),
            user_prompt=_json.dumps(to_hygiene_fix_report_payload(result), default=str),
            feature="rule_review_ai_assist_hygiene_fix",
            user=session.get("user"),
        )
    except Exception as exc:
        narrative_error = str(exc)

    return jsonify(
        {
            "adom": adom,
            "pkg": pkg,
            "generated_at": datetime.now(UTC).isoformat(),
            "fixes": result["fixes"],
            "stale_findings": result["stale_findings"],
            "narrative": narrative,
            "narrative_error": narrative_error,
        }
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_rule_review_ai_assist_hygiene_fix.py -v`
Expected: PASS (all tests)

Also run the full existing rule-review test suite to confirm nothing else broke:

Run: `pytest tests/test_rule_review_ai_assist.py tests/test_rule_review_ai_assist_fqdn.py -v`
Expected: PASS (unchanged)

- [ ] **Step 5: Commit**

```bash
git add app/routes/rule_review_routes.py tests/test_rule_review_ai_assist_hygiene_fix.py
git commit -m "$(cat <<'EOF'
feat: add POST /api/rule-review/ai-assist-hygiene-fix route

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 8: Frontend markup — third mode button, form, result container

**Files:**
- Modify: `app/templates/rule_review.html`

**Interfaces:**
- Produces: DOM elements `#rrAiModeHygieneFix`, `#rrAiHygieneFixForm` (containing `#rrHfAdom`, `#rrHfPackage`, `#rrHfFindingsText`, `#rrHfFindingsFile`, `#rrHfSubmitBtn`), `#rrAiHygieneFixRunning`, `#rrAiHygieneFixError`, `#rrAiHygieneFixResult` (containing `#rrHfStaleWarning`, `#rrHfFixesContainer`, `#rrHfNarrativeError`, `#rrHfNarrative`, `#rrHfDownloadBtn`) — consumed by Task 9's JS.

- [ ] **Step 1: Add the third mode button**

In `app/templates/rule_review.html`, locate the mode toggle block (around line 126-129) and add a third button:

```html
  <div class="rr-ai-mode-toggle" style="margin-bottom:1rem;display:flex;gap:.5rem">
    <button type="button" class="btn btn-sm btn-primary" id="rrAiModeSingle">Single Change</button>
    <button type="button" class="btn btn-sm btn-secondary" id="rrAiModeFqdn">FQDN Allowlist</button>
    <button type="button" class="btn btn-sm btn-secondary" id="rrAiModeHygieneFix">Hygiene Fix</button>
  </div>
```

- [ ] **Step 2: Add the Hygiene Fix form**

Immediately after the `</form>` closing `rrAiFqdnForm` (around line 220), add:

```html
  <form id="rrAiHygieneFixForm" class="rr-form" style="display:none">
    <div class="rr-form-row">
      <label for="rrHfAdom">ADOM</label>
      <select id="rrHfAdom"><option value="">— select ADOM —</option></select>
    </div>
    <div class="rr-form-row">
      <label for="rrHfPackage">Policy Package</label>
      <select id="rrHfPackage" disabled><option value="">— select ADOM first —</option></select>
    </div>
    <div class="rr-form-row">
      <label for="rrHfFindingsText">Paste hygiene findings (JSON or CSV)</label>
      <textarea id="rrHfFindingsText" rows="8" placeholder="Paste the contents of a Rule Hygiene JSON or CSV export here"></textarea>
    </div>
    <div class="rr-form-row">
      <label for="rrHfFindingsFile">Or upload a findings export (.json or .csv)</label>
      <input type="file" id="rrHfFindingsFile" accept=".json,.csv">
      <span class="rr-field-hint">If a file is attached, the pasted text above is ignored.</span>
    </div>
    <button type="submit" class="btn btn-primary" id="rrHfSubmitBtn">Run AI Assist</button>
  </form>
```

- [ ] **Step 3: Add the Hygiene Fix running/error/result containers**

Immediately after the existing `<div id="rrAiFqdnResult" ...>...</div>` block (around line 248), add:

```html
  <div id="rrAiHygieneFixRunning" class="rr-running" style="display:none">Fetching live policy data and generating fixes&hellip;</div>
  <div id="rrAiHygieneFixError" class="rr-error" style="display:none"></div>

  <div id="rrAiHygieneFixResult" style="display:none">
    <div id="rrHfStaleWarning" class="alert alert-warning" style="display:none"></div>
    <div id="rrHfFixesContainer"></div>
    <h3>AI-Generated Report</h3>
    <div id="rrHfNarrativeError" class="rr-notice" style="display:none"></div>
    <div id="rrHfNarrative" class="rr-narrative"></div>
    <button type="button" class="btn btn-sm" id="rrHfDownloadBtn">Download HTML Report</button>
  </div>
```

- [ ] **Step 4: Verify the page still renders**

Run: `python -c "from app import create_app; app = create_app(); app.test_client().get('/rule-review')"` in an environment with `SECRET_KEY` and `FMG_PRIMARY_HOST` set (or run the existing test suite, which already exercises page rendering):

Run: `pytest tests/ -k rule_review -v`
Expected: PASS (no route depends on this markup yet, so nothing should break)

- [ ] **Step 5: Commit**

```bash
git add app/templates/rule_review.html
git commit -m "$(cat <<'EOF'
feat: add Hygiene Fix mode markup to Rule Validation AI Assist panel

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 9: Frontend JS — mode wiring, ADOM/package loaders, submit + render

**Files:**
- Modify: `app/static/js/rule_review.js`

**Interfaces:**
- Consumes: DOM elements from Task 8; existing `esc()`, `switchAiMode()`-style pattern, `/api/rule-review/adoms`, `/api/rule-review/adoms/<adom>/packages` (existing endpoints), `/api/rule-review/ai-assist-hygiene-fix` (Task 7).
- Produces: module-level `hfLastResult` (the last successful response, used by Task 10's download button) and `hfSelectedOption` (a `Map` from fix-array-index to the currently selected option index, defaulting to `0`).

- [ ] **Step 1: Extend `switchAiMode` for the third mode and wire the button**

Replace the existing `switchAiMode` function (lines 915-936) with a version that also handles `'hygiene_fix'`:

```javascript
function switchAiMode(mode) {
  const forms = {
    single: document.getElementById('rrAiForm'),
    fqdn: document.getElementById('rrAiFqdnForm'),
    hygiene_fix: document.getElementById('rrAiHygieneFixForm'),
  };
  const buttons = {
    single: document.getElementById('rrAiModeSingle'),
    fqdn: document.getElementById('rrAiModeFqdn'),
    hygiene_fix: document.getElementById('rrAiModeHygieneFix'),
  };
  const results = {
    single: document.getElementById('rrAiResult'),
    fqdn: document.getElementById('rrAiFqdnResult'),
    hygiene_fix: document.getElementById('rrAiHygieneFixResult'),
  };
  Object.keys(forms).forEach(key => {
    forms[key].style.display = key === mode ? '' : 'none';
    buttons[key].classList.toggle('btn-primary', key === mode);
    buttons[key].classList.toggle('btn-secondary', key !== mode);
    if (key !== mode) results[key].style.display = 'none';
  });
  if (mode === 'hygiene_fix' && document.getElementById('rrHfAdom').options.length <= 1) {
    loadHfAdoms();
  }
}

document.getElementById('rrAiModeSingle')?.addEventListener('click', () => switchAiMode('single'));
document.getElementById('rrAiModeFqdn')?.addEventListener('click', () => switchAiMode('fqdn'));
document.getElementById('rrAiModeHygieneFix')?.addEventListener('click', () => switchAiMode('hygiene_fix'));
```

Remove the now-duplicated old two-line listener registration that previously followed the original `switchAiMode` definition (the two `addEventListener` lines directly below the old function body) so each button has exactly one listener.

- [ ] **Step 2: Add ADOM/package loaders scoped to the Hygiene Fix form**

Add after the new `switchAiMode` block:

```javascript
// ── AI Assist: Hygiene Fix mode ──────────────────────────────────────────

let hfPkgPaths = {};   // package display name -> path, scoped to the Hygiene Fix form

async function loadHfAdoms() {
  const sel = document.getElementById('rrHfAdom');
  try {
    const resp = await fetch('/api/rule-review/adoms');
    if (resp.status === 401) { location.href = '/login'; return; }
    const adoms = await resp.json();
    if (!Array.isArray(adoms)) return;
    adoms.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a; opt.textContent = a;
      sel.appendChild(opt);
    });
  } catch (_) {}
}

async function loadHfPackages(adom) {
  const sel = document.getElementById('rrHfPackage');
  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;
  hfPkgPaths = {};
  try {
    const resp = await fetch(`/api/rule-review/adoms/${encodeURIComponent(adom)}/packages`);
    if (resp.status === 401) { location.href = '/login'; return; }
    const pkgs = await resp.json();
    sel.innerHTML = '<option value="">— select package —</option>';
    if (Array.isArray(pkgs)) {
      pkgs.forEach(p => {
        hfPkgPaths[p.name] = p.path || p.name;
        const opt = document.createElement('option');
        opt.value = p.name; opt.textContent = p.name;
        sel.appendChild(opt);
      });
    }
    sel.disabled = false;
  } catch (_) {
    sel.innerHTML = '<option value="">Failed to load</option>';
  }
}

document.getElementById('rrHfAdom')?.addEventListener('change', (e) => {
  const adom = e.target.value;
  if (adom) loadHfPackages(adom);
});
```

- [ ] **Step 3: Add the submit handler and result state**

```javascript
let hfLastResult = null;
let hfSelectedOption = new Map();  // fix index -> selected option index

async function runHygieneFixAiAssist(evt) {
  evt.preventDefault();
  const errEl = document.getElementById('rrAiHygieneFixError');
  const resultEl = document.getElementById('rrAiHygieneFixResult');
  const runningEl = document.getElementById('rrAiHygieneFixRunning');
  errEl.style.display = 'none';
  resultEl.style.display = 'none';
  runningEl.style.display = '';

  const adom = document.getElementById('rrHfAdom').value;
  const pkgName = document.getElementById('rrHfPackage').value;
  const pkg = hfPkgPaths[pkgName] || pkgName;
  const fileInput = document.getElementById('rrHfFindingsFile');
  const file = fileInput.files[0];
  const text = document.getElementById('rrHfFindingsText').value;

  const fd = new FormData();
  fd.append('adom', adom);
  fd.append('pkg', pkg);
  if (file) {
    fd.append('findings_file', file);
  } else {
    fd.append('findings_text', text);
  }

  try {
    const resp = await fetch('/api/rule-review/ai-assist-hygiene-fix', { method: 'POST', body: fd });
    const data = await resp.json();
    runningEl.style.display = 'none';
    if (!resp.ok) {
      errEl.textContent = data.error || `Request failed (${resp.status})`;
      errEl.style.display = '';
      return;
    }
    hfSelectedOption = new Map();
    renderHygieneFixResult(data);
  } catch (e) {
    runningEl.style.display = 'none';
    errEl.textContent = 'Request failed: ' + e.message;
    errEl.style.display = '';
  }
}

document.getElementById('rrAiHygieneFixForm')?.addEventListener('submit', runHygieneFixAiAssist);
```

- [ ] **Step 4: Add the render function**

```javascript
function hfActiveOption(fix, idx) {
  const optIdx = hfSelectedOption.get(idx) ?? 0;
  return fix.options[optIdx] || null;
}

function renderHygieneFixResult(data) {
  hfLastResult = data;

  const staleEl = document.getElementById('rrHfStaleWarning');
  if ((data.stale_findings || []).length) {
    staleEl.innerHTML = '<strong>Skipped (not found in the live package):</strong><ul>' +
      data.stale_findings.map(f => `<li>${esc(f.policy_name || f.policy_id)} (${esc(f.check)}): ${esc(f.reason)}</li>`).join('') +
      '</ul>';
    staleEl.style.display = '';
  } else {
    staleEl.innerHTML = '';
    staleEl.style.display = 'none';
  }

  const container = document.getElementById('rrHfFixesContainer');
  container.innerHTML = data.fixes.map((fix, idx) => {
    const active = hfActiveOption(fix, idx);
    const radios = fix.options.length > 1
      ? '<div class="rr-hf-options">' + fix.options.map((o, oi) => `
          <label style="margin-right:1rem">
            <input type="radio" name="hf-opt-${idx}" data-fix-idx="${idx}" data-opt-idx="${oi}" ${oi === (hfSelectedOption.get(idx) ?? 0) ? 'checked' : ''}>
            ${esc(o.label)}
          </label>`).join('') + '</div>'
      : '';
    const description = active ? esc(active.description) : esc(fix.detail);
    const cliText = active && active.cli.length ? active.cli.join('\n\n') : '(no CLI -- manual review required)';
    return `
      <div class="rr-hf-fix-card" style="border:1px solid var(--border-color, #ccc);border-radius:6px;padding:.75rem;margin-bottom:.75rem">
        <div><strong>${esc(fix.policy_name)}</strong> <span class="text-muted">(id ${esc(fix.policy_id)}, ${esc(fix.check)})</span></div>
        ${radios}
        <div style="margin:.5rem 0">${description}</div>
        <pre class="rr-cli-block" data-fix-idx="${idx}">${esc(cliText)}</pre>
      </div>`;
  }).join('');

  container.querySelectorAll('input[type=radio]').forEach(radio => {
    radio.addEventListener('change', (e) => {
      const fixIdx = Number(e.target.dataset.fixIdx);
      const optIdx = Number(e.target.dataset.optIdx);
      hfSelectedOption.set(fixIdx, optIdx);
      renderHygieneFixResult(hfLastResult);
    });
  });

  const narrEl = document.getElementById('rrHfNarrative');
  const narrErrEl = document.getElementById('rrHfNarrativeError');
  if (data.narrative) {
    narrEl.textContent = data.narrative;
    narrErrEl.style.display = 'none';
  } else {
    narrEl.textContent = '';
    narrErrEl.textContent = 'AI summary unavailable: ' + (data.narrative_error || 'unknown error');
    narrErrEl.style.display = '';
  }

  document.getElementById('rrAiHygieneFixResult').style.display = '';
}
```

- [ ] **Step 5: Manually verify the mode switch and form wiring in a browser**

Start the dev server (`python wsgi.py`), log in, open `/rule-review`, click **Hygiene Fix**. Confirm: the ADOM dropdown populates, selecting an ADOM populates the Package dropdown, and the Single Change / FQDN Allowlist forms hide while Hygiene Fix's form shows. (Submitting requires a real FortiManager connection and a real findings export — covered end-to-end in Task 11.)

- [ ] **Step 6: Commit**

```bash
git add app/static/js/rule_review.js
git commit -m "$(cat <<'EOF'
feat: wire Hygiene Fix mode submit, ADOM/package loaders, and result rendering

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 10: Frontend JS — Download HTML Report

**Files:**
- Modify: `app/static/js/rule_review.js`

**Interfaces:**
- Consumes: `hfLastResult`, `hfSelectedOption`, `hfActiveOption()` from Task 9.
- Produces: click handler on `#rrHfDownloadBtn` that downloads `<pkg>_<YYYY-MM-DD>.html`.

- [ ] **Step 1: Add the download function**

```javascript
function downloadHygieneFixReport() {
  if (!hfLastResult) return;
  const dateStr = hfLastResult.generated_at.slice(0, 10);
  const title = `Hygiene Fix Report — ${hfLastResult.adom} / ${hfLastResult.pkg}`;

  const rows = hfLastResult.fixes.map((fix, idx) => {
    const active = hfActiveOption(fix, idx);
    const description = active ? active.description : fix.detail;
    const cliText = active && active.cli.length ? active.cli.join('\n\n') : '(no CLI -- manual review required)';
    return `
      <div class="finding">
        <h3>${esc(fix.policy_name)} <small>(id ${esc(fix.policy_id)}, ${esc(fix.check)})</small></h3>
        <p>${esc(description)}</p>
        <pre>${esc(cliText)}</pre>
      </div>`;
  }).join('');

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>${esc(title)}</title>
<style>
  body{font-family:sans-serif;font-size:13px;color:#1a2133;margin:1.5cm}
  h1{font-size:18px}
  h3{font-size:14px;margin-bottom:2px}
  .finding{border-bottom:1px solid #d0d7e2;padding:10px 0}
  pre{background:#f4f6f9;padding:8px;overflow-x:auto;white-space:pre-wrap}
  small{color:#5a6478}
</style></head><body>
<h1>${esc(title)}</h1>
<div>Generated ${esc(hfLastResult.generated_at)} &bull; ${hfLastResult.fixes.length} findings</div>
${rows}
</body></html>`;

  const a = document.createElement('a');
  const bl = new Blob([html], { type: 'text/html' });
  a.href = URL.createObjectURL(bl);
  a.download = `${hfLastResult.pkg}_${dateStr}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
}

document.getElementById('rrHfDownloadBtn')?.addEventListener('click', downloadHygieneFixReport);
```

- [ ] **Step 2: Manually verify the download in a browser**

With a Hygiene Fix result rendered (from Task 9's manual verification, or a mocked response entered via the browser dev console: `hfLastResult = {adom:'A', pkg:'P', generated_at:'2026-09-03T00:00:00', fixes:[{policy_id:'1', policy_name:'r1', check:'unlogged', detail:'x', options:[{label:'Enable logging', description:'d', cli:['set logtraffic all']}]}], stale_findings:[]}; renderHygieneFixResult(hfLastResult);` then click **Download HTML Report**), confirm a file named `P_2026-09-03.html` downloads and opens in a browser showing the finding, description, and CLI block.

- [ ] **Step 3: Commit**

```bash
git add app/static/js/rule_review.js
git commit -m "$(cat <<'EOF'
feat: add Hygiene Fix standalone HTML report download

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```

---

### Task 11: Documentation and end-to-end verification

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Document the new mode**

In `CLAUDE.md`, under `### Rule Validation tab` → `#### AI Assist mode`, after the existing paragraph describing `POST /api/rule-review/ai-assist-fqdn`, add:

```markdown
A third mode, **Hygiene Fix**, turns a completed Rule Hygiene run's findings
into deterministic remediations: paste or upload the findings (JSON or CSV,
from either the interactive Rule Hygiene export or a scheduled job's email
attachment) plus an ADOM + Policy Package, and `app/hygiene_fix.py`
re-fetches the live policy package, matches findings to live rules by
`policy_id` (flagging any that no longer match as "stale"), and generates
FortiOS CLI remediations per finding — every comment-changing fix appends a
`[HygieneFix YYYY-MM-DD]` traceability tag. Where a check has more than one
viable fix (Shadow: disable / reorder / narrow-scope; Over-Permissive:
disable / exempt), the engineer picks per-finding which option to use. The
LLM narrates the batch for a peer reviewer, same best-effort guarantee as
the other two modes. **Endpoint:** `POST
/api/rule-review/ai-assist-hygiene-fix` — body: `multipart/form-data` with
`adom`, `pkg`, and one of `findings_text` / `findings_file`. Results can be
downloaded as a standalone HTML report (`<package>_<date>.html`) via the
"Download HTML Report" button — client-side only, no server round trip,
same as every other export in this app. This app is read-only throughout —
every generated CLI snippet is a human-reviewed suggestion, never applied.
```

- [ ] **Step 2: Run the full test suite**

Run: `pytest tests/ -v 2>&1 | tail -60`
Expected: PASS (all tests, including the new `test_hygiene_fix.py` and `test_rule_review_ai_assist_hygiene_fix.py`)

- [ ] **Step 3: End-to-end manual verification against a real (or test) FortiManager**

Start the dev server, log in as an admin, confirm `ai_assist_enabled` is on (Admin → AI Assist). Go to `/hygiene`, run any check (e.g. Unlogged Rules) against a real ADOM/package, and export JSON. Go to `/rule-review` → AI Assist → **Hygiene Fix**, select the same ADOM + package, paste the exported JSON, submit. Confirm: fixes render with correct CLI, any multi-option finding (Over-Permissive, or a Shadow finding with an action mismatch) shows a working radio toggle that updates the CLI block live, the narrative renders (or shows a narration-error notice if AI Assist's provider isn't configured), and **Download HTML Report** produces a file named `<package>_<date>.html` with the same findings/CLI. Also verify the CSV path: export the same findings as CSV instead, paste that in, and confirm the check labels normalize correctly (per Task 7's `_normalize_check_key`).

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
docs: document Hygiene Fix AI Assist mode in CLAUDE.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KJXjnwaiJfsZe2xQa71LWW
EOF
)"
```
