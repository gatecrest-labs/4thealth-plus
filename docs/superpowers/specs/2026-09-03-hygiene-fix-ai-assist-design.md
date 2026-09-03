# Hygiene Fix AI Assist — Design

## Context

Rule Hygiene (`app/hygiene.py`, `/hygiene` page) runs 9 read-only checks
against a policy package and reports findings — it never proposes or
generates a remediation. Rule Validation's AI Assist panel
(`app/planner/`, `/rule-review` page) already has two single-request
"compute deterministically, narrate with an LLM" modes: **Single Change**
(`plan_change()`) and **FQDN Allowlist** (`plan_fqdn_change()`, see
[2026-08-17-fqdn-allowlist-ai-assist-design.md](2026-08-17-fqdn-allowlist-ai-assist-design.md)).

This design adds a third mode, **Hygiene Fix**: an engineer pastes or
uploads the findings from a completed Rule Hygiene run (interactive export
or scheduled-job attachment) and gets back, per finding, a deterministic
remediation (FortiOS CLI + an updated comment) they can review, adjust,
and download as a standalone HTML report.

The hygiene export's finding records only carry `policy_id`, `policy_name`,
`seq`, `check`, `detail` (plus embedded rule summaries for `shadow` and
`redundant` findings only — see `app/hygiene.py::check_shadow`/
`check_redundant_rules`). Several of the requested fix rules need full live
rule fields (source/destination objects, group membership, the current
comment text) that aren't in that export. So Hygiene Fix re-fetches the
live policy package from FortiManager and cross-references it against the
pasted findings by `policy_id`, rather than working from the export alone.

## Decisions

**1. Third mode inside the existing AI Assist panel, not a new tab.**
Same section (`rrAiAssistSection`), same `ai_assist_enabled` gate, same
mode-toggle pattern as the existing two buttons — add `Hygiene Fix`
alongside `Single Change` / `FQDN Allowlist`. Follows precedent set by
FQDN Allowlist's own design (decision 1 there).

**2. New backend module `app/hygiene_fix.py` — purely deterministic.**
No FMG calls, no LLM calls inside this module; it's a pure function
library, mirroring the compute/narrate split used by `app/planner/` and
`app/hygiene_ai.py`. Public entry point:

```python
def build_fixes(
    live_policies: list[dict],
    pasted_findings: list[dict],
    now: datetime | None = None,
) -> HygieneFixResult:
    ...
```

`HygieneFixResult` = `{fixes: list[PolicyFix], stale_findings: list[dict]}`.
`PolicyFix` = `{policy_id, policy_name, check, options: list[FixOption]}`.
`FixOption` = `{option_id, label, description, cli: list[str], new_comment: str | None}`.

One private generator function per check key (`_fix_unnamed`,
`_fix_shadow`, `_fix_unhit`, `_fix_missing_security_profile`,
`_fix_over_permissive`, `_fix_redundant`, `_fix_expired`, `_fix_disabled`,
`_fix_unlogged`), dispatched via a `_FIX_FNS` dict keyed by `check`,
mirroring `app/hygiene.py`'s own `_CHECK_FNS` dispatch pattern. A finding
whose `check` key has no registered generator (defensive — shouldn't
happen given the fixed `CHECKS` set) is skipped, not an error.

**3. Traceability tag for every comment-appending fix: `[HygieneFix
YYYY-MM-DD]`.**
Any fix that disables a rule or otherwise annotates it appends this exact
tag to the end of the rule's existing comment (space-separated), truncated
to FortiOS's 255-character comment field limit if needed (truncate the
*original* comment content, never the tag itself, so the tag is always
present and parseable). A dedicated helper `_append_tag(comment: str,
today: date) -> str` and its inverse `_find_tag(comment: str) -> date |
None` (regex `\[HygieneFix (\d{4}-\d{2}-\d{2})\]`) live in
`hygiene_fix.py` and are shared by every generator that needs to read or
write the tag — this is what makes `disabled`'s 90-day-age check possible
without guessing at arbitrary human-written dates in the comment.

**4. Per-check fix logic:**

| Check | Behavior | Options |
|---|---|---|
| `unnamed` | If src or dst resolves to a specific, non-`any`/`all` address or address-group name, suggest name `"Allow <src> to <dst>"` (truncated to FortiOS's 35-char name limit, first src/dst name used if multiple). Otherwise name = `"Unknown -- Requires additional research"`. Always appends the date tag to the comment. CLI: `set name`, `set comments`. | 1 |
| `shadow` | Uses the finding's own `shadow_rule`/`shadowing_rule` summaries (already embedded in the pasted export) plus the live rule. Option A (always): disable the shadowed rule + date tag. Option B (only if `shadow_rule.action != shadowing_rule.action`): reorder — CLI to move the shadowed policy above the shadowing policy (FortiOS `move <id> before <id>`). Option C (only if the two rules' scopes are covering but not identical — i.e. not also a `redundant` finding): narrow the shadowing rule's scope by removing the shadowed rule's specific src/dst/service members from it, described as a proposed diff (best-effort CLI; if the shadowing rule's scope is a single `any`/group member that can't be safely split automatically, the option is still shown but its `cli` is empty and `description` says manual editing is required). | 1–3, order A/B/C |
| `unhit` | Disable + date tag. CLI: `set status disable`, `set comments`. | 1 |
| `missing_security_profile` | No CLI. `description` restates the existing `detail` and explicitly says no automated fix is offered. | 0 (informational only — `options: []`) |
| `over_permissive` | Option A: disable + date tag. Option B: append `[HygieneFix EXEMPT YYYY-MM-DD]` to the comment (same tag helper, `EXEMPT` marker inserted before the date) with no other CLI change — i.e. the rule stays as-is but is now flagged reviewed-and-accepted. | 2, user picks per finding |
| `redundant` | Always targets the later (redundant) rule per `check_redundant_rules`'s own semantics — disable + date tag. CLI references `duplicate_of` from the finding for the description text ("redundant with rule '<name>' (id <id>)"). | 1 |
| `expired` | Disable + date tag. | 1 |
| `disabled` | Read the live rule's comment via `_find_tag`. No tag found → propose adding today's tag (comment-only CLI, rule stays disabled). Tag found and `(now - tag_date).days > 90` → propose `delete <id>` CLI instead (no comment edit — the rule is going away). Tag found and ≤90 days old → `options: []`, `description` states no action needed yet, with the days-remaining count. | 0 or 1, varies by branch |
| `unlogged` | CLI: `set logtraffic all`. No comment change (logging state isn't the kind of thing that needs a review-audit-trail tag). | 1 |

All CLI blocks are wrapped in the same `config firewall policy` / `edit
<id>` / `next` / `end` framing as `app/planner/cli_gen.py` produces
elsewhere in this app, for visual consistency across all three AI Assist
modes.

**5. Stale-finding detection.**
Before dispatching to fix generators, every pasted finding's `policy_id`
is looked up in the freshly-fetched live package (keyed by `str(policyid)`,
matching the string-cast convention `app/hygiene.py` already uses).  Not
found → added to `stale_findings` (echoing the original finding plus a
`reason: "policy_id not found in live package — may have been deleted or
renumbered since the hygiene run"`) and excluded from `fixes`. This can't
be perfect (a renumbered-but-still-present rule looks identical to a
deleted one from just an ID mismatch) but catches the common case and
surfaces it rather than silently generating CLI against a rule that no
longer exists.

**6. New endpoint: `POST /api/rule-review/ai-assist-hygiene-fix`.**
Body: `multipart/form-data` (to support both a pasted-text field and an
optional file upload, matching the existing FQDN route's dual-input
handling) with fields `adom`, `pkg` (package path, from the same
adom/package selector already on the page), `findings_text` (raw
pasted JSON or CSV) and/or `findings_file` (an uploaded `.json`/`.csv`).
Exactly one of `findings_text`/`findings_file` must be non-empty; if both
are present the file wins (matches the existing FQDN "file overrides
manual rows" convention). Parsing:
- `.json` / JSON text → `json.loads`, then accept either a bare list of
  finding dicts or the full export envelope (`{findings: [...], ...}`) —
  both the interactive export and the scheduler's `.json` attachment
  produce the latter shape.
- `.csv` / CSV text → `csv.DictReader`, expecting the same five columns
  the existing CSV export/attachment writes (`Policy ID, Policy Name,
  Seq, Check, Detail`); shadow/redundant rule-summary detail isn't
  present in CSV, so Shadow's options B/C and Redundant's `duplicate_of`
  description text degrade to a generic phrasing when parsed from CSV
  (still functionally correct, just less detailed prose).

Route logic: `check_adom_access(adom)` (same as every other ADOM-scoped
route) → parse findings → `FMGClient.get_policies(adom, pkg)` for live
data → `hygiene_fix.build_fixes(...)` → best-effort LLM narration
(`feature="rule_review_ai_assist_hygiene_fix"`) → response `{adom, pkg,
generated_at, stale_findings, fixes, narrative, narrative_error}`. Error
handling matches the other two modes exactly: malformed paste/file → 400;
`FMGError` → 502; unexpected → 500 via the existing
`internal_api_error`/`upstream_api_error` helpers; narration failure never
drops the deterministic result.

**7. LLM narration: same pattern, hygiene-fix-specific system prompt.**
One `get_provider().narrate()` call summarizing the batch (counts by
check, notable items like an upcoming rule deletion) for a peer reviewer,
built from a `to_hygiene_fix_report_payload()` helper in
`hygiene_fix.py` mirroring `to_fqdn_report_payload()`. The narrative
reflects the *default* selected option per finding (first option in each
`options` list) — if the user changes a per-finding radio client-side
after the narrative is generated, the CLI/description update live but the
prose isn't regenerated, matching the existing modes' behavior (a
resubmit is required to re-narrate; not a new pattern).

**8. Frontend: mode toggle, paste/upload form, per-finding option
radios.**
`rule_review.html`/`rule_review.js`: third toggle button; its form has
ADOM + Package dropdowns (reusing the page's existing selector JS), a
`<textarea>` for paste, and a file input for upload (same "file overrides
manual" convention as FQDN). Results render one card per finding: check
label, policy name/id, and — where `options.length > 1` — a radio group
to pick the active option; the card's CLI `<pre>` block and description
update to reflect the selected option. A `stale_findings` warning banner
lists any skipped findings. Copy-all-CLI and the narrative panel reuse
existing chrome. **Download HTML Report** button (client-side, `Blob`,
no round trip — same as every other export in this app) serializes the
*currently selected* option per finding into a standalone HTML file:
finding, one-line description, and a `<pre>` CLI block, filename
`<pkg>_<YYYY-MM-DD>.html`.

**9. Testing.**
`tests/test_hygiene_fix.py`: one test per generator's happy path plus its
documented edge cases —
`unnamed` with/without a resolvable src or dst reference,
`shadow` with matching vs. differing actions (option B) and identical vs.
merely-covering scopes (option C),
`disabled` with no tag / tag ≤90 days / tag >90 days,
`over_permissive` returning both options,
plus route-level tests for: stale `policy_id` skip-and-warn, JSON-envelope
vs. bare-list vs. CSV parsing, and the file-overrides-text precedence
rule.

## What This Delivers

A third **Hygiene Fix** mode on the Rule Validation tab's AI Assist panel:
1. Engineer selects ADOM + Package, pastes or uploads a completed Rule
   Hygiene run's findings (JSON or CSV, from either the interactive export
   or a scheduled job's email attachment).
2. 4THealth+ re-fetches the live policy package, matches findings to live
   rules by `policy_id`, flags any that no longer match, and — for every
   matched finding — deterministically computes one or more remediation
   options (FortiOS CLI + an updated comment carrying a `[HygieneFix
   YYYY-MM-DD]` traceability tag wherever a comment change is proposed).
3. Where a check has more than one viable remediation (Shadow,
   Over-Permissive), the engineer picks per-finding which option to use;
   the CLI and description update live.
4. The structured result is sent to the configured LLM for a one-shot
   peer-review narrative, following the same never-lose-the-plan
   guarantee as the other two AI Assist modes.
5. The engineer downloads a self-contained HTML report (named
   `<package>_<date>.html`) listing every finding, its fix description,
   and copy-pasteable CLI.

Rule Hygiene itself (`/hygiene` page, `app/hygiene.py`'s checks), the
existing Single Change and FQDN Allowlist AI Assist modes, and the
scheduled Rule Hygiene job are all unaffected — this is purely additive,
consuming their existing output as input.

## Explicitly Out of Scope

- Any change to `app/hygiene.py`'s check logic or finding shape — Hygiene
  Fix consumes findings as they already exist today.
- Actually applying any generated CLI to FortiManager/devices — this app
  is read-only throughout (per `CLAUDE.md`); every output here is a
  human-reviewed, copy-pasted suggestion, same as every other CLI-gen
  path in this app.
- Parsing the scheduled job's HTML email report directly (its content is
  a per-host/per-check summary table, not a per-finding list — not a
  useful input shape for this feature). JSON and CSV attachments/exports
  are the supported inputs.
- Automatically re-running Rule Hygiene to get fresh findings — the
  engineer supplies an already-completed run's output; this feature only
  re-fetches live *policy* data, not live *findings*.
- Persisting Hygiene Fix results anywhere — same one-off, no-persistence
  pattern as every other AI Assist analysis in this app.
