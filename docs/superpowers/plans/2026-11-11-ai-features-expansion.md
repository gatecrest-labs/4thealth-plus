# AI Features Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add six LLM-narrated features (Rule Lookup explainer, Package Change Alert summaries, Zone Policy narration, executive briefing, license renewal plan, natural-language Rule Lookup input) behind the existing `ai_assist_enabled` flag, and record each in `CHANGELOG.md`.

**Architecture:** Each feature follows the repo's boundary: a deterministic engine computes the answer and the LLM only narrates it (the exception, Task 7, only *fills a form* that the deterministic engine then runs). One new shared helper, `app/ai_narrate.py`, holds the payload-cap/system-prompt/provider-call boilerplate currently copy-pasted across `hygiene_ai.py`, `pending_changes_ai.py` and others; new modules use it, old modules are not refactored.

**Tech Stack:** Flask blueprints, `app.llm.get_provider()` (`narrate` / `extract_json`), `app.app_settings.get_setting`, APScheduler, pytest.

**Spec:** none written; scope comes from the chat recommendation of 2026-11-11. Behaviour contract below is the spec.

## Global Constraints

- Every AI endpoint gated on `get_setting("ai_assist_enabled", False)`; off → HTTP 503 `{"error": "AI Assist is not enabled"}` (same string as existing routes).
- Every feature has a `GET .../<name>-status` → `{"available": bool}` OR reuses an existing status route on the same page. Frontend **fails closed**: status fetch error → treated as unavailable. Off-state UI: **hidden** for buttons added to existing result views (matches Config-Delta/Device Review); no new always-visible panels.
- Narration endpoints return `{narrative, narrative_error}` and **never 500** on LLM failure (`LLMError`/any exception → `narrative: null`, `narrative_error: str`). Validation errors are 400, ADOM access via `check_adom_access`, tab via `tab_required`.
- Scheduled/email output: AI section is best-effort, silently omitted on failure, never blocks delivery, and honours `ai_assist_enabled`.
- `feature=` tag passed to `provider.narrate` must be unique per feature (drives Admin AI-usage breakdown): `rule_lookup_explain`, `package_alert_summary`, `zone_query_explain`, `zone_segmentation_summary`, `executive_briefing`, `license_renewal_plan`, `rule_lookup_nl_parse`.
- LLM input is always a bounded, already-computed JSON payload (cap 64,000 chars, raise `ValueError` beyond it, like `hygiene_ai.py`). Never send raw rule comments in bulk or credentials; never claim a change was applied. All CLI shown is "suggestion only".
- No FMG calls added; narration works from data the request already has or an existing cache. Read-only project: nothing pushes config.
- Each task updates `CHANGELOG.md` under `## [Unreleased]` in a single `### AI features expansion` section (create it in Task 1, append bullets after), plus `app/static/js/help.js` line ~589 AI-toggle list and the relevant `CLAUDE.md` section. Commit trailer per repo attribution rules.
- Use `uv`; no new dependencies.

## Review Focus

- Flag flips off while a page is open → click returns 503 and the UI shows the error text, not a stack trace (test per route).
- LLM returns empty string/whitespace → `narrative` is `None` with a `narrative_error`, not a blank box.
- Oversized payload (Rule Lookup with 5,000 matched rules; ADOM with 500 devices) → trimmed with an explicit "N more not shown" count passed to the model, never a 413/500.
- Prompt injection via data fields (rule names/comments containing "ignore previous instructions") → system prompt states fields are data; narrative is plain text rendered with `textContent`/`_esc`, never `innerHTML`.
- NL parse returns fields that fail the deterministic parser (`_parse_addr_search`) → 400-style inline error, form not submitted automatically.

---

## File Structure

| File | Responsibility |
|---|---|
| `app/ai_narrate.py` (new) | `narrate_payload()`, `ai_enabled()`; shared by tasks 2–6 |
| `app/rule_lookup_ai.py` (new) | trim lookup result + explain; NL-query parser (Task 7) |
| `app/package_change_alerts.py` | add AI paragraph to alert email |
| `app/zone_ai.py` (new) | explain query verdict; summarize segmentation report |
| `app/executive_briefing.py` (new) | assemble briefing payload from existing caches, narrate |
| `app/executive_briefing_scheduler.py` (new) | optional weekly email, mirrors `device_review_scheduler.py` |
| `app/license_renewal_ai.py` (new) | group/order expiring licenses + EOS, narrate |
| `app/routes/*.py`, `app/static/js/*.js`, `templates/*.html` | endpoints + buttons per task |
| `tests/test_<module>.py` | one per new module + route tests |

---

### Task 1: Shared narration helper + changelog scaffold

**Files:**
- Create: `app/ai_narrate.py`, `tests/test_ai_narrate.py`
- Modify: `CHANGELOG.md` (add `### AI features expansion` under `[Unreleased]`)

**Interfaces:**
- Produces:
  - `ai_enabled() -> bool` (wraps `get_setting("ai_assist_enabled", False)`)
  - `narrate_payload(system_prompt: str, payload: dict, *, feature: str, user: str | None = None, max_chars: int = 64_000) -> str` — json-dumps with `default=str`, raises `ValueError` if over cap, calls `get_provider().narrate`, raises `LLMError` on blank result.
  - `safe_narrate(system_prompt, payload, *, feature, user=None) -> tuple[str | None, str | None]` returning `(narrative, error)`; never raises. Routes use this.

- [ ] **Step 1: Write failing tests** in `tests/test_ai_narrate.py`: `test_oversize_payload_raises_value_error`, `test_blank_completion_becomes_llm_error`, `test_safe_narrate_returns_error_tuple_on_provider_failure` (patch `app.llm.get_provider` to a stub whose `narrate` raises `LLMError("boom")`; assert `(None, "boom")`), `test_safe_narrate_passes_feature_and_user` (stub records kwargs).
- [ ] **Step 2: Run** `uv run pytest tests/test_ai_narrate.py -v` → FAIL (module missing).
- [ ] **Step 3: Implement** `app/ai_narrate.py` per signatures above; import `get_provider` lazily inside the function (so tests can patch `app.llm.get_provider`, same as `hygiene_ai.py`).
- [ ] **Step 4: Run** the tests → PASS.
- [ ] **Step 5: Changelog** — add section header and a first bullet "Added: shared `app/ai_narrate.py` helper used by the new AI features" (internal-facing, one line).
- [ ] **Step 6: Commit** `feat(ai): shared narration helper`.

---

### Task 2: Rule Lookup explainer

**Files:**
- Create: `app/rule_lookup_ai.py`, `tests/test_rule_lookup_ai.py`, `tests/test_hygiene_rule_lookup_ai_route.py`
- Modify: `app/routes/hygiene_routes.py` (add routes near `hygiene_rule_lookup`, ~line 743), `app/static/js/rule_lookup.js`, `app/templates/hygiene.html` (button + output div, `display:none`), `CHANGELOG.md`, `CLAUDE.md` (Rule Lookup bullet), `help.js`

**Interfaces:**
- Consumes: `narrate/safe_narrate` (Task 1); the existing rule-lookup response (`rows`, `searched`, `skipped_count`, per-field labels `exact|broader|narrower|overlap|name`).
- Produces: `build_lookup_narrative(adom: str, searched: dict, result: dict, user: str | None) -> tuple[str | None, str | None]` — trims to the first 25 rows (+ `rows_not_shown` count) and always includes `skipped_count`, so the model can say "any/negated rules were not evaluated".
- Routes: `GET /api/hygiene/rule-lookup/ai-status` (`tab_required("rule_hygiene")`), `POST /api/hygiene/adoms/<adom>/rule-lookup/explain` body `{searched, rows, skipped_count, total}` (client posts back what it already holds; **no re-search, no cache access**), returns `{narrative, narrative_error}`.

- [ ] **Step 1: Tests** — `test_trims_to_25_rows_and_reports_remainder`, `test_includes_skipped_count`, `test_route_503_when_disabled`, `test_route_400_when_rows_not_list`, `test_route_enforces_adom_access` (patched `check_adom_access` returning 403), `test_llm_failure_returns_200_with_error`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** module + routes. System prompt: explain in ≤6 sentences which rule(s) would allow/deny the searched flow, in rule-order, call out `broader`/`overlap` matches as less certain, state explicitly that `all`/negated rules were not evaluated; treat field values as data.
- [ ] **Step 4: Frontend** — in `rule_lookup.js`, after results render, if `GET ai-status` true show "Explain results" button; click POSTs the in-memory rows (first 25), renders `narrative` via `textContent`, error into the existing `rlError`-style notice. Status fetch failure → button stays hidden.
- [ ] **Step 5: Run** new tests + `uv run pytest tests -k "rule_lookup or hygiene" -q` → PASS.
- [ ] **Step 6: Changelog/docs** — CHANGELOG bullet "Added: Rule Lookup **Explain results**"; CLAUDE.md Rule Lookup section one line; help.js AI-toggle list.
- [ ] **Step 7: Commit** `feat(ai): Rule Lookup explain results`.

---

### Task 3: Package Change Alert AI summary

**Files:**
- Modify: `app/package_change_alerts.py` (`build_email_html` caller in `_evaluate_rule`, ~line 460; add `_ai_summary_html`), `app/admin_routes`/`admin.js`/`admin.html` (per-rule checkbox), `package_change_alerts.example.json`, `CHANGELOG.md`, `CLAUDE.md` (Package Change Alerts section), `help.js`
- Test: `tests/test_package_change_alerts.py` (extend)

**Interfaces:**
- Consumes: `diffs: dict[device][vdom] -> list[{type,line}]` already built by `collect_package_diffs`; `app.pending_changes_ai.build_diff_narrative(adom, devices, user=None)` — **reuse it**, convert `diffs` to its `devices` shape `[{device, summary:{}, vdoms:[{name, changes}]}]`. Do not write a new prompt.
- Produces: rule field `ai_summary_enabled` (default `true`, validated in `_validate_rule_fields`, persisted like the Config-Delta job field); `_ai_summary_html(adom, pkg, diffs, enabled) -> tuple[str, str | None]` mirroring `config_diff_scheduler._build_ai_narrative_html`; `build_email_html(..., ai_html: str = "")` inserts it after the intro paragraph; `runs[]` entry gets `ai_narrative_error` on failure.

- [ ] **Step 1: Tests** — `test_email_includes_ai_section_when_enabled` (patch `build_diff_narrative` → "X"; assert `AI Summary` and escaped text in HTML), `test_ai_section_omitted_when_flag_off`, `test_ai_section_omitted_when_rule_opts_out`, `test_narration_failure_still_sends_and_records_error`, `test_narrative_html_is_escaped` (text `<script>`), `test_dedupe_hash_unchanged_by_ai` (hash must not include narrative).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Narrate once per package, only if `diffs` non-empty (already guaranteed at that point).
- [ ] **Step 4: Admin UI** — "AI Summary" checkbox in the Package Change Alerts rule form (`pca*` functions in `admin.js`), default checked; include in create/update payload.
- [ ] **Step 5: Run** `uv run pytest tests/test_package_change_alerts.py tests/test_admin_package_alerts_routes.py -v` → PASS.
- [ ] **Step 6: Changelog/docs**, **Step 7: Commit** `feat(ai): AI summary in Package Change Alert emails`.

---

### Task 4: Zone Policy narration (verdict + segmentation health)

**Files:**
- Create: `app/zone_ai.py`, `tests/test_zone_ai.py`, `tests/test_zone_ai_routes.py`
- Modify: `app/routes/zone_routes.py`, `app/static/js/zone_policy.js`, `app/templates/zone_policy.html`, `CHANGELOG.md`, `CLAUDE.md` (Zone Policy section), `help.js`

**Interfaces:**
- Consumes: `zdb.run_query(...)` result (verbose, with governing rules) and `zdb.compute_segmentation_report(db)` result — both passed back by the client from what it already rendered, **or** recomputed server-side for the segmentation case (cheap, no FMG) so the model never sees client-edited data.
- Produces: `explain_query(results: list[dict], user=None) -> tuple[str|None, str|None]` (caps 20 flow results); `summarize_segmentation(report: dict, user=None) -> tuple[...]` (top 15 open pairs by severity + all trust-boundary mismatches, plus counts).
- Routes (`tab_required("zone_policy")`): `GET /api/zone/ai-status`, `POST /api/zone/query/explain` body `{src, dst, service}` — **re-runs `zdb.run_query` server-side** and narrates that, ignoring any client-supplied verdict; `POST /api/zone/segmentation-report/summarize` (no body; computes report itself). Both return `{narrative, narrative_error}`; 503 if `policy_db.json` missing / AI off.

- [ ] **Step 1: Tests** — `test_explain_runs_query_server_side` (patch `zdb.run_query`, assert LLM payload contains its verdict, not a posted one), `test_explain_caps_results_at_20`, `test_segmentation_payload_orders_mismatches_first`, `test_503_when_ai_disabled`, `test_503_when_db_missing`, `test_never_500_on_llm_error`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** Prompt: explain the ALLOWED/BLOCKED/UNKNOWN verdict citing the governing rule per the documented precedence (block all > block only > allow only > allow all > implicit UNKNOWN); for segmentation, list the three highest-risk items and a suggested order of remediation, no CLI.
- [ ] **Step 4: Frontend** — "Explain" button under Query Flow results; "Summarize with AI" under Segmentation Health; both hidden unless `ai-status` true.
- [ ] **Step 5: Run** zone tests (`-k zone`) → PASS. **Step 6: Changelog/docs. Step 7: Commit** `feat(ai): Zone Policy verdict explanation and segmentation summary`.

---

### Task 5: Executive briefing (on demand + weekly email)

**Files:**
- Create: `app/executive_briefing.py`, `app/executive_briefing_scheduler.py`, `executive_briefing.example.json`, `tests/test_executive_briefing.py`, `tests/test_executive_briefing_routes.py`
- Modify: `app/__init__.py` (register scheduler beside the other background schedulers), `app/routes/admin_routes.py` (+ `admin.html`/`admin.js` sub-section under Scheduled), `.gitignore` (`executive_briefing.json`), `docker-compose.yml` only if the file must be shared with the collector (see note), `CHANGELOG.md`, `CLAUDE.md`, `help.js`

**Interfaces:**
- Consumes: the same data the executive summary payload uses. **Refactor, don't duplicate:** extract the payload-assembly body of `ext_executive_summary` (`app/routes/external_api_routes.py:460-495`) into `build_executive_payload() -> dict` (same module or `app/executive_payload.py`), leave the route calling it, and keep the response byte-identical (existing `tests/test_external_api_executive.py` must still pass untouched).
- Produces:
  - `build_briefing(payload: dict, previous: dict | None, user=None) -> tuple[str | None, str | None]` — sends only numeric/status fields (hygiene score, compliance %, pending diffs, online/total, backup stale/never, license expiring 30/60/90, PSIRT counts, HW-EOS counts, silent devices, freshness flags) plus a week-over-week delta computed **deterministically** in Python from `previous` (stored last payload); model told to cite figures verbatim and to flag any section whose `freshness` says stale.
  - Config file `executive_briefing.json` `{enabled, day, time, email, last_payload}` atomic via `app/atomic_io.py`; `executive_briefing_scheduler.start()/reload()` mirrors `device_review_scheduler.py`.
  - Routes (`admin_required`): `GET/PUT /admin/api/executive-briefing`, `POST /admin/api/executive-briefing/generate` → `{narrative, narrative_error, deltas}` (on-demand; does not send email), `POST .../send-now`.

- [ ] **Step 1: Tests** — `test_deltas_computed_without_llm` (previous vs current → exact diffs), `test_payload_contains_no_infra_hostnames_or_tokens` (assert keys allow-list; `infra` list excluded), `test_stale_freshness_flagged_in_payload`, `test_scheduled_run_skipped_when_ai_off`, `test_email_sent_with_deterministic_table_even_if_narration_fails`, `test_last_payload_saved_only_after_send`, `test_external_executive_summary_unchanged` (existing test).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** refactor first (green on existing tests), then briefing module, then scheduler.
- [ ] **Step 4: Email** — deterministic KPI table first (always sent), AI narrative second (best-effort), same shape as `device_review_scheduler` reports. Uses `smtp_client.send_email`.
- [ ] **Step 5: Admin UI** — Admin → Scheduled → "Executive Briefing": enabled, weekday, time, recipients, **Generate preview** button (shows narrative inline), **Send now**. Section hidden when AI off (mirror `checkHostMetricsAiAvailability`).
- [ ] **Step 6: Collector note** — jobs that run in the collector need the config file visible there; follow the Package Change Alerts precedent (bind-mount in `docker-compose.yml` for both services) and note in CLAUDE.md. Verify where `config_diff_scheduler` runs and register this scheduler in the same process.
- [ ] **Step 7: Run** `uv run pytest tests -k "executive or briefing" -q` → PASS. **Step 8: Changelog/docs. Step 9: Commit** `feat(ai): executive briefing`.

---

### Task 6: License & lifecycle renewal plan

**Files:**
- Create: `app/license_renewal_ai.py`, `tests/test_license_renewal_ai.py`
- Modify: `app/routes/api_routes.py` (next to `/api/devices/all/license`), `app/static/js/versions.js`, `app/templates/versions.html`, `CHANGELOG.md`, `CLAUDE.md` (Device Versions tab), `help.js`

**Interfaces:**
- Consumes: `license_status_cache.get_latest()["all_devices"]`, `compute_expiring_soon(all_devices)`, and hardware-EOS data from the lifecycle source used by `_lifecycle()` in `external_api_routes.py` (reuse, don't re-derive).
- Produces: `build_renewal_buckets(all_devices, lifecycle, as_of: date | None = None) -> dict` — **deterministic**: per-ADOM groups, ordered by soonest of (license expiry, HW EOS), each device tagged `expired|<=30|<=60|<=90|eos_12m`; `build_renewal_plan(buckets, user=None) -> tuple[str|None, str|None]` caps at 40 devices detailed + counts for the rest.
- Route: `POST /api/devices/all/license/renewal-plan` (`tab_required("versions")`, body `{adom?: str}`; with `adom` → `check_adom_access`; without → filter to accessible ADOMs exactly as `/api/devices/all/license` does) returns `{buckets, narrative, narrative_error}` — **buckets are returned even when AI is off or fails**, so the deterministic ordering is useful on its own; the button itself is hidden when AI is off (status via `GET /api/devices/all/license/ai-status`).

- [ ] **Step 1: Tests** — `test_buckets_ordered_soonest_first`, `test_expired_devices_first_and_tagged`, `test_eos_and_license_both_considered`, `test_adom_filter_respects_access` (restricted group sees only allowed ADOMs), `test_caps_40_devices_with_remainder_count`, `test_as_of_injection_is_deterministic`.
- [ ] **Step 2–4: Run fail → implement → pass.** Prompt: propose a renewal order and batching per ADOM, say which are most urgent and why, never state prices or contract terms (not in the data).
- [ ] **Step 5: Frontend** — "Renewal plan" button in License Status section; export of the plan reuses the section's existing CSV/JSON/PDF pattern if it applies to bucket rows, otherwise text only (decide at implementation; don't add a new export type).
- [ ] **Step 6: Changelog/docs. Step 7: Commit** `feat(ai): license renewal plan`.

---

### Task 7: Natural-language Rule Lookup input (confirm-before-run)

**Files:**
- Modify: `app/rule_lookup_ai.py` (add parser), `app/routes/hygiene_routes.py`, `app/static/js/rule_lookup.js`, `app/templates/hygiene.html`, `CHANGELOG.md`, `CLAUDE.md`, `help.js`
- Test: `tests/test_rule_lookup_ai.py` (extend), `tests/test_hygiene_rule_lookup_ai_route.py` (extend)

**Interfaces:**
- Consumes: `provider.extract_json(...)` (as `app/psirt/extract.py` does); existing deterministic validators `_parse_addr_search` and `rule_lookup.parse_port_query` in `hygiene_routes.py`.
- Produces: `parse_nl_query(text: str, user=None) -> dict` returning `{src, dst, port}` strings (each possibly empty) — raises `ValueError` if text > 500 chars or if all three come back empty; **post-validates** each non-empty field with the same parsers the search route uses and raises `ValueError` naming the field that failed, so a hallucinated value never reaches the form. Route `POST /api/hygiene/rule-lookup/parse` body `{text}` → `{src, dst, port}` or 400 `{error}`; 503 when AI off. It **never runs the search**.
- UI: a text box "Describe what you're looking for" above the existing three inputs (hidden when AI off); on parse success the three fields are **filled and highlighted**, the user presses the existing Search button. Shows "Parsed as: …" so the mapping is visible.

- [ ] **Step 1: Tests** — `test_valid_parse_returns_three_fields` (stub `extract_json` → `{"src":"10.1.0.0/16","dst":"grp-DB*","port":"tcp/3306"}`), `test_invalid_ip_from_model_rejected_with_field_name`, `test_all_empty_rejected`, `test_over_500_chars_rejected`, `test_route_never_calls_search` (patch `rule_lookup.search`, assert not called), `test_503_when_ai_disabled`, `test_injection_text_cannot_add_extra_keys` (model returns extra `"cmd"` key → ignored).
- [ ] **Step 2–4: Fail → implement → pass.** System prompt lists the exact accepted syntaxes (IP, CIDR, netmask, wildcard `10.1.*.*`, name pattern, `tcp/443`, range, service name) and forbids inventing names not present in the user's text.
- [ ] **Step 5: Frontend** wiring; fail-closed status.
- [ ] **Step 6: Changelog/docs. Step 7: Commit** `feat(ai): natural-language Rule Lookup input`.

---

### Task 8: Wrap-up

- [ ] **Step 1:** Run the full suite `uv run pytest -q`; expect no new failures (note any pre-existing ones separately).
- [ ] **Step 2:** Manual check with `ai_assist_enabled` **off**: every new button/section absent, every new endpoint 503. Then **on** with a stub/real provider: each feature produces output; kill the provider URL → each shows the inline error and the page keeps working.
- [ ] **Step 3:** Confirm `CHANGELOG.md` `### AI features expansion` lists all six features plus the helper, the refactor in Task 5, and new files/config (`executive_briefing.json`, `ai_summary_enabled` on alert rules).
- [ ] **Step 4:** `graphify update .`; final commit.

## Self-Review Notes

- **Coverage:** features 1–6 from the recommendation ↔ Tasks 2, 3, 4, 5, 6, 7 (recommendation #3 split into verdict + segmentation inside Task 4). Changelog updated in every task and verified in Task 8.
- **Types:** `safe_narrate` returns `(narrative, error)` everywhere; Task 3 reuses `build_diff_narrative` instead of a new prompt; `feature=` tags are listed once in Global Constraints.
- **Risk ordering:** Tasks 2–4 are low risk; Task 5 includes a refactor of the external executive route (guarded by existing tests); Task 7 is last because it is the only one where model output feeds input.
- **Open decisions flagged for the implementer, not assumed:** where the briefing scheduler runs (web vs collector, Task 5 Step 6) and whether the renewal plan gets an export (Task 6 Step 5).
