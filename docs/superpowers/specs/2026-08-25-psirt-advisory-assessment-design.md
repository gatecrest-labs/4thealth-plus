# PSIRT Advisory Assessment — Design

Date: 2026-08-25
Status: Approved for implementation planning

## Problem

Fortinet sends PSIRT advisory notification emails for newly disclosed
vulnerabilities. Today, triaging one requires an engineer to manually read
the advisory, figure out which FortiGate/FortiManager systems in the fleet
run an affected version, check whether a documented workaround is already
in place, and decide whether the fleet needs a config change, a firmware
upgrade, or nothing at all — with priority informed by exploitability, not
just CVSS. This is slow, inconsistent, and easy to under-prioritize when an
advisory doesn't clearly state real-world exploitation.

`~/code/github/ai/4tanalyst` already solved this as a set of MCP tools
orchestrated by a Claude Code skill (`analyze-psirt`). That architecture
doesn't transplant directly: 4tanalyst's `parse_advisory` tool does **not**
call an LLM itself — the calling Claude Code agent reads the email in its
own conversational context and passes structured fields in. 4THealth+ is a
web app with no such agent in the loop, so the LLM-extraction step has to
become a real server-side API call. Everything downstream of extraction
(version matching, workaround verification, priority scoring, and the HTML
report itself) is deterministic Python in the source — that part ports
close to verbatim, the same way `app/planner/` was ported from
4tanalyst's `planner/` for Rule Validation's AI Assist.

## Goals

- New **PSIRT Advisory Assessment** section on the Device Review tab.
- User selects an ADOM (or all ADOMs accessible to them) and supplies a
  PSIRT advisory — paste the email text or upload a `.eml`/`.txt` file.
- An LLM call extracts structured advisory fields (CVE IDs, affected
  version ranges, workaround text, severity, exploitation language) into
  an **editable review form** the user confirms or corrects before the
  scan runs — this replaces 4tanalyst's "ask the engineer for the missing
  field" conversational loop, which has no equivalent in a web UI.
- Deterministically, per device: compare firmware against the advisory's
  affected ranges, check whether any documented workaround is already
  applied via live FortiManager config, and assign one of **no action /
  configuration change required / upgrade required / unknown needs manual
  check**.
- Compute priority deterministically from CVSS band, Fortinet's own
  exploitation wording, CISA KEV catalog membership, and whether the fleet
  is actually exposed.
- Render a self-contained HTML report per assessment.
- Best-effort enrichment against fortiguard.com and the CISA KEV feed,
  gated by an opt-out `.env` flag for restricted/air-gapped deployments.
- Follow this repo's core rule (same as `app/planner/`): the LLM only
  extracts unstructured text into structured fields; every verdict,
  version comparison, and score is computed by deterministic Python.

## Non-goals (v1)

- No automated remediation — no CLI/config is generated or pushed.
  Analysis only.
- No mailbox polling — intake is paste or a user-supplied file upload.
- No FortiSwitch/FortiAP/FortiAnalyzer version matching — advisories
  naming those products are reported as "out of scope, review manually."
  Only FortiGate (FortiOS) and FortiManager itself are matched.
- No guessing on ambiguous input — malformed advisory extraction,
  unparseable version ranges, and unrecognized workaround text all
  surface explicitly rather than defaulting to a verdict.
- No disposition/audit-trail persistence — this is a one-off analysis,
  like NAT Lookup or Rule Validation's AI Assist. 4tanalyst's
  `feedback_mcp` audit trail has no equivalent here and isn't being added.
- No second LLM pass over the finished report — the HTML report is pure
  deterministic templating from the assessment data, matching what the
  source actually does (not what its skill's chat presentation implied).

## Architecture & data flow

```
PSIRT email (paste or file upload)
        │
   POST /api/device-review/psirt/extract
        │   LLM call (app/llm provider) — extract structured fields as JSON
        │   (advisory_id, cve_ids, affected_ranges, workaround_text,
        │    fortinet_severity, exploited_in_wild_text, cvss_score, ...)
        │
   Editable review form (frontend only) — user confirms/corrects fields
        │
   POST /api/device-review/psirt/assess   { adom: "<name>" | "*", advisory: {...} }
        │
   app/psirt/enrich.py   (best-effort: fortiguard.com page + CISA KEV feed;
        │                 PSIRT_ENRICHMENT_ENABLED=false disables both)
        │
   app/psirt/engine.py   assess() — per-device progress loop (ThreadPoolExecutor,
        │                same pattern as Device Review's bulk scan), scoped to
        │                the selected ADOM or all ADOMs the user can access
        │  ├─ app/fmg_client.py: get_system_status(), get_adoms(), get_devices(adom)
        │  ├─ app/psirt/version_match.py    (deterministic version comparison)
        │  └─ app/psirt/workaround_checks.py (config checks via existing
        │        FMGClient methods)
        │
   app/psirt/scoring.py   (deterministic priority)
        │
   app/templates/psirt_report.html   (Jinja2, no LLM) → downloadable/viewable HTML
```

## Components

### `app/psirt/` — deterministic core

Ported from `~/code/github/ai/4tanalyst/psirt/`, same adaptation pattern as
`app/planner/` (see `app/planner/VENDORED_FROM.md` for precedent). A new
`app/psirt/VENDORED_FROM.md` records the source commit SHA/date so future
fixes discovered in 4tanalyst's `psirt/` package can be synced later via
the same manual-review workflow already documented for the planner
(see the `4tanalyst-sync-workflow` memory).

- **`models.py`** — `Advisory`, `AffectedRange`, `DeviceFinding`,
  `PsirtAssessment` dataclasses with `to_dict()`. Verbatim port — no FMG
  dependency.
- **`version_match.py`** — `parse_version`, `compare_versions`,
  `version_in_range`, `VersionMatchError`. Verbatim port — no FMG
  dependency. Unparseable version syntax raises rather than defaulting to
  "not affected."
- **`scoring.py`** — `compute_priority()`. Verbatim port — no FMG
  dependency. CVSS band, forced-to-High on KEV/exploited-in-wild text,
  zero-exposure fleet always scores "informational."
- **`enrich.py`** — `fetch_advisory_page()`, `check_kev()`,
  `enrich_advisory()`. Ported with `httpx` swapped for `requests` (this
  repo's existing HTTP dependency — no new package). Both fetches disabled
  entirely when `PSIRT_ENRICHMENT_ENABLED=false`; enrichment failures
  never raise, they set `enrichment_degraded=True` and the report marks
  affected fields "from email only, not corroborated."
- **`workaround_checks.py`** — registry mapping recognized workaround
  patterns to check functions, adapted to call `app/fmg_client.py`
  directly instead of `fortimanager_mcp.query`:
  - `disable_http_https_admin_access` / `disable_gui_internet_facing` →
    `FMGClient.get_device_interfaces_all_vdoms()` (already used by Device
    Review's `interface_protocols`/`admin_port_nondefault` checks — same
    `allowaccess` field, same public-IP classification logic ported
    verbatim from the source).
  - `configure_trusted_hosts` → **upgraded from the source's permanent
    stub** (`manual_verification_required`, since 4tanalyst never
    implemented the underlying FMG query) to a real check, reusing the
    exact logic already in `app/device_review.py::_run_trusted_hosts`
    (`FMGClient.get_device_admins()`, unrestricted-trusthost detection).
  - Unrecognized workaround text still yields
    `manual_verification_required` — never guessed. The registry is
    expected to grow one advisory at a time, same as the source.
- **`engine.py`** — `assess(advisory, fmg_client, adom_scope, ...) ->
  PsirtAssessment`. Adapted from the source's always-every-ADOM scan to
  accept an `adom_scope` parameter: a single ADOM name, or `"*"` for every
  ADOM the caller's FMG client/session can access (respecting the same
  ADOM-access-control filtering used elsewhere — `check_adom_access`).
  Structured to support incremental per-device progress reporting for the
  threaded route below, rather than only returning a final result.

### New LLM capability — structured extraction

`app/llm/base.py` gains `extract_json(system_prompt, user_prompt) -> dict`
alongside the existing `narrate()`. Implemented per-provider as a
`narrate()`-style single-shot call with a system prompt instructing
"respond with ONLY valid JSON matching this shape," then `json.loads()`
the result. A parse failure raises `LLMError` with the raw response
attached for diagnostics — never a silent guess at the missing fields.
Reuses the existing `ai_assist_enabled` app-settings flag and
`AI_PROVIDER` selection; no new toggle.

`app/psirt/extract.py` (new, thin) builds the extraction prompt (field
list, required-vs-optional, exact `Advisory`/`AffectedRange` shape) and
calls `extract_json()`, then runs the same validation `parse_advisory`
performs in the source (CVE ID regex, non-empty `affected_ranges`,
`advisory_id` character whitelist) before handing the result to the
frontend for the editable-review step. Validation failures return a
structured error (which fields are missing/malformed) rather than a
generic 500, so the frontend can highlight exactly what the user needs to
fill in manually.

### Routes — `app/routes/psirt_routes.py` (new blueprint)

Registered under the same `device_review` tab permission as the existing
Device Review routes.

- `GET  /api/device-review/psirt/extract-status` — reports availability
  (reads `ai_assist_enabled`, same pattern as every other AI-Assist status
  endpoint in this repo).
- `POST /api/device-review/psirt/extract` — body `{ email_text }` or a
  multipart file (`.eml` parsed via Python's stdlib `email` package to
  pull the plain-text body; `.txt` used as-is). Returns extracted fields
  or a structured validation error. Never a raw 500 for a malformed
  extraction — same posture as every other AI route in this repo.
- `POST /api/device-review/psirt/assess/device` — body
  `{ adom, device, advisory }` — single-device evaluation, used by the
  progress loop (mirrors `POST /api/device-review/run/device`).
- `POST /api/device-review/psirt/assess` — body `{ adom, advisory }`
  (`adom: "*"` = all accessible ADOMs) — bulk entry point, mirrors
  `bulk_device_review_adom()`; used when the frontend needs one round-trip
  rather than a client-driven per-device loop (kept for parity/testing,
  but the UI drives per-device calls for the progress bar).
- `POST /api/device-review/psirt/report` — body carries the
  already-computed assessment (client holds it after the scan, same
  "already-computed, never recomputed" pattern as Config-Delta's AI
  Summary) and returns the rendered HTML. No server-side persistence.

### UI — new section on the Device Review page

`device_review.html`/`device_review.js` gain a third section, same visual
pattern as Hygiene's multi-section layout and NAT Lookup:

1. **PSIRT Advisory Assessment** section label.
2. ADOM selector — single-ADOM dropdown plus an explicit **All ADOMs**
   option (not a separate control).
3. Paste textarea **or** file upload (`.eml`/`.txt`) for the advisory
   email — mutually exclusive toggle.
4. **Extract** button → `POST .../extract` → populates an **editable
   review form**: advisory ID, CVE IDs, affected ranges (repeatable
   product/min/max/fixed-version/notes rows), workaround text, Fortinet
   severity, CVSS score, exploitation text. Validation errors from the
   extract call highlight the specific missing/malformed field inline.
5. **Run Assessment** button → per-device progress bar reusing Device
   Review's existing `.pv-progress-wrap` CSS/JS pattern → results:
   priority badge with rationale, KEV-hit badge if applicable,
   verdict-count summary, filterable/paginated fleet exposure table
   (device, ADOM, product, current version, in-range, workaround status,
   verdict, reason), out-of-scope-products callout, degraded-data warning
   banner.
6. **Download/View HTML Report** button.

### Report — `app/templates/psirt_report.html`

New Jinja2 template (this repo has no shared cross-feature report
renderer today, unlike 4tanalyst's `scripts/render_report.py`), rendered
server-side from `PsirtAssessment.to_dict()`. Content, in order:

1. Advisory summary — CVE ID(s), advisory ID/link, product, published
   date, Fortinet's severity, CVSS, description.
2. Exploitation signal — Fortinet's own wording + CISA KEV hit (yes/no,
   with rationale) + computed priority.
3. Fleet exposure table — one row per device.
4. Per-device verdict detail — no action / configuration change required
   (workaround text + what the live config actually has, or
   `manual_verification_required` for unrecognized workaround text) /
   upgrade required (current → fixed version).
5. Degraded-data warnings.
6. Out-of-scope products, listed explicitly for manual review.

Pure templating, no LLM — matches the source's actual behavior.

## Configuration

New `.env` variables, documented in `.env.example` and `CLAUDE.md`
alongside the existing `AI_PROVIDER`/`SNMP_*` blocks:

```
PSIRT_ENRICHMENT_ENABLED=true   # fortiguard.com + CISA KEV fetches; false for air-gapped deployments
PSIRT_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
PSIRT_FETCH_TIMEOUT=5           # seconds, per enrichment fetch
```

## Error handling

- LLM extraction failure (API error, malformed JSON) → structured error to
  the frontend, form stays editable, never a silent guess.
- Validation failure (missing CVE IDs, empty affected ranges, invalid
  advisory ID characters) → same posture, specific field called out.
- Enrichment fetch failures (fortiguard.com or KEV feed unreachable, or
  `PSIRT_ENRICHMENT_ENABLED=false`) → assessment proceeds on email-derived
  data alone; report marks affected fields "from email only, not
  corroborated."
- FortiManager query failures (ADOM list, device list, workaround check)
  → degraded treatment; a degraded scan never claims "no action needed"
  for devices it couldn't fully check — those get
  `verdict=unknown_needs_manual_check`.
- Unrecognized/ambiguous version-range syntax → typed error surfaced to
  the user, never defaults to "not affected."

## Testing

- `tests/test_psirt_version_match.py` — range parsing + comparison.
- `tests/test_psirt_scoring.py` — priority matrix (CVSS band × KEV ×
  exploited-text × zero-fleet-exposure cases).
- `tests/test_psirt_enrich.py` — fetch success/failure/disabled cases,
  mocked `requests`.
- `tests/test_psirt_workaround_checks.py` — each registered check against
  fake `FMGClient` device data (in-place / not-in-place / unrecognized),
  including the upgraded `configure_trusted_hosts` check.
- `tests/test_psirt_engine.py` — `assess()` end-to-end with a fake
  `FMGClient`, covering single-ADOM and `"*"`-scope cases and degraded
  paths.
- `tests/test_psirt_extract.py` — `extract_json()` happy path, malformed
  JSON, missing-field validation.
- `tests/test_psirt_routes.py` — extract/assess/report routes, including
  `ai_assist_enabled=false`, LLM failure, and ADOM-access-control
  filtering for the `"*"` scope.
- `tests/test_psirt_render.py` — HTML rendering from a fixed
  `PsirtAssessment`.

## Open questions for implementation planning

- Exact prompt/schema wording for `extract_json()` — needs iteration
  against real PSIRT email samples once implemented.
- Whether `.eml` parsing needs multipart/HTML-body handling or plain-text
  extraction is sufficient for real Fortinet PSIRT emails (needs a sample
  to confirm).
- Initial size of the `workaround_checks.py` registry beyond the 3 ported
  patterns — grow advisory-by-advisory per the source's own stated
  approach.
