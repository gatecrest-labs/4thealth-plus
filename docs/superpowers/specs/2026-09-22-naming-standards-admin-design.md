# Naming Standards Admin UI — Design

Date: 2026-09-22
Status: approved for planning

## Problem

`naming.yaml` (gitignored, copied from tracked `naming.example.yaml`) already
drives Rule Validation's AI Assist / Hygiene Fix naming, but:

1. The only way to change it is hand-editing the YAML file on the server and
   restarting the app (`@lru_cache` in `app/planner/standards.py::_load_yaml`
   means edits made while the app is running are invisible until restart).
2. `standards.object_name()` and `standards.policy_name()` — the functions
   that actually generate `H_10.1.1.1`, `SVC_TCP_443`,
   `CHG123_WAN_TO_DMZ_001`, etc. — are hardcoded Python f-strings. They do
   **not** read the `pattern:` field from `naming.yaml` at all today. Editing
   a pattern in the YAML currently changes only what's displayed/narrated to
   the LLM, never what's actually generated.
3. There is no in-app way for an admin to review or change the standard —
   nothing surfaces it in the Admin tab, and nothing documents the token
   syntax a company would need to write their own patterns.

Companion feature request (from a related change in the sibling
`4tanalyst` repo, see `~/code/github/ai/4tanalyst` commit `06c835a`): ship a
generic default naming standard, let each install override it for their own
conventions, and document the override workflow (including an
AI-assisted "turn our policy doc into this YAML" prompt). 4tanalyst solves
this with a file-override + restart pattern (no web UI, since it's an MCP
server, not a web app). This spec adapts the same underlying idea —
generic default, fully overridable, documented token-based prompt for
AI-assisted generation — to 4thealth-plus's Admin UI, and additionally makes
edits actually change generated behavior (which 4tanalyst does not need to
solve, since editing its YAML always was live behavior).

## Scope

**In scope** — make these 4 types pattern-driven and admin-editable:
`host`, `network`, `service`, `policy`. These are exactly the types already
centralized in `app/planner/standards.py`.

**Out of scope** (documented as a known boundary, not silently dropped):
- FQDN / wildcard-FQDN / FQDN-destination-group naming
  (`app/planner/engine.py::_fqdn_object_name`, `_fqdn_group_name`) stays
  hardcoded. It has security-sensitive sanitization baked in (defense
  against CLI injection via attacker-controlled FQDN strings feeding into
  `edit "..."` CLI statements) and refactoring it into a generic template
  engine is a separate, riskier effort.
- `address_group`, `service_group`, `nat_rule`, `vip` patterns remain in
  `naming.yaml` as documentation/reference only — nothing in the codebase
  currently generates names for these object types, so there's no live
  behavior to wire up.
- `zone_abbrevs` in `naming.yaml` is confirmed dead (unused anywhere in
  `app/`) — left as-is, not addressed by this feature.
- `review_requirements.yaml` (risk/logging/approval rules) is a separate
  file and feature; this spec touches `naming.yaml` only.

## Design

### 1. Template engine — `app/planner/naming_template.py` (new)

```python
def render(pattern: str, **tokens: str) -> str:
    """Substitute <TOKEN_NAME> placeholders in `pattern` with `tokens` values.

    Raises NamingTemplateError (a PlannerDataError subtype) if the pattern
    references a token not present in `tokens`, or is empty/malformed —
    never silently emits a partial/broken name.
    """
```

- Token syntax: `<UPPER_SNAKE_CASE>`, matched with a simple regex
  (`<[A-Z_]+>`). No nested tokens, no conditionals — deliberately minimal to
  keep validation simple and errors legible to a non-programmer admin.
- Per-type token vocabularies (documented in the doc file and the admin
  help panel):
  - `host`: `<IP_ADDRESS>`
  - `network`: `<NETWORK_ADDRESS>`, `<PREFIX_LEN>`
  - `service`: `<PROTO>`, `<PORT>`
  - `policy`: `<TICKET_ID>`, `<SRC_INTF>`, `<DST_INTF>`, `<SEQ>`
- `<SEQ>` for policy is always rendered zero-padded to 3 digits
  (`f"{seq:03d}"`) before substitution — matches today's hardcoded
  `_001`/`_002` behavior; not itself a configurable token width in v1
  (YAGNI — no requester has asked for a different width).

### 2. `standards.py` changes

`object_name()` and `policy_name()` are rewritten to:
1. Load the relevant `conventions.<type>.pattern` string from
   `load_naming()`.
2. Build the token dict for that call (e.g. for `host`:
   `{"IP_ADDRESS": ip.split("/")[0]}`).
3. Call `naming_template.render(pattern, **tokens)`.

With the shipped default `naming.example.yaml`, output must be byte-identical
to today's hardcoded behavior — this is the regression bar covered by
existing/new unit tests in `tests/` (exact path found during planning).

`_load_yaml()` drops `@lru_cache` — re-reads `naming.yaml` from disk on
every call, matching `app/groups.py`/`app/app_settings.py`'s existing
no-cache pattern. This repo's config files are small (a few KB) and read
once per AI Assist/Hygiene Fix request; the FMG API calls those flows
already make dominate any disk-read cost.

### 3. Persistence — `app/naming_standards.py` (new)

Mirrors `app/app_settings.py`'s atomic-write pattern:

- `get_naming() -> dict` — reads `naming.yaml` (delegates to
  `standards.load_naming()`).
- `validate_naming(data: dict) -> list[str]` — renders each of the 4 in-scope
  patterns against a fixed dummy token set (e.g. `IP_ADDRESS="10.0.0.1"`,
  `TICKET_ID="CHG000000"`, `SRC_INTF="wan1"`, `DST_INTF="dmz"`, `SEQ=1`,
  `PROTO="tcp"`, `PORT="443"`, `NETWORK_ADDRESS="10.0.0.0"`,
  `PREFIX_LEN="24"`) and returns a list of human-readable errors (empty list
  = valid). Also rejects an empty/missing `pattern` string per type.
- `save_naming(data: dict) -> None` — calls `validate_naming()` first,
  raises on any error (caller returns 400 with the error list — a save
  request is never allowed to leave `naming.yaml` in a state that breaks a
  live AI Assist request), then writes atomically
  (`app/atomic_io.py`, `threading.Lock`, same as `app_settings.py`).
- `reset_to_default() -> None` — copies `naming.example.yaml` over
  `naming.yaml` (atomic write, same lock).

### 4. Admin UI

New **Naming Standards** sub-tab in Admin (`admin.html`/`admin.js`,
alongside Zone Policy/AI Assist/Scheduled), admin-only (existing
`admin_required` pattern):

- 4 cards, one per in-scope type (Host, Network, Service, Policy), each with:
  - `pattern` text input
  - `examples` — small repeatable list (add/remove line, like Zone Policy's
    subnet list pattern), display-only for AI narration, not used by the
    template engine
  - `notes` — textarea, display-only
  - a live preview line below the pattern input, re-rendered on every
    keystroke client-side using the same dummy token set as
    `validate_naming()` (duplicated in JS — small, fixed dict, not worth a
    round trip per keystroke); shows either the rendered example name or an
    inline error if the pattern references an unknown token
- **Import YAML** — a paste box + "Apply" button that parses pasted YAML
  text (must match the `platforms.fortigate.conventions.*` schema) and
  populates the 4 cards' fields from it, without saving — the admin still
  reviews the live preview and clicks **Save** to persist. This is the
  landing point for the "paste your policy doc into Claude with this
  prompt, paste the YAML result here" workflow documented below (adapted
  from 4tanalyst's `docs/naming-convention.md` prompt).
- **Save** button — `PUT /admin/api/naming-standards`, body is the full
  naming dict; 400 with error list on validation failure, flash success
  message on 200 (existing Admin flash-message convention).
- **Reset to Defaults** button with a confirm dialog — `POST
  /admin/api/naming-standards/reset`.
- A help icon/tooltip next to the section header linking to
  `docs/naming-conventions.md` and summarizing the token vocabulary inline
  (the "online help" requirement) — same tooltip pattern already used
  elsewhere in Admin (e.g. the host-metrics Docker memory tooltip).

**API endpoints** (`app/routes/admin_routes.py`, all `admin_required`):
- `GET  /admin/api/naming-standards` — current `naming.yaml` content
- `PUT  /admin/api/naming-standards` — validate + save
- `POST /admin/api/naming-standards/reset` — reset to `naming.example.yaml`

### 5. Documentation

- **New `docs/naming-conventions.md`**: explains the token syntax and
  per-type vocabulary, gives 2-3 example company patterns (ticket-based
  like the shipped default, a minimal/no-ticket variant, a
  department-code variant), documents the Admin UI workflow, and includes
  an adapted version of 4tanalyst's AI-generation prompt — "paste your
  org's naming policy document into Claude and ask it to produce YAML
  matching this schema, then paste the result into Admin → Naming
  Standards → Import YAML" — with the schema restricted to the 4 in-scope
  types plus the informational-only ones, and a note that patterns must use
  the documented `<TOKEN>` placeholders exactly (unlike 4tanalyst's
  free-form `<PLACEHOLDER>` convention, since these patterns are now
  actually parsed).
- **`docs/configuration.md`**: update the existing one-line `naming.yaml`
  table row to link to the new doc and mention the Admin UI as the
  supported way to edit it post-install (hand-editing the file remains
  supported as a fallback, matching every other gitignored-runtime-file
  convention in this repo).
- **CLAUDE.md**: add a subsection under "Rule Validation tab" documenting
  the Naming Standards sub-tab, the template engine, the exact 4-type
  scope boundary, and pointing at `docs/naming-conventions.md` — following
  this repo's existing convention of every admin feature being documented
  in both CLAUDE.md (architecture) and a `docs/*.md` file (operator-facing).

### 6. Default / first-run behavior

Unchanged from today: `naming.example.yaml` is tracked in git;
`cp naming.example.yaml naming.yaml` remains the documented first-run step
(already covered by existing setup instructions, just cross-referenced
from the new doc). No new bootstrap step — "basic standard out of the box"
is already true, this feature only adds the ability to change it afterward
without hand-editing files or restarting.

## Testing

- Unit tests for `naming_template.render()`: happy path, missing token,
  malformed pattern, empty pattern.
- Unit tests for `standards.object_name()`/`policy_name()` against the
  shipped default YAML — byte-identical output to today's hardcoded
  behavior (regression bar).
- Unit tests for `naming_standards.validate_naming()`: valid data, each of
  the 4 types with a broken pattern, missing pattern.
- Route tests for the 3 new admin endpoints: happy path, validation
  failure (400 + error list), non-admin access (403/redirect per existing
  `admin_required` behavior), reset.

## Out of scope / explicitly deferred

- FQDN/wildcard-FQDN/FQDN-group naming customization (see Scope above).
- Making `address_group`/`service_group`/`nat_rule`/`vip` patterns live —
  no generator exists for them yet; if one is added later, it should follow
  this same template-engine pattern.
- Configurable `<SEQ>` zero-pad width.
- `review_requirements.yaml` (risk/logging/approval standards) admin UI —
  a natural follow-on, not part of this spec.
