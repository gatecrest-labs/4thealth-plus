# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Read-only web dashboard for monitoring FortiGate firewalls via FortiManager. All integrations are strictly read-only — nothing in this project pushes configuration to Fortinet devices.

## Running the Flask web app

```bash
# Install dependencies
uv sync

# Development
python wsgi.py            # https://localhost:5443

# Production (gthread worker required for background summary job)
gunicorn --workers 2 --threads 4 --worker-class gthread --bind 0.0.0.0:5443 wsgi:app
```

The app auto-enables HTTPS if `certs/cert.pem` and `certs/key.pem` exist (self-signed is fine; generate with `openssl req -x509 ...`). Both cert files are gitignored.

Configuration is read from `.env` (gitignored). Key variables:

```
SECRET_KEY=              # Flask session signing key
FMG_PRIMARY_HOST=<your-fortimanager-ip>   # Used for ADOM/device/policy queries
FMG_API_TOKEN=your-bearer-token-here   # preferred
# FMG_USERNAME=your-api-username         # fallback if no token
# FMG_PASSWORD=your-api-password
FMG_VERIFY_SSL=false
CPU_WARN=70  CPU_CRIT=90
MEM_WARN=75  MEM_CRIT=90
SUMMARY_REFRESH_HOUR=1   # nightly summary recalculation hour (default 01:00)
SUMMARY_REFRESH_MINUTE=0
SNMP_ENABLED=false       # enable SNMPv3 polling for FortiManager/FortiAnalyzer/FortiAuthenticator CPU/mem
SNMP_PORT=161
SNMP_TIMEOUT=5
SNMP_RETRIES=1
SNMP_POLL_INTERVAL=60    # seconds between background poll cycles
SNMP_USER=
SNMP_AUTH_PROTOCOL=SHA   # SHA | SHA256 | SHA512
SNMP_AUTH_KEY=
SNMP_PRIV_PROTOCOL=AES   # AES | AES192 | AES256
SNMP_PRIV_KEY=
```

Infrastructure dashboard targets (FortiManager, FortiAnalyzer, FortiCollector, FortiAuthenticator, etc.)
are defined in `infra_targets.json` (gitignored). Copy `infra_targets.example.json` to get started.
Each entry is `{ "label": "...", "host": "...", "type": "..." }`. Add or remove entries freely.
An optional `"token"` field on any entry sets a per-device bearer token (each Fortinet appliance
type generates its own token). Token priority: per-device `"token"` → `FMG_API_TOKEN` → username/password.

CPU/memory for `FortiManager`, `FortiAnalyzer`, and `FortiAuthenticator` entries is sourced via
SNMPv3 polling (see `app/infra_health_cache.py`), not FMG JSON-RPC — FortiAuthenticator in
particular has no JSON-RPC status/resource API. A background poller
(`app/infra_health_cache.py`, `SNMP_POLL_INTERVAL` seconds, default 60) queries each target and
caches `{cpu, mem, snmp_status}`; `/api/infrastructure` reads instantly from this cache. Optional
per-device `"snmp_user"` / `"snmp_auth_key"` / `"snmp_priv_key"` / `"snmp_auth_protocol"` /
`"snmp_priv_protocol"` fields override the global `SNMP_*` `.env` defaults, following the same
override-over-default pattern as `"token"`. `FortiCollector` entries (and any other type) continue
to use the legacy FMG JSON-RPC CPU/mem path unchanged.

CPU/mem OIDs live in `OID_MAP` in `app/infra_health_cache.py`. FortiManager's OIDs are confirmed
against a real FMG-VM64-KVM (v7.6.7), cross-checked against the FMG GUI's System Resources widget
— CPU is a direct percentage OID (`fmSystem` group, `1.3.6.1.4.1.12356.103.2.1.1.0`), but memory
has no native percentage OID and is derived from used-KB/total-KB. FortiAnalyzer and
FortiAuthenticator OIDs are still NOT confirmed against real hardware — verify both with
`snmpwalk` or Fortinet's official MIBs before enabling `SNMP_ENABLED=true` for those types in any
production environment.

SNMPv3 privacy (AES) requires the `cryptography` package — without it, `pysnmp` fails silently
with `Ciphering services not available` on every request needing `authPriv`.

## User management

```bash
python manage_users.py add <username> [--password <pw>] [--role admin|viewer]
python manage_users.py list
python manage_users.py delete <username>
python manage_users.py secret   # generate a SECRET_KEY value
```

User accounts are stored in `users.json` (committed). Passwords are bcrypt-hashed.

## Flask app architecture

```
app/
  __init__.py          # Flask app factory, registers blueprints, starts background schedulers
  config.py            # Reads .env into a Config object
  auth.py              # Session-based login; bcrypt password verify against users.json
  fmg_client.py        # FortiManager JSON-RPC client (context manager: auto login/logout)
  hygiene.py           # Rule hygiene check engine (9 checks: unnamed, unlogged, shadow, disabled, expired, unhit, missing security profile, redundant, over-permissive)
  hygiene_ai.py        # AI Explain for a single Rule Hygiene finding — narrates one already-computed finding, never re-runs a check
  device_review.py     # Device Review check engine — interface protocol checks; add new checks here
  rule_review.py       # Policy analysis + route-tracing engine; zone policy integration
  zone_db.py           # Zone policy DB engine — loads policy_db.json, runs queries, validates, handles CRUD
  summary_job.py       # Background job: managed firewall + rule counts; nightly APScheduler
  adom_cache.py        # Background cache: ADOM list from FortiManager, refreshed every 30 min
  ai_usage.py           # AI Assist usage/cost tracking, SQLite-backed (ai_usage.db)
  host_metrics.py       # Host CPU/mem/disk sampling, SQLite-backed (host_metrics.db); Admin page graphs
  groups.py            # Group management: tab permissions + ADOM access control (groups.json)
  decorators.py        # login_required, tab_required, admin_required, check_adom_access
  app_settings.py      # Persistent app settings (app_settings.json); used for external_api_enabled toggle
  api_tokens.py        # Bearer token CRUD for the external API; SHA-256 hashes stored in api_tokens.json
  routes/
    auth_routes.py            # /login, /logout
    dashboard_routes.py       # /, /firewalls, /versions (Jinja2 pages)
    api_routes.py             # /api/* JSON endpoints consumed by frontend JS
    hygiene_routes.py         # /hygiene page + /api/hygiene/* endpoints
    rule_review_routes.py     # /rule-review page + /api/rule-review/* endpoints
    zone_routes.py            # /zone-policy page + /api/zone/* endpoints
    device_review_routes.py   # /device-review page + /api/device-review/* endpoints
    admin_routes.py           # /admin page + /admin/api/* group/user/log/ADOM/settings/token endpoints
    pending_changes_routes.py # /pending-changes page + /api/pending-changes/* endpoints
    external_api_routes.py    # /external/api/* bearer-token endpoints for FW-Analyst integration
wsgi.py                # Entry point; SSL context wiring
policy_db.json         # Network segmentation policy database (gitignored — runtime data)
groups.json            # Group definitions (gitignored — copy from groups.example.json); includes tab and ADOM permissions
app_settings.json      # App feature flags (gitignored — copy from app_settings.example.json)
api_tokens.json        # Hashed bearer tokens (gitignored — copy from api_tokens.example.json)
```

### ADOM filtering convention

All ADOM list endpoints filter out names that start with `"forti"` (case-insensitive) — these are FortiManager system ADOMs (FortiManager_Managed_Devices, etc.) that don't contain real firewall policy packages. Both `/api/adoms` and `/api/rule-review/adoms` apply this filter. Any new ADOM-returning endpoint should do the same.

### ADOM access control

Groups have two layers of access control:

1. **Tab access** — which navigation tabs a non-admin user can see (existing).
2. **ADOM access** — which FortiManager ADOMs a non-admin user can interact with (added).

Each group in `groups.json` may include:
```json
{
  "adom_restrict": true,
  "allowed_adoms": ["Enterprise Services", "Enterprise Dev", "Enterprise SDWAN"]
}
```

**Access rules:**
- Admin users → always unrestricted (all ADOMs, all tabs).
- Non-admin users with at least one group where `adom_restrict=false` → unrestricted ADOM access.
- Non-admin users where every group has `adom_restrict=true` → union of their `allowed_adoms` lists.
- User in no group → no ADOM access.

**Enforcement** (`app/decorators.py → check_adom_access(adom)`): called at the top of every ADOM-scoped API route. Returns a 403 JSON response if the user cannot access the ADOM. ADOM list endpoints (`/api/adoms`, `/api/rule-review/adoms`) silently filter out inaccessible ADOMs.

**ADOM cache** (`app/adom_cache.py`): queries FortiManager at startup and every 30 minutes. The admin UI uses this list to populate the ADOM checkbox picker in the group editor. New ADOMs are discovered automatically but are **never automatically added** to any group's `allowed_adoms` list — restricted groups must be explicitly updated by an admin.

**Admin API endpoint** `GET /admin/api/adoms` returns `{ adoms: [...], last_updated, status }` from the cache.

### FortiManager client design

`FMGClient` in `app/fmg_client.py` authenticates to FortiManager's JSON-RPC API (`/jsonrpc`) and queries managed FortiGate devices through FortiManager's proxy endpoint (`/sys/proxy/json`). This means the app never connects directly to individual firewalls — all firewall data flows through FortiManager.

Health status uses a three-tier model: green (healthy), yellow (warn threshold crossed), red (crit threshold crossed or unreachable). Thresholds are the `CPU_WARN/CRIT` and `MEM_WARN/CRIT` env vars.

Sessions expire after 1 hour. `COOKIE_SECURE` is automatically set when SSL is active.

### Background summary job

`app/summary_job.py` runs a background thread at startup and on a nightly schedule (APScheduler). It enumerates all ADOMs, counts managed devices and policy rules (only in ADOMs that have devices — empty system ADOMs are skipped). Results live in an in-memory dict; `/api/summary` reads from it instantly.

**Critical production requirement:** Gunicorn must use `--worker-class gthread`. The default `sync` worker forks child processes — background threads from the parent do not transfer, so the scheduler would never fire. Use `--workers 2 --threads 4 --worker-class gthread`.

### Rule Review tab

`GET /hygiene` → `hygiene.html` + `hygiene.js`

Two-section layout (tab displays as "Rule Review" in the nav; internal key remains `rule_hygiene`):
1. **Policy Rules** (top) — select ADOM + package, rule table loads automatically. Features:
   - Independent ADOM/package selectors from the Hygiene Analysis section below
   - Full-text regex search across name, ID, comment, source, destination, service, interfaces
   - Field-scoped filter dropdown (search within a single column)
   - Address groups and service groups expand inline (click the triangle) to show member objects; group member lists over 10 entries paginate (10/25/50/100 per page)
   - Address objects show subnet detail when available
   - Interface badges (source = blue, destination = green)
   - Page size 10/25/50/100 with `<< < … > >>` pagination
   - Export (CSV/JSON/PDF) — each export includes a filter header block at the top (package, ADOM, timestamp, search terms, total/filtered counts)
2. **Hygiene Analysis** (below) — select ADOM + package, run 9 checks, filter/export findings (CSV/JSON/PDF).
   - **Find Unused Objects** button (next to Run Analysis) scans the selected package and lists address/address-group/service/service-group objects not referenced by any policy rule (BFS group-member expansion catches indirect references; FortiGuard/built-in objects like `all`/`ANY`/`g-*`/`ISDB-*` are excluded). A scope selector (All / Local only / Global only) controls whether the shared Global-ADOM object pool is included — services and service groups have no global pool, so `scope=global` always returns empty for those. Results are filterable/paginated (10/25/50/100) with CSV/JSON export. Backend: `GET /api/hygiene/unused-objects?adom=&pkg=&scope=`, logic in `app/hygiene.py::find_unused_objects()`.

Backend: `POST /api/hygiene/policies` returns `srcaddr_exp`, `dstaddr_exp`, `service_exp` arrays with `{name, type, members?, detail?}` objects alongside the flat name lists. Also returns `srcintf`/`dstintf`.

**AI Explain endpoints:**
- `GET  /api/hygiene/ai-explain-status` — reports whether AI Explain is available (reads the `ai_assist_enabled` app-settings flag)
- `POST /api/hygiene/explain-finding` — body is a single finding object; narrates it via `app/hygiene_ai.py`; returns `{narrative, narrative_error}`, never a 500

AI Explain ("Explain" button on individual Hygiene Analysis findings) reuses
the same `ai_assist_enabled` app-settings flag as Rule Validation's AI
Assist and Device Review's AI Summary (Admin → AI Assist) — there is no
separate Rule Review toggle.

### Device Review tab

`GET /device-review` → `device_review.html` + `device_review.js`

Runs configurable security checks against every device in a selected ADOM. Combines interface-protocol analysis with CIS hardening checks in a single unified results table.

**Workflow:**
1. Select ADOM → device list loads automatically.
2. Choose which checks to run (all checked by default).
3. For parameterised CIS checks, a **Check Parameters** panel appears — enter expected IPs before running.
4. Click **Run Analysis** — a per-device progress loop fires, findings appear in a filterable, paginated table.
5. Export results as CSV, JSON, or PDF.

**Result values:**
- `INSECURE` — red: cleartext protocols (HTTP, Telnet) are enabled
- `FAIL` — red: CIS check failed (server missing, sync disabled, etc.)
- `WARN` — yellow: CIS host check — service is active but configured servers do not match expected (NTP, Syslog, FortiAnalyzer, DNS); effectively unreachable for Interface Protocols (unknown protocols default to informational)
- `CONFIG_MISSING` — yellow: CIS check ran but no expected values were supplied; device value shown for information
- `PASS` — green: CIS check passed
- `INFO` — blue: informational finding (e.g. PING enabled; interfaces with only informational protocols)

**Protocol severity configuration:** Create `protocol_severity.json` at the project root (gitignored) to override default protocol classifications. See `protocol_severity.example.json` for all defaults and valid values (`secure`, `insecure`, `info`, `null`). Overrides take effect on app restart.

**Implemented checks (26 total):**

| Key | Name | CIS Level | data_keys | Parameterised |
|-----|------|-----------|-----------|---------------|
| `interface_protocols` | Interface Protocols | — | `interfaces` | No |
| `ntp_config` | NTP Configuration | L1 | `ntp` | Yes (expected IPs) |
| `syslog_config` | Syslog Configuration | L1 | `syslog` | Yes (expected IPs) |
| `trusted_hosts` | Trusted Hosts on Admin Accounts | L1 | `admins` | No |
| `default_admin` | Default 'admin' Account | L1 | `admins` | No |
| `admin_mfa` | Admin Two-Factor Authentication | L1 | `admins` | No |
| `idle_timeout` | Admin Idle Timeout | L1 | `system_global` | Yes (max minutes) |
| `lockout_threshold` | Admin Lockout Threshold | L1 | `system_global` | Yes (max attempts) |
| `password_length` | Password Minimum Length | L1 | `password_policy` | Yes (min chars) |
| `log_disk` | Local Disk Logging | L1 | `log_disk` | No |
| `log_severity` | Log Severity Level | L1 | `log_disk` | Yes (max severity) |
| `log_faz` | FortiAnalyzer Logging | L1 | `log_faz` | Yes (expected FAZ IP) |
| `dns_servers` | DNS Servers | L1 | `dns` | Yes (expected IPs) |
| `snmp_version` | SNMP Version Enforcement | L1 | `snmp_community`, `snmp_sysinfo` | No |
| `snmp_readonly` | SNMP Read-Only | L2 | `snmp_users` | No |
| `tls_version` | Minimum TLS Version | L1 | `system_global` | Yes (min TLS) |
| `ssh_ciphers` | SSH Strong Ciphers | L2 | `system_global` | No |
| `firmware_version` | Firmware Version Compliance | L1 | `device_meta` | Yes (min version) |
| `ha_sync` | HA Sync Status | L2 | `ha_status` | No |
| `hostname_changed` | Hostname Changed From Default | L1 | `system_global` | No |
| `admin_port_nondefault` | Non-Default Admin Port | L1 | `system_global` | No |
| `prelogin_banner` | Pre-Login Banner Enabled | L1 | `system_global` | No |
| `timezone_set` | Timezone Explicitly Configured | L1 | `system_global` | No |
| `vpn_weak_crypto` | VPN Weak Crypto (Phase1/Phase2) | L2 | `ipsec_phase1`, `ipsec_phase2` | No |
| `vpn_pfs` | VPN Perfect Forward Secrecy | L2 | `ipsec_phase2` | No |
| `vpn_ike_version` | VPN IKE Version | L2 | `ipsec_phase1` | No |

Note: `system_global` is fetched once and shared by `idle_timeout`, `lockout_threshold`, `tls_version`, `ssh_ciphers`, `hostname_changed`, `admin_port_nondefault`, `prelogin_banner`, and `timezone_set`. `admins` is shared by `trusted_hosts`, `default_admin`, and `admin_mfa`. `log_disk` is shared by `log_disk` and `log_severity`. `device_meta` is populated from the device list (no extra API call). `ipsec_phase1`/`ipsec_phase2` fetch `vpn.ipsec/phase1-interface` and `vpn.ipsec/phase2-interface` from all VDOMs via FMG proxy (`FMGClient.get_device_ipsec_phase1`/`get_device_ipsec_phase2`); `ipsec_phase1` is shared by `vpn_weak_crypto` and `vpn_ike_version`, `ipsec_phase2` by `vpn_weak_crypto` and `vpn_pfs`.

**Check engine — `app/device_review.py`:**

The check registry (`CHECKS` list) is the single place to add new checks. Each entry is:

```python
{
    "key":          "my_check",           # unique ID used in API + JS
    "name":         "Display Name",       # shown in UI checkbox list
    "description":  "One-line summary",   # tooltip
    "data_keys":    ["interfaces"],       # which device data blobs to fetch
                                          # see implemented data_keys above
    "params_schema": [],                  # [] = binary check, no user input
                                          # or list of input descriptors:
                                          # [{"key","label","type","placeholder","required"}]
    "run":          _my_check_function,   # callable(device_name, device_data, params) -> list[Row]
}
```

`device_data` is a dict populated by the route from the `data_keys` list — only the keys needed by selected checks are fetched per device. `params` is the user-supplied values for that check (empty dict for binary checks).

A `Row` dict must contain: `device`, `interface` (or `"system"` for device-level checks), `vdom`, `ip`, `type` (or `"system"`), `status`, `check`, `result`, `detail`, `protocols`, `has_insecure`, `has_secure`.

`CHECKS_META` (serialisable — no `run` key) is passed to both the page template and the frontend as `CHECK_DEFS`, driving the params panel UI dynamically.

**API endpoints:**
- `GET  /api/device-review/adoms/<adom>/devices` — list devices in an ADOM
- `POST /api/device-review/run/device` — body: `{ adom, device, checks, check_params }` — single device (used by progress loop)
- `POST /api/device-review/run` — body: `{ adom, devices, checks, check_params }` — bulk run; `devices: []` means all, `checks` absent means all, `check_params` maps check key → param dict
- `GET  /api/device-review/ai-summary-status` — reports whether AI Summary is available (reads the `ai_assist_enabled` app-settings flag)
- `POST /api/device-review/ai-summary` — body: `{ adom, results, checks }` — narrates an already-computed run; returns `{ narrative, narrative_error }`, never a 500

AI Summary ("Summarize with AI" on the Device Review results table) reuses
the same `ai_assist_enabled` app-settings flag as Rule Validation's AI
Assist (Admin → AI Assist) — there is no separate Device Review toggle.

**Adding a new CIS check (binary example):**
1. Add a proxy method to `fmg_client.py` if new device data is needed.
2. Add a fetch branch in `_fetch_device_data()` in `device_review_routes.py` for the new `data_key`.
3. Write `_run_my_check(device_name, device_data, params) -> list[Row]` in `device_review.py`.
4. Append an entry to `CHECKS` with the appropriate `data_keys` and empty `params_schema`.
No template or frontend JS changes are needed for binary checks.

#### PSIRT Advisory Assessment

New section on the same `/device-review` page (below the CIS checks table),
not a separate nav tab. Paste or upload (`.eml`/`.txt`) a Fortinet PSIRT
advisory email; an LLM extracts structured fields (advisory ID, CVE IDs,
affected version ranges, workaround text, severity, exploitation wording)
into an editable review form — the only LLM touchpoint in this feature.
Everything downstream is deterministic: `app/psirt/engine.py::assess()`
scans the selected ADOM (or every ADOM the user can access, via `"*"`)
for affected firmware and whether any documented workaround is already
applied, then `app/psirt/scoring.py` computes priority from CVSS band,
Fortinet's exploitation wording, and CISA KEV catalog membership. Ported
from `~/code/github/ai/4tanalyst`'s `psirt/` package — see
`app/psirt/VENDORED_FROM.md` for provenance and the sync workflow.

**Workaround checks** (`app/psirt/workaround_checks.py`) — a registry
matching recognized workaround phrasing to real FortiManager config
checks via `app/fmg_client.py`: disabling HTTP/HTTPS admin access,
disabling GUI on internet-facing interfaces, and trusted-hosts
restriction (the last one reuses the same logic as Device Review's
`trusted_hosts` CIS check). Unrecognized workaround text always yields
`manual_verification_required` — never guessed.

**Enrichment** — best-effort fetches against the fortiguard.com advisory
page and the CISA KEV feed, gated by `PSIRT_ENRICHMENT_ENABLED` (default
`true`; set `false` for air-gapped deployments). Failures degrade
gracefully — the assessment proceeds on email-derived data alone.

**Feature gate:** reuses the same `ai_assist_enabled` app-settings flag as
every other AI-Assist feature in this repo (Admin → AI Assist) — no
separate PSIRT toggle.

**API endpoints:**
- `GET  /api/device-review/psirt/extract-status`
- `POST /api/device-review/psirt/extract` — body `{ email_text }` or multipart file upload
- `POST /api/device-review/psirt/assess/device` — body `{ adom, device, advisory }`
- `POST /api/device-review/psirt/assess` — body `{ adom: "<name>" | "*", advisory }`
- `POST /api/device-review/psirt/report` — body `{ assessment }`, returns HTML

No persistence — each assessment is a one-off analysis, same as NAT Lookup
and Rule Validation's AI Assist.

### Rule Validation tab

`GET /rule-review` → `rule_review.html` + `rule_review.js`

Three-step workflow: define flows → select policy packages → review results.
- Resolves address and service objects for each ADOM to match flows against policies
- Performs path-relevance checks using live device routing + interface data via FMG proxy
- Integrates zone policy (via `app.zone_db`) for segmentation policy verdicts — reads `policy_db.json` directly, no external service required
- Generates FortiOS CLI snippets for new/modified rules
- Verdict categories: PERMITTED / MODIFIABLE / NEW_RULE_NEEDED / EXPLICITLY_DENIED

#### AI Assist mode

Alongside the bulk CSV/XLSX table workflow above, the Rule Validation tab offers an
**AI Assist** panel for single-request change analysis: an engineer describes one
change (source/destination/service/target firewalls, plus optional ticket ID and
justification) and gets back a deterministic verdict, an AI-written narrative
report, and a peer-review package.

**`app/planner/`** — the deterministic change-planning engine, ported from
`~/code/github/ai/4tanalyst`'s `planner/` package (see
`app/planner/VENDORED_FROM.md` for full provenance, the exact source commit, and
the file-by-file adaptation table). It computes the verdict — the LLM never does.
Key modules: `models.py` (data classes), `matching.py` (address/service resolution),
`standards.py` (naming/risk/logging/approval lookups), `cli_gen.py` (FortiOS CLI
generation), `insertion.py` (rule placement), `fetch.py` (pulls live FMG + zone-policy
data), `engine.py` (`plan_change()` — the single entry point that ties it all
together). `catalogs.py` and `zone_adapter.py` (`ZoneDBAdapter`) are 4THealth+-native
adapters that let the ported engine call `app.fmg_client.FMGClient` and
`app.zone_db` in-process instead of over HTTP with separate credentials.

**`app/llm/`** — a thin, provider-agnostic narration layer (`get_provider()` in
`app/llm/__init__.py`) that turns the planner's already-computed structured result
into prose. The LLM only explains the plan — it never computes or edits any value
in it. `AI_PROVIDER` in `.env` selects the backend: `claude` (default,
`claude_provider.py`), `codex` (`codex_provider.py`), or `ollama`
(`ollama_provider.py`, local or cloud via `OLLAMA_HOST`/`OLLAMA_MODEL`). Every
provider implements the same `LLMProvider.narrate(system_prompt, user_prompt) ->
str` interface (`app/llm/base.py`) and raises `LLMError` on any failure — the
route catches this and returns the deterministic plan with a
`narrative_error` note rather than losing the result.

**Feature flag:** AI Assist is off by default, gated by the `ai_assist_enabled`
setting in `app_settings.json` (same atomic-write pattern as
`external_api_enabled`). Toggle it in **Admin → AI Assist**. `GET
/api/rule-review/ai-assist-status` reports current availability to the frontend;
when disabled, the panel stays visible but shows a disabled notice and disables
the submit button (the form itself is not hidden).

**Required setup files:** `app/planner/standards.py` reads `naming.yaml` and
`review_requirements.yaml` from the project root (both gitignored, runtime
data — same pattern as `policy_db.json`). Copy the tracked examples before
using AI Assist: `cp naming.example.yaml naming.yaml` and `cp
review_requirements.example.yaml review_requirements.yaml`, then edit them to
match your team's actual naming/approval standards. A missing file surfaces as
a `502` with an actionable message (`PlannerDataError`) rather than a raw
`FileNotFoundError`.

**Endpoint:** `POST /api/rule-review/ai-assist` — body: `{ src, dst, service,
firewalls: [{device, adom}], ticket_id?, justification?, src_group?, dst_group? }`.
Runs `plan_change()` against live FMG data, then narrates the result with the
configured provider. Returns `{ plan, narrative, narrative_error, path_relevance
}` — `plan` (the deterministic verdict) is always present; `narrative` is
best-effort and `narrative_error` explains why it's null on failure. FMG API
errors (`FMGError`, e.g. an authentication or JSON-RPC failure) surface as
`502`; a raw network-level failure (e.g. connection refused) is not currently
wrapped as `FMGError` and would surface as a `500` — a known, separate gap in
`app/fmg_client.py`. The LLM call itself is never allowed to turn a good plan
into a lost result.

### Zone Policy tab

`GET /zone-policy` → `zone_policy.html` + `zone_policy.js`

Self-contained network segmentation policy browser. No FortiManager connection required — all data comes from `policy_db.json` in the project root.

Three sub-tab panels, read-only for all users:
1. **Query Flow** — enter source/destination IPs (multi-line or comma-separated), optional service, get ALLOWED/BLOCKED/UNKNOWN verdict with governing rules
2. **Browse** — zone accordion list (searchable, filterable) + full policy table (filterable by access type/severity)
3. **Segmentation Health** — effectiveness score, open zone-pair list, and trust-boundary mismatch report (see below)

**Validate** and **Edit Database** live under **Admin → Zone Policy** (admin only) — see the Admin tab section below. This keeps the Zone Policy tab fully read-only for every user and consolidates all `policy_db.json` write operations in Admin.

Backend: `app/zone_db.py` is the single source of truth — query engine, validation, and all CRUD mutations. It writes back to `policy_db.json` atomically. Routes in `app/routes/zone_routes.py`:
- `POST /api/zone/query` — flow query (tab_required)
- `GET /api/zone/zones`, `GET /api/zone/policies`, `GET /api/zone/validate`, `GET /api/zone/segmentation-report` — read-only (tab_required)
- Zone/subnet/policy mutation routes — admin_required

**Segmentation Health report** (`zdb.compute_segmentation_report()`): for every ordered zone pair (A→B, A≠B), flags pairs with at least one `allow all` policy as "open"; score = `1 - open_pairs/total_pairs`, as a percentage. Also surfaces **trust-boundary mismatches** — pairs where both zones have an optional `trust_level` (0–100) set, the trust delta is ≥40, and an `allow all`/`allow only` policy connects them (e.g. a low-trust Guest zone with open access into a high-trust Server zone). `trust_level` is opt-in per zone; pairs are skipped from mismatch analysis unless both zones have it set, so an un-annotated database produces no false positives. Editable via **Admin → Zone Policy → Modify Zone Field** (`trust_level` in `ZONE_MUTABLE_FIELDS`), integer 0–100 or blank to clear.

Zone evaluation logic: block all > block only (service match) > allow only (service match) > allow all > implicit UNKNOWN. Zone hierarchy is supported via `parents[]` and zone name expansion.

**Access types:**
- `allow all` — permits all traffic between zones regardless of service
- `allow only` — permits traffic only if the requested service matches the policy's service list; non-matching services fall through to later rules (allowlist semantics)
- `block all` — denies all traffic between zones regardless of service
- `block only` — denies traffic only if the requested service matches the policy's service list (denylist semantics)

#### policy_db.json

Runtime data file (gitignored). Copy from a known-good source or build from scratch. Structure:

```json
{
  "zones": {
    "ZoneName": {
      "domain": "Default", "is_shared": false, "description": "",
      "subnets": [{"subnet": "10.1.0.0/16", "description": ""}],
      "children": [], "parents": [],
      "trust_level": 90
    }
  },
  "policies": [
    {
      "policy_set": "Corp", "from_zone": "ZoneA", "to_zone": "ZoneB",
      "access_type": "allow all", "severity": "high",
      "services": [], "description": ""
    }
  ]
}
```

#### Standalone production deployment

4THealth+ can run standalone (without FortiManager) if only the Zone Policy tab is needed. The only requirement is `policy_db.json`. All other tabs degrade gracefully when FMG is unreachable. To deploy standalone (an admin account is needed to reach Admin → Zone Policy for validation/editing):

1. Copy `policy_db.json` to the project root
2. Create `users.json` with at least one account (`python manage_users.py add ...`)
3. Set `SECRET_KEY` and optionally `FMG_PRIMARY_HOST` in `.env`
4. Generate TLS certs: `openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes`
5. Run: `gunicorn --workers 2 --threads 4 --worker-class gthread --bind 0.0.0.0:5443 wsgi:app`

### Map tab (Beta)

`GET /map` → `map.html` + `map.js`

Interactive Leaflet map displaying all managed devices in selected ADOMs. Device markers color-coded by health status (green/yellow/red/offline). Backend: `app/map_cache.py` maintains in-memory device cache with periodic refresh from FortiManager; `app/map_regions.py` provides regional grouping. Routes in `app/routes/map_routes.py`:
- `GET /map` — page (tab_required)
- `GET /api/map/devices` — device list with coordinates (filtered by ADOM access)

#### Map → Firewalls deep-link

`map.html` injects `window._canSeeFirewalls = {{ ('firewalls' in allowed_tabs) | tojson }}` before `map.js` loads. When `true`, each device popup includes a **View Details →** anchor linking to `/firewalls?device=<encodeURIComponent(device.name)>&adom=<encodeURIComponent(device.adom)>`. `firewalls.js` reads these params in `checkDeepLink()` at page load, pre-fills `#searchInput`, calls `doSearch()`, then auto-clicks the matching `[data-device]` button to open the detail modal. The URL is cleaned with `history.replaceState()` immediately after reading params.

#### Health status ledger

`#mapHealthLedger` is a `position:fixed` overlay (bottom-right, `z-index:1000`) populated by `updateHealthLedger()` in `map.js`. It counts `.status` values from the `allDevices` array and displays four `.ledger-item` spans using `.status-dot` color classes (`green`, `yellow`, `red`, `offline`). Called once from `loadDevices()` after `renderMarkers()`. Fleet-wide counts — not affected by ADOM filter.

New CSS classes added to `style.css`: `.map-health-ledger`, `.ledger-item`, `.map-popup-footer`, `.map-popup-details-link`.

### Config-Delta tab

`GET /pending-changes` → `pending_changes.html` + `pending_changes.js`

Shows FortiManager install-preview diffs per device. All operations are read-only — the tab triggers FMG's install-preview workflow but never pushes any configuration to devices.

**Workflow:**
1. Select ADOM → device table loads with sync status for every device (parallelised, 10-worker thread pool).
2. Optionally filter by name/IP, or check **Pending only** to show only devices with outstanding changes.
3. Click a device row → diff panel fetches and renders the per-VDOM CLI diff.
4. Click **+ Add to Export Queue** to stage the diff for bulk export.
5. Export the queue as CSV, JSON, or PDF.

**Status fields per device:**

| Field | Values | Meaning |
|---|---|---|
| `conf_status` | `insync` / `outofsync` | Device config vs. FMG database |
| `db_status` | `modified` / `nochange` | FMG database has changes not yet installed |
| `pkg_status` | `modified` / `nochange` | Policy package modified but not yet installed |

Table rows show a single compact badge (highest-priority state). The diff panel header shows all three badges simultaneously.

**Diff generation:** `get_install_preview()` in `app/fmg_client.py` chains four FMG JSON-RPC calls: stage the modified package (`/securityconsole/install/package`, `flags=["preview"]`) → generate the combined preview (`/securityconsole/install/preview`) → fetch the CLI text (`/securityconsole/preview/result`) → cancel the pending-install lock (`/securityconsole/package/cancel/install`). `get_package_info()` treats FMG 7.6.x's `"conflict"` package status the same as `"modified"` for staging purposes (7.4.x never returns `"conflict"`). `preview/result` is looked up first by the `install/preview` task's own ID (the key confirmed working on FMG 7.4.10), falling back to the staging task's ID if that returns no diff (required on FMG 7.6.7) — this fallback ordering was reverse-engineered by capturing FMG 7.6.7's own GUI JSON-RPC traffic. `parse_preview_diff()` then parses the raw CLI text into `{type: "add"|"remove"|"modify", line: str}` objects grouped by VDOM.

**Export queue:** Multiple devices can be staged before exporting. Changing ADOM clears the queue with a confirmation prompt. Each export includes a metadata header (ADOM, device list, timestamp, username via `PC_USER` template global).

**Routes in `app/routes/pending_changes_routes.py`:**
- `GET /pending-changes` — page (tab_required)
- `GET /api/pending-changes/adoms` — ADOM list (forti-prefix filtered, ADOM-access filtered)
- `GET /api/pending-changes/adoms/<adom>/devices` — device list with status fields
- `POST /api/pending-changes/adoms/<adom>/device/<device>/preview` — trigger + return parsed diff
- `GET  /api/pending-changes/ai-summary-status` — reports whether AI Summary is available (reads the `ai_assist_enabled` app-settings flag)
- `POST /api/pending-changes/adoms/<adom>/device/<device>/ai-summary` — body: `{ summary, vdoms }` — the parsed diff already held in memory from the preview task result; narrates it via `app/pending_changes_ai.py`; returns `{ narrative, narrative_error }`, never a 500 (400 if `vdoms` is missing or not a list)

AI Summary ("Summarize with AI" on the Config-Delta diff panel) reuses the
same `ai_assist_enabled` app-settings flag as Rule Validation's AI Assist,
Device Review's AI Summary, and Rule Hygiene's AI Explain (Admin → AI
Assist) — there is no separate Config-Delta toggle.

### Scheduled Exports

Two scheduler modules support recurring exports: Config-Delta diffs (`app/config_diff_scheduler.py`) and Device Review CIS audit results (`app/device_review_scheduler.py`). Both are APScheduler-based, persist jobs in gitignored JSON files, and are registered in `app/__init__.py` alongside other background schedulers.

#### Config-Delta Scheduled Jobs

`app/config_diff_scheduler.py` — APScheduler-based export engine supporting scheduled jobs on one or more days of the week. Persists jobs and run history in `config_diff_jobs.json` (project root, gitignored); jobs store `days_of_week` (array of day codes like `["MON","THU"]`) that APScheduler converts to a comma-joined lowercase cron string. Reuses `bulk_preview_adom()` from `app/routes/pending_changes_routes.py` for the actual FMG diff fetching.

`app/smtp_client.py` — stdlib `smtplib` wrapper. Config in `smtp_config.json` (project root, gitignored). `send_email()` raises on failure; `test_connection()` always returns a dict.

**Admin UI:** Admin → Scheduled sub-tab. SMTP form + jobs table. JS in `app/static/js/admin.js`.

**Persistence pattern:** Same as `app_settings.json` / `api_tokens.json` — atomic JSON writes via `app/atomic_io.py`, threading.Lock for concurrent access.

**Run history pruning:** On each successful job execution, records older than `run_history_days` (default 30) are removed from `runs[]` in `config_diff_jobs.json`.

**AI Summary:** When `ai_assist_enabled` is on AND the job's own `ai_summary_enabled` field (default `true`) is also on, reports include an AI-generated summary section (best-effort — silently omitted if narration fails, never blocks report delivery). The section is also omitted entirely when no device in the run has any actual diff changes (e.g. a fully in-sync ADOM), so a no-op run never triggers an LLM call or shows empty prose. A narration failure is recorded as `ai_narrative_error` on the run history entry in `config_diff_jobs.json`. Per-job `ai_summary_enabled` lets a job be scheduled without incurring any LLM token cost even while the global AI Assist flag stays on for other features — toggled via the "AI Summary" checkbox on the job form in Admin → Scheduled.

#### Device Review Scheduled Jobs

`app/device_review_scheduler.py` — APScheduler-based scheduler mirroring `config_diff_scheduler.py`.

Persists jobs in `device_review_jobs.json` (gitignored; copy `device_review_jobs.example.json` to create).

**Job schema:**
```json
{
  "id": "uuid",
  "name": "Weekly CIS Audit",
  "adom": "Enterprise Services",
  "days_of_week": ["MON", "FRI"],
  "time": "02:00",
  "checks": ["ntp_config", "trusted_hosts"],
  "check_params": { "ntp_config": { "expected_servers": "10.1.1.1" } },
  "email": "alice@corp.com, bob@corp.com",
  "format": "pdf",
  "enabled": true,
  "ai_summary_enabled": true,
  "runs": [...]
}
```

`checks`: list of check keys from `CHECKS_META`; empty list = run all 18.
`check_params`: only entries for parameterized checks; omitted keys = `CONFIG_MISSING`.
`email`: comma-separated string — `smtp_client._parse_recipients()` handles splitting.
`ai_summary_enabled`: default `true`; when `false`, the scheduled run never calls the LLM for its AI Summary section even if `ai_assist_enabled` is globally on — set per-job in Admin → Scheduled to avoid unwanted token spend on jobs that don't need narration.

**`bulk_device_review_adom(adom, checks, check_params, max_workers=4)`** in `app/routes/device_review_routes.py` — session-free entry point for the scheduler. Uses `ThreadPoolExecutor(max_workers=4)`.

**Admin API endpoints** (all `admin_required`):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/api/device-review/jobs` | List all Device Review scheduled jobs |
| `POST` | `/admin/api/device-review/jobs` | Create a new job |
| `PUT` | `/admin/api/device-review/jobs/<id>` | Update an existing job |
| `DELETE` | `/admin/api/device-review/jobs/<id>` | Delete a job |
| `POST` | `/admin/api/device-review/jobs/<id>/run` | Trigger an immediate run |
| `GET` | `/admin/api/device-review/jobs/<id>/status` | Get last run status / history |

**Scheduled report output:** Email reports include a **per-host summary table** at the top of both the email body and the attached file (HTML, CSV, and JSON formats), showing per-device counts for each result type: Device | PASS | FAIL | INSECURE | WARN | CONFIG_MISSING | INFO | Total. The per-check aggregate summary follows below the host summary in the email body. When `ai_assist_enabled` is on AND the job's own `ai_summary_enabled` field (default `true`) is also on, reports also include an AI-generated summary section (best-effort — silently omitted if narration fails, never blocks report delivery). Toggled via the "AI Summary" checkbox on the job form in Admin → Scheduled.

#### Rule Hygiene Scheduled Jobs

`app/rule_hygiene_scheduler.py` — APScheduler-based scheduler mirroring `device_review_scheduler.py`.

Persists jobs in `rule_hygiene_jobs.json` (gitignored; copy `rule_hygiene_jobs.example.json` to create).

**Job schema:**
```json
{
  "id": "uuid",
  "name": "Weekly Rule Hygiene",
  "adom": "Enterprise Services",
  "days_of_week": ["MON", "FRI"],
  "time": "03:00",
  "checks": ["unnamed", "unlogged"],
  "include_unused_objects": false,
  "batch_size": 20,
  "format": "html",
  "email": "alice@corp.com",
  "enabled": true,
  "runs": [...]
}
```

`checks`: list of check keys from `hygiene.CHECKS`; empty list = run all 9.
`include_unused_objects`: when true, fetches ADOM-level address/service catalogs once and runs `find_unused_objects()` per package.
`batch_size`: number of per-package report files per zip email (1–100, default 20). For ADOMs with more packages than `batch_size`, multiple emails are sent: email 1 has the full summary table + Part 1 zip; subsequent emails contain a `[Part N of M]` subject and the next zip.

**`bulk_hygiene_adom(adom, checks, include_unused_objects, max_workers=4)`** in `app/routes/hygiene_routes.py` — session-free entry point for the scheduler. Uses `ThreadPoolExecutor(max_workers=4)`. Scope member data (via `FMGClient.get_pkg_scope_members`) is used to determine the device name for file naming. Unlike the interactive `/api/hygiene/run` path, the scheduler does not overlay live per-device hit counts for the `unhit` check (too expensive across every package in an ADOM) and always pre-fetches address/service catalogs once per ADOM for the `shadow`/`redundant` resolvers, rather than only when those checks are selected.

**Admin API endpoints** (all `admin_required`):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/api/rule-hygiene/jobs` | List all Rule Hygiene scheduled jobs |
| `POST` | `/admin/api/rule-hygiene/jobs` | Create a new job |
| `PUT` | `/admin/api/rule-hygiene/jobs/<id>` | Update an existing job |
| `DELETE` | `/admin/api/rule-hygiene/jobs/<id>` | Delete a job |
| `POST` | `/admin/api/rule-hygiene/jobs/<id>/run` | Trigger an immediate run |
| `GET` | `/admin/api/rule-hygiene/jobs/<id>/status` | Get last run status / history |

### External API

`app/routes/external_api_routes.py` — blueprint at `/external/api/`

Provides read-only zone policy access to external programs (e.g. FW-Analyst) via bearer token authentication. No browser session is required.

**Feature gate:** The external API is disabled by default. Enable it in **Admin → External API** — this writes `{"external_api_enabled": true}` to `app_settings.json`. Disabling it returns 503 on all `/external/api/` requests without touching token records.

**Authentication:** Every request must include `Authorization: Bearer <token>`. Tokens are created in Admin → External API → New Token. Plaintext is shown once; only the SHA-256 hash is stored in `api_tokens.json`.

**Endpoints (all read-only):**
- `POST /external/api/zone/query` — same payload/response as internal `/api/zone/query`
- `GET  /external/api/zone/zones` — zone list
- `GET  /external/api/zone/policies` — policy list
- `GET  /external/api/executive/summary` — fleet-wide metrics for the 4tExecutive dashboard (hygiene score, version compliance %, pending config-diff count, firewall online count/total); backed by `app/executive_summary_cache.py`, which runs TWO independent scheduled sweeps at different cadences — a cheap device sweep (online count, version compliance, pending diffs; default every 15 min, `EXEC_SUMMARY_REFRESH_MINUTES`) and an expensive hygiene sweep (downloads every policy in every ADOM; default every 60 min, `EXEC_SUMMARY_HYGIENE_REFRESH_MINUTES` — raise this in large environments to reduce FMG load). Each sweep only updates its own fields in the shared store, so a slow hygiene sweep never blanks out fresh device data.

**CSRF:** `/external/api/` requests are exempt from CSRF validation (bearer token is the auth mechanism, no session cookie exists).

**Supporting modules:**
- `app/app_settings.py` — atomic read/write of `app_settings.json` (feature flags)
- `app/api_tokens.py` — token create/list/revoke/validate; tokens stored as SHA-256 hashes
- `app/executive_summary_cache.py` — background sweep computing the four executive-summary metrics; same pending|running|ok|error store pattern as `summary_job.py`

**Admin endpoints added to `admin_routes.py`:**
- `GET/PUT /admin/api/settings` — get/set `external_api_enabled` and `executive_compliant_versions`
- `GET /admin/api/tokens` — list tokens
- `POST /admin/api/tokens` — create token (returns plaintext once)
- `DELETE /admin/api/tokens/<id>` — revoke token

### Pending Changes tab

`GET /pending-changes` → `pending_changes.html` + `pending_changes.js`

Shows FortiManager install-pending changes — config committed in FortiManager but not yet pushed to physical FortiGate devices. Uses the FMG Install Preview API (async task-based diff generation).

**Tab key:** `pending_changes`

**Workflow:**
1. Select ADOM → device list loads with sync status badges.
2. Optionally filter via search (name or IP) or "Pending only" toggle.
3. Click a device → right panel shows spinner while FMG generates the diff (10–60s).
4. Diff renders as CLI-format lines grouped by VDOM (add/remove/modify).
5. "Add to Export Queue" → chip appears in sticky footer bar.
6. Export queue: CSV, JSON, or PDF covering all queued devices in one document.

**`conf_status` integer-to-string mapping** (from FMG dvmdb):
- `0` → `"unknown"`
- `1` → `"insync"`
- `2` → `"outofsync"`

The "Pending only" toggle filters the device list by `conf_status`. It does not gate the preview call — clicking any device always triggers a live preview because `conf_status` can lag behind actual state.

**New FMGClient methods** (`app/fmg_client.py`):

`get_devices_with_sync_status(adom)` — calls `/dvmdb/adom/{adom}/device`; normalises `conf_status` integer to string.

`get_install_preview(adom, device)` — async three-step:
1. POST `/securityconsole/install/preview` → `taskid`
2. Poll `/task/task/{taskid}` every 2s until `percent == 100` (timeout: `PREVIEW_TIMEOUT_SECS = 90`)
3. GET `/securityconsole/preview/result/{adom}` → raw CLI diff text

`parse_preview_diff(raw)` — module-level helper; parses CLI diff into `{summary, vdoms, raw}`. **Implementation note:** The FMG preview output format must be verified against a real FMG instance — the parser in `_classify_lines()` may need adjustment based on actual output. The `raw` field is always returned so the frontend has an unprocessed fallback.

**Export queue pattern:** Export queue is client-side only (`exportQueue` array in `pending_changes.js`). Queue clears on ADOM change (with confirmation dialog). CSV/JSON/PDF exports cover all queued devices in one document.

**API endpoints:**
- `GET  /api/pending-changes/adoms` — ADOM list (filtered by access)
- `GET  /api/pending-changes/adoms/<adom>/devices` — device list with `conf_status`
- `POST /api/pending-changes/adoms/<adom>/device/<device>/preview` — trigger preview, return structured diff

### Admin tab

`GET /admin` → `admin.html` + `admin.js` (admin only)

Above the sub-tab bar, three **host resource graphs** (CPU/Memory/Disk) show
the resource usage of the host running this app, with a range-pill selector
(`1h/4h/12h/1d/7d/14d`). Sampled every 60s by `app/host_metrics.py`
(`record_sample()`, mirrors `app/ai_usage.py`'s SQLite pattern) into
`host_metrics.db` (gitignored, project root); a daily job prunes rows older
than 90 days. `GET /admin/api/host-metrics?range=` returns time-bucketed
`{cpu, mem, disk}` series. Charts are rendered as plain CSS/JS bar charts
(`admin.js`, `.hm-*` CSS classes) — same hand-rolled style as the AI Usage
chart, no charting library dependency. The Memory card shows an info-icon
tooltip ("Reflects host memory — container memory limit may differ.") when
`os.path.exists('/.dockerenv')` is true (passed to the template as
`in_docker`).

`GET /admin/api/host-metrics/ai-summary` computes deterministic 7-day
trend stats for CPU/mem/disk (`app/host_metrics_ai.py::compute_trend()` —
plain arithmetic, no LLM) plus the 7-day AI Assist usage summary, then
narrates them via the configured LLM provider
(`build_trend_narrative()`); returns `{ trends, narrative,
narrative_error }` — narration failure degrades to `narrative: null` with
`narrative_error` set, never a 500. `503` if AI Assist is disabled. Reuses
the same `ai_assist_enabled` app-settings flag as Rule Validation's AI
Assist, Device Review's AI Summary, Rule Hygiene's AI Explain, and
Config-Delta's AI Summary (Admin → AI Assist) — there is no separate
host-metrics toggle.

Sub-tabs: Groups & Permissions, Map Region Colors, External API, AI Assist,
Scheduled, Backup, **Zone Policy**, Application Logs.

**Zone Policy sub-tab** — Validate and Edit Database (zone/subnet/policy
rule CRUD against `policy_db.json`) moved here from the Zone Policy nav tab
so all writes to `policy_db.json` are UI-gated to admins, not just API-gated
(see [Zone Policy tab](#zone-policy-tab)). The JS (`admin.js`, under
`// --- Zone Policy Edit ---`) is lazy-loaded the first time the sub-tab is
clicked and posts to the same `/api/zone/*` mutation routes as before — no
backend changes.

**Backup sub-tab** — remote transfer supports **SFTP, FTP, and SCP**
(`app/backup_scheduler.py::transfer_file()` / `test_connection()`). SCP uses
the `scp` PyPI package (`SCPClient`) over the same `paramiko` SSH transport
as SFTP; default port 22, same field set as SFTP (host/port/username/
password/remote dir) — no new form fields. The FTP-plaintext warning banner
only shows for `protocol === 'ftp'`.

## Dependency management

This project uses `uv`. `uv.lock` is committed; `pyproject.toml` should be too. Do not use `pip install` directly — use `uv add <package>` to keep the lockfile in sync.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A `.githooks/post-commit` hook automates this on every commit. One-time setup per clone: `git config core.hooksPath .githooks`.
