# Feature Reference

## Managed Network Summary

The **summary bar** at the top of the Dashboard shows the total scale of the managed firewall estate.

| Stat | Source | Meaning |
|---|---|---|
| **Managed Firewalls** | `dvmdb` device count per ADOM | Total FortiGate devices registered across all ADOMs with at least one device |
| **Policy Rules Managed** | Policy package enumeration | Sum of all firewall policy entries across every package in every active ADOM |

Data is **never calculated on page load**. A background job runs instead:

1. **On app startup** — fires automatically, stores results in memory. The Dashboard shows spinners while the calculation runs (typically 4–5 minutes on large instances).
2. **Nightly at 01:00** (configurable via `SUMMARY_REFRESH_HOUR`) — APScheduler triggers a fresh calculation.
3. **On demand (admin only)** — `POST /api/summary/refresh` kicks off an immediate recalculation.

FortiManager has no single "total rule count" API. The job enumerates every ADOM, skips empty system ADOMs, enumerates every policy package, and fetches policy IDs per package. On a production instance with ~135 packages and ~14,700 rules this takes roughly 4–5 minutes.

---

## Rule Review

Four independent sections on a single page: **Policy Rules**, **Object Lookup**, **Interface Lookup**, and **NAT Lookup**. All analysis is read-only. (The **Hygiene Analysis** panel that used to live here moved to the [Audit Review](#audit-review) tab.)

### Policy Rules

1. Select an **ADOM** and **Policy Package** — the full rule table loads automatically.
2. Search using the full-text search box (supports regex). Optionally scope the search to a single field.
3. Click any address group or service group triangle to expand its members inline.
4. Page through rules using 10 / 25 / 50 / 100 per-page pagination.
5. Export as **CSV**, **JSON**, or **PDF** — each export includes a filter context header.

---

## Audit Review

Three sections on a single page: **Device Review** (management-interface + CIS hardening checks), **Hygiene Analysis** (policy rule checks, moved here from Rule Review), and **PSIRT Advisory Assessment**. All analysis is read-only.

### Device Review

Runs configurable security checks against the management-plane interfaces of every device in a selected ADOM.

#### Workflow

1. Select an ADOM — the device grid loads with all devices selected by default.
2. Filter or deselect devices using the searchable grid.
3. Choose which checks to run (all enabled by default).
4. Click **Run Analysis** — findings appear in a filterable, paginated table.
5. Export results as **CSV**, **JSON**, or **PDF** (PDF includes ADOM, timestamp, and device count — suitable as compliance evidence).

#### Result Values

| Result | Meaning |
|---|---|
| `INSECURE` | Red — cleartext protocol (HTTP, Telnet) is enabled |
| `FAIL` | Red — CIS check failed (server missing, sync disabled, etc.) |
| `WARN` | Yellow — CIS host check — service is active but configured servers do not match expected (NTP, Syslog, FortiAnalyzer, DNS); effectively unreachable for Interface Protocols (unknown protocols default to informational) |
| `CONFIG_MISSING` | Yellow — CIS check ran but no expected values supplied; device value shown for information |
| `PASS` | Green — CIS check passed |
| `INFO` | Blue — informational finding (e.g. PING enabled) |

**Protocol Severity Override:** Protocol classifications (secure/insecure/informational) can be customised without code changes. Copy `protocol_severity.example.json` to `protocol_severity.json` at the project root and edit values. Valid values: `secure`, `insecure`, `info`, `null`. Changes take effect on app restart. Interfaces with only informational protocols (e.g. `ping`, `fgfm`) report **INFO**. The **WARN** result is effectively unused for Interface Protocols — unknown protocols default to `None` (informational), so WARN is unreachable in practice.

**CIS Host Checks (NTP, Syslog, FortiAnalyzer, DNS):** These checks return **WARN** (amber) when the service is active but the configured servers do not exactly match the expected addresses. **FAIL** is reserved for when the service is completely disabled or unconfigured. IP addresses and FQDNs are both matched via DNS resolution.

#### AI Summary

*Admin-gated (`ai_assist_enabled` in Admin → AI Assist).* After running an analysis, a **Summarize with AI** button generates a short plain-English summary of the results — overall posture and which devices/checks need attention first — from the aggregated check counts plus the FAIL/INSECURE findings (capped, never the full per-interface result set). The same summary is generated automatically (best-effort) for scheduled Audit Review email/PDF reports when the flag is enabled.

#### Adding a New Check

The check registry in `app/device_review.py` is the single place to add checks:

```python
{
    "key":          "my_check",
    "name":         "Display Name",
    "description":  "One-line summary",
    "data_keys":    ["interfaces"],       # which device data blobs to fetch
    "params_schema": [],                  # [] = binary, or list of input descriptors
    "run":          _my_check_function,   # callable(device_name, device_data, params) -> list[Row]
}
```

### Hygiene Analysis

1. Select an **ADOM** and **Policy Package** (independent from the Device Review selectors above).
2. Choose the checks to run (all enabled by default).
3. Click **Run Analysis**.
4. Filter by text or check category, and export findings as **CSV**, **JSON**, or **PDF**.

### Available Checks

| Check | Display name | What it finds |
|---|---|---|
| `unnamed` | Unnamed Rules | Rules with no name and/or no comment |
| `unlogged` | Unlogged Rules | Rules where `logtraffic` is disabled or not set |
| `shadow` | Shadow Rules | Enabled rules unreachable because a broader any/any/any rule appears above them |
| `disabled` | Disabled / Inactive Rules | Rules whose `status` field is `disable` |
| `expired` | Expired Rules | Rules referencing a time-based schedule whose end-date has passed |
| `unhit` | Unused / Un-Hit Rules | Rules where the hit counter is 0 |
| `missing_security_profile` | Missing Security Profiles | Accept rules with `utm-status` disabled, or UTM enabled but no IPS/AV/webfilter/DNS filter/application-control profile attached |
| `redundant` | Redundant Rules | A rule whose src/dst/service scope is fully covered by an earlier rule with the same action |
| `over_permissive` | Over-Permissive Rules | Accept rules where 2+ of source/destination/service are unrestricted (`all`/`ANY`) — `critical` when all three are, `high` when two are |

### Exempting a Rule From Hygiene Checks

Add the word **"Exempt"** anywhere in a rule's comment field (case-insensitive — e.g. `"Exempt -- approved by security, CHG0012345"`) and every hygiene check silently skips that rule on every future run, regardless of which checks are selected. This is the whitelist mechanism for rules that were reviewed and intentionally kept as-is, so they stop reappearing in every report.

Implementation: `app/hygiene.py::_is_exempt()` checks the rule's `comments`/`comment` field for the substring `"exempt"` (lower-cased). `run_checks()` runs every check against the **full** policy list first — exempted rules are *not* removed from the input, only from the returned findings — so shadow/redundant analysis for other rules stays correct: an exempted rule still counts as the earlier/broader rule when determining whether it shadows something else. Applies uniformly to both interactive runs and Scheduled Rule Hygiene jobs (both go through `run_checks()`).

This closes the loop with Hygiene Fix's over-permissive "Exempt (keep enabled)" option below, which writes a `[HygieneFix EXEMPT YYYY-MM-DD]` comment tag — choosing that fix for a rule now also marks it exempt for future Hygiene Analysis runs.

### AI Explain

*Admin-gated (`ai_assist_enabled` in Admin → AI Assist).* Each finding row can be expanded to reveal an **Explain** button. One click sends that single finding (never the whole result set) to the configured LLM, which returns a plain-English explanation of why it matters plus a suggested FortiOS CLI remediation snippet — the LLM never runs or overrides a check, and the snippet is a suggestion for a human reviewer, not something the app applies automatically.

### PSIRT Advisory Assessment

Paste or upload (`.eml`/`.txt`) a Fortinet PSIRT advisory email. An LLM extracts structured fields — advisory ID, CVE IDs, affected version ranges, workaround text, severity, exploitation wording — into an editable review form; this is the only LLM touchpoint in the feature. Everything downstream is deterministic: the app scans the selected ADOM (or every accessible ADOM) for affected firmware and whether a documented workaround is already applied, then computes a priority from CVSS band, Fortinet's exploitation wording, and CISA KEV catalog membership. Each completed assessment is downloadable as a standalone HTML report. Admin-gated by the same `ai_assist_enabled` flag as the rest of AI Assist.

**Persistence:** every completed assessment (run from the UI, via `POST /api/audit-review/psirt/assess`) is saved to `psirt.db` (gitignored, project root) — see `app/psirt_store.py`. Two tables: `advisories` (one row per advisory, upserted — CVEs, CVSS, severity, KEV flag, affected ranges, workaround text, `created_at`/`closed_at`) and `assessments` (append-only history of runs, each with `devices_affected` and a `summary`). The **Open PSIRT Advisories** panel below the results table lists every saved advisory that hasn't been closed, with its most recent device-affected count, and a **Close advisory** button that sets `closed_at` — once closed, the advisory stops counting toward fleet exposure (see below) and stops being re-checked by the scheduler.

**Scheduled re-assessment:** a background job (`app/psirt_reassess_scheduler.py`) re-runs `app.psirt.engine.assess()` for every still-open advisory on the same cadence as the executive-summary device sweep (`EXEC_SUMMARY_REFRESH_MINUTES`, default 15 minutes), so exposure stays current without the user re-running anything. It reuses that sweep's already-cached device inventory (`app.executive_summary_cache.get_devices_raw_by_adom()`) rather than making a fresh FMG download — a `_CachedDeviceClient` stand-in supplies `get_adoms()`/`get_devices()` from the cache. Two things that inventory can't provide are handled as expected degradations rather than failures: a FortiManager-itself finding (when an advisory names FortiManager) reports as a warning since the cached inventory has no FMG version, and workaround verification (which needs live per-device config reads) falls back to `manual_verification_required` per device. A per-advisory failure during the sweep skips saving for that advisory only — its last successful result is left untouched — and the sweep continues with the next one.

---

## Config-Delta

Shows exactly which FortiOS CLI configuration lines will change when the next install is pushed to a device. Useful for change-record preparation and pre-change validation.

All calls are read-only — the tab triggers FortiManager's install-preview workflow via the JSON-RPC API but never pushes any configuration to devices.

### Workflow

1. Select an **ADOM** — the device table loads, showing all devices with their current sync status.
2. Optionally filter by device name or IP, or check **Pending only** to show only devices with outstanding changes.
3. Click any device row — the diff panel populates with a per-VDOM CLI diff.
4. Review the colour-coded diff: **green** lines are additions (`+`), **red** lines are deletions (`-`), **amber** lines are modifications (`~`).
5. Click **+ Add to Export Queue** to accumulate multiple devices into a single export document.
6. Export the queue as **CSV**, **JSON**, or **PDF** for use in a change record.

### Status Badges

The device table shows a single compact badge per device representing the highest-priority state:

| Badge | Meaning |
|---|---|
| **Out of Sync** | Device config has drifted from FortiManager — a re-install is required |
| **Pending** | FortiManager database has changes not yet pushed to the device |
| **Pkg Pending** | Policy package has been modified in FortiManager but not yet installed |
| **In Sync** | Device is fully in sync with FortiManager |

The diff panel header shows the full set of badges simultaneously (conf\_status, db\_status, and pkg\_status).

### Summary Tiles

Above the CLI diff, count tiles group changes by category: **Firewall Policy**, **Routing**, **Address**, **Service**, **System**, **Other**. Only categories with at least one change are shown.

### Export Queue

Devices can be staged into an export queue one at a time. The queue persists across device selections in the same ADOM. Changing ADOM clears the queue (with a confirmation prompt).

Each export includes a metadata header with ADOM, device list, timestamp, and username.

### Backend

`parse_preview_diff()` in `app/fmg_client.py` chains two FMG JSON-RPC calls (trigger + poll) to retrieve the raw CLI diff text, then parses it into structured `{type, line}` change objects grouped by VDOM.

**API endpoints:**

| Method | Path | Description |
|---|---|---|
| GET | `/api/pending-changes/adoms` | List ADOMs accessible to the current user |
| GET | `/api/pending-changes/adoms/<adom>/devices` | Device list with `conf_status`, `db_status`, `pkg_status` |
| POST | `/api/pending-changes/adoms/<adom>/device/<device>/preview` | Trigger and return the install-preview diff |

Device status lookups (`pkg_status`) are parallelised with a thread pool (10 workers) to avoid 504 timeouts on large ADOMs.

### Bulk Export — Navigation Guard

While an "Export All" bulk export is running, the browser will prompt for confirmation before navigating away or closing the tab, preventing accidental cancellation of a long-running export.

### Scheduled Exports (Admin)

Admins can configure weekly scheduled Config-Delta exports in **Admin → Config-Diff**. Each job specifies an ADOM, day of week, time, export format (PDF/CSV/JSON), and an email recipient. Jobs run server-side via APScheduler and email the full diff report as an attachment with a summary in the email body. Run history (last 30 days by default) is visible per job.

Audit Review scheduled reports include a **Host Summary** table at the top of both the email body and the attached file, showing per-device counts for each result type (PASS, FAIL, INSECURE, WARN, CONFIG_MISSING, INFO, Total). The existing per-check aggregate summary remains in the email body below the host summary.

### AI Summary

*Admin-gated (`ai_assist_enabled` in Admin → AI Assist).* A **Summarize with AI** button in the diff panel generates a short plain-English description of what's actually changing (new/removed policies, address or service object changes, routing changes) from the parsed CLI diff — capped per device and per line count to keep the LLM payload bounded. The raw CLI diff is always shown/exported unmodified alongside the summary. Scheduled export emails include the same summary automatically (best-effort — silently omitted if narration fails or the ADOM has no changes to summarize).

---

## Rule Validation

Helps engineers validate firewall rule change requests before submitting them. For each requested flow it answers:

1. Is the traffic already permitted by an existing policy?
2. If blocked — can an existing rule be modified, or is a new rule needed?
3. Is the selected firewall actually in the traffic path?

All analysis is read-only.

### Workflow

1. **Define Flows** — enter source IP, destination IP, and port combinations manually, or import a CSV/XLSX file.
2. **Select Policy Packages** — pick an ADOM and package; repeat for multiple packages.
3. Click **Review** to start the analysis.

### Verdicts

| Verdict | Meaning |
|---|---|
| `PERMITTED` | An existing enabled rule matches and its action is `accept` |
| `EXPLICITLY_DENIED` | A rule matches and its action is `deny` |
| `MODIFIABLE` | A rule exists but needs adjustment (e.g. service or address expansion) |
| `NEW_RULE_NEEDED` | No matching rule found — a new policy entry must be created |

### CSV / XLSX Import

| Column (aliases accepted) | Description |
|---|---|
| `source` / `src` | Source IP address or CIDR subnet |
| `destination` / `dst` / `dest` | Destination IP address or CIDR subnet |
| `port` / `service` / `svc` | TCP/UDP port number, port name, or `tcp/8443` style |
| `comment` / `note` | Free-text reason (optional) |

Column order does not matter; headers are case-insensitive.

### Zone Policy Integration

When zone policy is configured, Rule Validation calls the zone policy API to check whether the requested flow is permitted at the network segmentation layer — independent of any specific firewall rule. If zone policy is not configured, the tab degrades gracefully (firewall policy analysis still works).

### Path Analysis

For each flow the engine fetches live routing table and interface data from FortiManager, then checks whether the source and destination IPs resolve to different interfaces on the selected device. A **⚠ Not In Path** result means the traffic likely routes through a different firewall.

### AI Assist

*Admin-gated (`ai_assist_enabled` in Admin → AI Assist).* Alongside the bulk CSV/XLSX table workflow above, the **AI Assist** panel offers three modes, selected by the buttons at the top of the panel. In every mode the verdict/plan/fix is always computed deterministically first — the LLM only narrates an already-computed result — and if narration fails, the deterministic output is still returned with a `narrative_error` note rather than a lost result. Multi-provider: Claude (default), Codex, or Ollama, selected server-wide via `AI_PROVIDER` in `.env`.

#### Single Change

A single-request mode: describe one change (source/destination/service/target firewalls, plus an optional ticket ID and justification) and get back a deterministic verdict — computed by the same ported, tested change-planning engine (`app/planner/`) as the bulk workflow above — an AI-written narrative report, and a peer-review package. **Endpoint:** `POST /api/rule-review/ai-assist`.

#### FQDN Allowlist

For vendor FQDN/wildcard-FQDN allowlist requests spanning multiple entries at once (e.g. a batch of Apple push-notification hostnames). Enter vendor, category, source IP, and target firewall(s), then either upload a vendor allowlist `.xlsx` or add rows manually (FQDN/wildcard, ports, protocol, required, comment). Produces a deterministic per-firewall coverage analysis plus proposed FortiGate CLI (address objects, destination group, policy) and an AI-written report. **Endpoint:** `POST /api/rule-review/ai-assist-fqdn`.

#### Hygiene Fix

Turns a completed Rule Hygiene run's findings into deterministic remediations. Paste or upload the findings export (JSON or CSV — from either the interactive Hygiene Analysis export or a Scheduled Rule Hygiene job's email attachment), select the ADOM + Policy Package the findings came from, and run it. `app/hygiene_fix.py::build_fixes()` re-fetches the live policy package fresh from FortiManager and matches each finding to its rule by `policy_id`; findings whose rule no longer exists (deleted or renumbered since the hygiene run) are returned separately as **stale**, never silently dropped.

- **Grouped by rule:** findings are stable-sorted by `policy_id` so every check that flagged the same rule appears together in the results (live view and the downloaded HTML report). Each finding also carries a `related_checks` list — shown as "Also flagged by: ..." — since two findings on the same rule can suggest conflicting remediations (e.g. Shadow's "narrow scope, keep enabled" vs. Unhit's "disable"); check for that before applying either.
- **Multiple fix options:** where a check has more than one viable remediation, radio buttons let you pick per-finding — **Shadow** offers disable / reorder above the shadowing rule / narrow the shadowing rule's scope (only when the differing dimension can be split safely without a wildcard); **Over-Permissive** offers disable / exempt (keep enabled). Choosing **Exempt** writes an `[HygieneFix EXEMPT YYYY-MM-DD]` comment tag, which Hygiene Analysis's checks then recognize as [an exemption](#exempting-a-rule-from-hygiene-checks) and stop re-flagging that rule.
- **Traceability tag:** every comment-changing fix appends a `[HygieneFix YYYY-MM-DD]` tag. A rule already disabled and tagged more than 90 days ago recommends outright deletion instead of re-tagging.
- **No guessed fixes:** checks with no safe automated remediation (`missing_security_profile`; an `unnamed` rule whose source *and* destination are both unrestricted) show an explanatory message instead of a CLI snippet — the tool never invents a placeholder value and applies it as real CLI.
- **Download HTML Report** — a standalone, shareable report reflecting your current per-finding option selections, generated entirely client-side (no server round trip), same as every other export in this app.

**Endpoint:** `POST /api/rule-review/ai-assist-hygiene-fix` — `multipart/form-data` with `adom`, `pkg`, and one of `findings_text` / `findings_file`. This app is read-only throughout: every generated CLI snippet, from any of the three modes, is a suggestion for human review — never applied by the app itself.

---

## Zone Policy

A self-contained network segmentation policy browser. It reads `policy_db.json` from the project root and requires no FortiManager connection.

### Sub-tabs

| Sub-tab | Description |
|---|---|
| **Query Flow** | Enter source/destination IPs (multi-line or comma-separated) and optional service; get an ALLOWED / BLOCKED / UNKNOWN verdict with the governing rule |
| **Browse** | Zone accordion list (searchable) and full policy table (filterable by access type and severity) |
| **Validate** | Schema validation report — error and warning counts |
| **Edit Database** | *(admin only)* Add/remove/modify zones, subnets, and policy rules; changes are written back to `policy_db.json` atomically |

### Zone Evaluation Precedence

Block all → block only (service match) → allow only (service match) → allow all → implicit UNKNOWN.

| Access Type | Semantics |
|-------------|-----------|
| `allow all` | Permits all traffic regardless of service |
| `allow only` | Permits traffic only if the service matches the list (allowlist); non-matching services fall through |
| `block all` | Denies all traffic regardless of service |
| `block only` | Denies traffic only if the service matches the list (denylist); non-matching services fall through |

### policy_db.json Format

```json
{
  "zones": {
    "ZoneName": {
      "domain": "Default", "is_shared": false, "description": "",
      "subnets": [{"subnet": "10.1.0.0/16", "description": ""}],
      "children": [], "parents": []
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

---

## Map (Beta)

Renders all managed FortiGate devices on an interactive OpenStreetMap base layer using Leaflet and the MarkerCluster plugin.

### Internet Connectivity

The **app server** requires no internet access — all JavaScript, CSS, and the US states GeoJSON are bundled under `app/static/vendor/`.

The **user's browser** makes tile requests to `https://{s}.tile.openstreetmap.org`. If this domain is blocked, the map shows a grey background but pins, clustering, and popups all continue to work. For air-gapped deployments, change the `L.tileLayer(...)` URL in `app/static/js/map.js` to point to a self-hosted tile server.

### Location Data

FortiManager stores `latitude` and `longitude` for each device. These can be set manually in **Device Manager → device properties → Location**, or inferred via IP geolocation (`location_from: diag`). Devices where both fields are `0.0` are silently excluded from the map.

Location data is fetched at app startup and re-fetched every 24 hours (configurable via `MAP_CACHE_INTERVAL_HOURS`).

### Map Features

| Feature | Detail |
|---|---|
| **Colour by region** | Device pins are coloured by US geographic region. Each region groups a configurable set of states and has its own hex colour. |
| **Clustering** | Nearby devices merge into a count bubble at low zoom levels. |
| **Device popup** | Click a pin to see name, region, ADOM, platform, firmware version, description, connection status, and exact coordinates. |
| **ADOM filter** | Checkboxes let users show/hide devices per ADOM instantly — no server round-trip. |
| **Refresh button** | Admin-only; triggers an immediate background refresh. |

### Region Configuration

Admins can add, rename, or delete regions and change state assignments and colours without restarting the app:

1. Navigate to **⚙ Admin → Map Region Colors**.
2. Click **+ Add Region** to create a new region, or edit an existing row.
3. Use the multi-select in each row to assign states. A state can only belong to one region.
4. Use the colour picker to set the pin colour.
5. Click **Save**.

Changes are written to `map_regions.json` and take effect on the next map page load. Default regions:

| Region | States | Default colour |
|---|---|---|
| Upper Midwest | Minnesota, Wisconsin, North Dakota, South Dakota | Blue (`#1976d2`) |
| Colorado | Colorado | Red (`#e53935`) |
| Southwest | Texas, New Mexico | Green (`#43a047`) |
| Other | Any state not in a named region | Near-black (`#333333`) |

---

## External API

Allows programs like **FW-Analyst** to query zone policy data programmatically without a browser session. All endpoints are read-only.

### Enabling

1. Log in as an admin and go to **Admin → External API**.
2. Check **External API enabled** and click **Save**.

When disabled (the default), all `/external/api/` requests return `503 {"error": "External API is disabled"}`.

### Token Management

1. Click **+ New Token**, enter a descriptive name (e.g. `FW-Analyst-Prod`), and click **Generate Token**.
2. Copy the token value — **it is shown only once**.
3. Tokens can be revoked at any time from the same panel.

### Making Requests

```http
POST /external/api/zone/query
Authorization: Bearer 4th_<your-token>
Content-Type: application/json

{"src": "10.1.0.5", "dst": "10.2.0.10", "service": "443"}
```

### Python Example

```python
import requests

resp = requests.post(
    "https://4thealth.yourdomain.com/external/api/zone/query",
    headers={"Authorization": "Bearer 4th_<your-token>"},
    json={"src": "10.1.0.5", "dst": "10.2.0.10", "service": "443"},
    verify=False,
)
data = resp.json()
```

### Executive Summary Endpoint

The **4tExecutive dashboard** polls fleet-wide metrics from the `/external/api/executive/summary` endpoint:

```http
GET /external/api/executive/summary
Authorization: Bearer 4th_<your-token>
```

Response:
```json
{
  "hygiene_score": 87.3,
  "version_compliance_pct": 91.2,
  "pending_config_diff_count": 4,
  "firewall_online_count": 212,
  "firewalls_total": 218,
  "status": "ok",
  "last_updated": "2026-08-24T15:00:00Z",
  "schema_version": 2,
  "change_control": {
    "devices_out_of_sync": 4,
    "admin_changes_24h": 12,
    "admin_changes_by_user": [{"user": "alice", "count": 8}, {"user": "bob", "count": 4}],
    "collected_at": "2026-09-10T01:00:00Z"
  },
  "by_adom": {
    "Corp": {
      "firewalls_total": 42,
      "firewall_online_count": 40,
      "version_compliance_pct": 92.9,
      "pending_config_diff_count": 3,
      "devices_with_failures": 5
    }
  },
  "infra": [
    {
      "role": "fortimanager",
      "label": "FMG-01",
      "hostname": "fmg1.corp.local",
      "cpu": 12.4,
      "mem": 38.1,
      "disk_pct": 41.0,
      "ha_role": "master",
      "status": "green",
      "last_updated": "2026-09-10T00:00:00Z"
    }
  ],
  "lifecycle": {
    "devices_hw_eos": 3,
    "devices_hw_eos_12m": 5,
    "models_unknown": ["FortiGate-Unicorn"],
    "collected_at": "2026-09-10T00:00:00Z"
  },
  "psirt": {
    "open_advisories": 3,
    "devices_critical": 5,
    "devices_high": 2,
    "devices_medium": 0,
    "devices_critical_mitigated": 1.0,
    "kev_exposed_devices": 2,
    "top_advisory": {"advisory_id": "FG-IR-24-001", "cvss": 9.8, "kev": true, "device_count": 5, "devices": [{"device": "FW-Branch-01", "adom": "Corp", "version": "v7.2.4", "workaround_applied": false}]},
    "mean_days_to_remediate_90d": 12.5,
    "collected_at": "2026-09-10T00:00:00Z"
  }
}
```

**Metrics:**
- `hygiene_score` — findings-density across five cheap hygiene checks (unnamed, unlogged, disabled, expired, unhit), expressed as a 0–100 percentage; `null` if no policy packages are found.
- `version_compliance_pct` — percentage of devices matching an admin-configured target version list; `null` if the list is not configured (see below).
- `pending_config_diff_count` — total devices with out-of-sync or modified configuration across all ADOMs.
- `firewall_online_count` / `firewalls_total` — connected vs. total FortiGate device count.
- `status` — one of `pending`, `running`, `ok`, or `error`; lets consumers distinguish "not computed yet" from "real data."
- `last_updated` — ISO 8601 timestamp of whichever sweep (see below) most recently completed.
- `schema_version` — `2` as of this release (bumped from `1`; the bump is purely additive — every v1 key is still present).
- `change_control` — who's changing what, and how much of the fleet has drifted from FortiManager's database:
  - `devices_out_of_sync` — device count whose normalized `conf_status` (from `FMGClient.get_devices_with_sync_status()`, the same call the device sweep already made) is not `"insync"` — covers both `"outofsync"` and an unrecognized status. Freshness: the top-level `device_sweep_collected_at` field, same as the other device-sweep-sourced counts.
  - `admin_changes_24h` — total FortiManager admin audit-log entries in the trailing 24 hours, from a separate hourly sweep (`app/change_control_cache.py`) calling `FMGClient.get_audit_log(hours=24)` once (the audit log is FortiManager-instance-wide, not per-ADOM).
  - `admin_changes_by_user` — the top 5 users by change count in that window, as `[{user, count}]`, ties broken by first-seen order.
  - `collected_at` — ISO 8601 timestamp of the audit-log sweep that produced `admin_changes_24h`/`admin_changes_by_user`. Persisted to `change_control.json` (gitignored) so a restart doesn't blank these two fields until the next hourly sweep completes; a failed sweep (FMG unreachable, endpoint unsupported by the FMG version) leaves the last successful result in place.
  - **`oldest_pending_change_days` is intentionally not included.** FortiManager's `dvmdb` device object (as read by `get_devices_with_sync_status()`) carries no confirmed per-device modification timestamp in this codebase's vendored API knowledge — no such field is read anywhere else in the app, and no FMG API reference is vendored here to confirm one exists. The key is omitted entirely rather than reporting a fabricated or always-null value; add it once a real FMG instance confirms which field (if any) carries it, following the same "not confirmed against real hardware" caveat already documented for the FortiAnalyzer/FortiAuthenticator SNMP OIDs in CLAUDE.md.
- `lifecycle` — hardware end-of-support (EOS) exposure, computed inside the device sweep from the platform strings `app/pending_status_cache.py` already caches (no extra FMG call) matched against a static table in `app/model_eos.py` (mirrors `app/version_eol.py`'s FortiOS software-EOL table, but keyed by hardware platform string with an actual EOS date rather than a fixed version set):
  - `devices_hw_eos` — device count whose hardware platform has already reached end-of-support.
  - `devices_hw_eos_12m` — device count whose hardware platform reaches (or already has reached) end-of-support within the next 12 months; a superset of `devices_hw_eos`.
  - `models_unknown` — distinct platform strings with no entry in `app/model_eos.py`'s table, so a hardware family this table hasn't been updated for is visible rather than silently treated as "not EOS". `is_hw_eos()`/`hw_eos_within()` both return `None` (never `False`) for an unrecognized model.
  - `collected_at` — same timestamp as `device_sweep_collected_at` (same sweep, same source data).
  - **Device configuration backup age (`device_backup`) is not implemented.** The FMG revision-history endpoint this would need could not be confirmed against the lab FortiManager or any vendored API knowledge in this repo — see `docs/superpowers/specs/2026-09-10-device-backup-age-spike.md` for the investigation and recommended next step.
- `by_adom` — the same five fleet-wide device-sweep metrics (`firewalls_total`, `firewall_online_count`, `version_compliance_pct`, `pending_config_diff_count`, `devices_with_failures`), broken out per ADOM. Computed inside the same device sweep that produces the fleet-wide numbers (the sweep already loops per-ADOM), so this costs no extra FMG calls beyond what the fleet-wide sweep already makes. `forti*` system ADOMs are excluded, same as every other ADOM-returning endpoint in this repo. `pending_config_diff_count` is `null` for an ADOM whenever `pending_status_cache` isn't ready yet, matching the fleet-wide field's own honesty rule. `devices_with_failures` is the one field the device sweep genuinely cannot compute itself (it needs live CIS check results, not a device list) — it's filled in from `app/device_review_rollup.py`'s `get_latest_by_adom()`, i.e. whichever ADOM a *scheduled Device Review job* most recently covered; an ADOM with no such run yet (or ever) gets `null`, never a fabricated `0`.
- `infra` — management-plane health for FortiManager, FortiAnalyzer, and FortiAuthenticator `infra_targets.json` entries, as `[{role, label, hostname, cpu, mem, disk_pct, ha_role, status, last_updated}]`. `cpu`/`mem`/`status`(green/amber/red when a reading exists)/`last_updated` come straight from `app/infra_health_cache.py`'s existing SNMPv3 poll cache (no new SNMP traffic). `hostname`/`ha_role`/`disk_pct` come from a lightweight `FMGClient.get_system_status()` call per target, made once per device-sweep cycle (`app/infra_health_cache.py::fetch_meta()`) — not cached separately, since the sweep's own 15-minute-default cadence is already an appropriate refresh rate for fields that change this slowly. **Never includes the target's `host` (an IP) or its `token`** — only `label` (from `infra_targets.json`) and the device-reported `hostname`. `status` is `"gray"` when the target is unreachable by both SNMP and the FMG API, `"green"` when the API is reachable but no SNMP reading is available, and green/amber/red from the SNMP reading otherwise.
- `psirt` — fleet-wide PSIRT exposure, sourced from `psirt.db` (see [PSIRT Advisory Assessment](#psirt-advisory-assessment) above) rather than a live sweep:
  - `open_advisories` — count of saved advisories not yet closed.
  - `devices_critical` / `devices_high` / `devices_medium` — device count affected by open advisories in that priority band (from the advisory's own computed priority, not CVSS alone). A device counts here regardless of whether a workaround is already applied — this field is never silently reduced for mitigation.
  - `devices_critical_mitigated` — of the critical-band devices above, those with a confirmed workaround in place, counted **at half weight** (e.g. 2 mitigated devices → `1.0`). Reported as its own field specifically so it is never used to silently shrink `devices_critical`.
  - `kev_exposed_devices` — distinct devices affected by any open advisory listed in the CISA KEV catalog.
  - `top_advisory` — the single highest-priority open advisory (ties broken by CVSS, then device count); `null` if there are no open advisories.
  - `mean_days_to_remediate_90d` — mean days between an advisory being first saved and being closed, over advisories closed in the trailing 90 days; `null` if none were closed in that window.
  - `collected_at` — ISO 8601 timestamp of when this rollup was computed (computed on read, not cached).

**Two independent background sweeps, on different cadences:** `hygiene_score` is expensive to compute — it downloads every policy in every package in every ADOM — so it refreshes on its own, much slower schedule (`EXEC_SUMMARY_HYGIENE_REFRESH_MINUTES`, default 60 minutes) than the other four metrics (`EXEC_SUMMARY_REFRESH_MINUTES`, default 15 minutes), which only need one lightweight device-list call per ADOM. Each sweep only updates its own fields; the other sweep's most recent values are always preserved in between. In large environments (hundreds of FortiGates), raise `EXEC_SUMMARY_HYGIENE_REFRESH_MINUTES` further to reduce load on FortiManager.

**Configuring Version Compliance:** In **Admin → External API**, add a comma-separated list of compliant firmware versions (e.g., `v7.4.1, v7.4.2`) to **Executive Summary — compliant firmware version(s)**. Devices matching any version in that list count as compliant. Leave empty to report `version_compliance_pct: null` (better than a fabricated number with no target configured).

**Note:** `last_backup_status` reports the status (`"ok"` or the raw scheduler status string) of the most recently completed *scheduled backup run* — this app's own application-config backup (`app/backup_scheduler.py`), not firewall device configs. `null` if no scheduled backup has ever completed. Device configuration backup age is tracked separately as `device_backup` (see above); the two are not the same thing and neither should be read as the other.

### Drill-down details lists

Five rollup objects in the executive summary payload carry an optional per-item breakdown list, capped and ordered most-severe-or-most-relevant-first, for a per-device drill-down view. See [api-reference.md](api-reference.md#drill-down-details-lists) for the cap/order summary table.

**`device_review.details`** — per-device failing-check breakdown, from `app/device_review_rollup.py::build_details()`. Excludes devices that errored during review or that passed every check. Capped at 50, sorted by `worst_severity` (critical → high → medium → low), then by number of failed checks (descending), then by device name (ascending):
```json
{
  "device": "FW-Branch-12",
  "adom": "Corp",
  "failed_checks": ["unnamed_policies", "unlogged_policies"],
  "worst_severity": "high"
}
```

**`rule_hygiene.details`** — per-package finding breakdown, from `app/hygiene_rollup.py::build_details()`. Excludes packages with no findings. Capped at 50, sorted by number of findings (descending), then adom (ascending), then package name (ascending):
```json
{
  "package": "Corp-Edge",
  "adom": "Corp",
  "findings": [{"policy_id": 14, "check": "unnamed_policies", "severity": "low"}]
}
```

**`version_breakdown.eol_devices`** — every device running an end-of-life FortiOS version, from `app/routes/external_api_routes.py::_version_breakdown()`. Capped at 50, sorted oldest firmware first (unparseable versions sort last, since "unknown" isn't the same as "oldest"), then by device name:
```json
{
  "device": "FW-Branch-03",
  "adom": "Corp",
  "version": "v6.4.8"
}
```

**`silent_devices`** — devices FortiManager reports as not connected (`conn_status != 1`); new in this release. `devices_silent` is the total count, `details` a capped, sorted subset:
```json
{
  "devices_silent": 3,
  "details": [
    {"devid": "FGT60F1234567890", "devname": "FW-Branch-07", "last_log_at": null}
  ],
  "collected_at": "2026-09-10T00:00:00Z"
}
```
Capped at 50; entries are sorted internally by adom then device name, but `adom` itself is **not** included in each `details` entry (`devid`, `devname`, `last_log_at` only). `last_log_at` is always `null` in this release — this is a FortiManager connectivity proxy, not a FortiAnalyzer log-freshness check, and this codebase does not currently query the latter. See `docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md` for the investigation and why the field is reserved but unfilled rather than removed.

**`psirt.top_advisory.devices`** — per-device breakdown for the single highest-priority open advisory, from `app/psirt_store.py::_top_advisory_devices()`. Capped at 50, sorted unmitigated (`workaround_applied: false`) first, then adom, then device name:
```json
{
  "top_advisory": {
    "advisory_id": "FG-IR-24-001",
    "cvss": 9.8,
    "kev": true,
    "device_count": 5,
    "devices": [
      {"device": "FW-Branch-01", "adom": "Corp", "version": "v7.2.4", "workaround_applied": false}
    ]
  }
}
```
**Note:** `top_advisory.devices` changed from an int device count to this list. The old count is preserved as `top_advisory.device_count`, unchanged.

### Runtime Files

| File | Purpose |
|---|---|
| `app_settings.json` | Stores `external_api_enabled`, `executive_compliant_versions`, and `ai_assist_enabled` (created automatically) |
| `api_tokens.json` | Stores SHA-256 token hashes (created automatically) |
| `psirt.db` | SQLite — saved PSIRT advisories and assessment history (created automatically) |
| `change_control.json` | Latest admin audit-log rollup (`admin_changes_24h`, `admin_changes_by_user`) — created automatically |

---

## Application Logging

The **Admin → Application Logs** tab shows the in-memory log buffer in real time.

| Level | When used |
|---|---|
| `ERROR` | Unhandled exceptions, authentication failures |
| `WARN` | Failed login attempts, unexpected API responses |
| `INFO` | Login/logout events, group changes *(default)* |
| `DEBUG` | Admin page access, API round-trips |
| `TRACE` | Detailed per-request data for deep troubleshooting |

- The buffer holds up to **2,000 entries** and is reset on process restart.
- Use the level and component filters to narrow results.
- The **Set** button changes the capture level at runtime — no restart required.

---

## Admin

*(admin only)* Sub-tabs: Groups & Permissions, Map Region Colors, External API, AI Assist, Scheduled, Backup, Zone Policy, Application Logs.

Above the sub-tab bar, three **host resource graphs** (CPU/Memory/Disk) show the resource usage of the host running the app, with a range selector (1h/4h/12h/1d/7d/14d), sampled every 60 seconds.

### AI Assist Toggle

A single `ai_assist_enabled` flag gates every AI feature in the app — Rule Validation's AI Assist, Audit Review's AI Summary/AI Explain/PSIRT extraction, Config-Delta's AI Summary, and the Admin AI Trend Summary below. Toggle it in **Admin → AI Assist**, which also shows an AI usage/cost chart (calls, tokens, estimated cost) sourced from every LLM call the app has made.

### AI Trend Summary

*Admin-gated (`ai_assist_enabled`).* A **Generate AI Trend Summary** button above the host resource graphs computes 7-day trend statistics deterministically (percent change, slope per day, a days-to-threshold projection) for CPU/Memory/Disk, then has the LLM phrase a short readable summary of what needs attention — the LLM only explains numbers already computed, it never detects a trend itself.

---

## Extending the Application

Adding a new page follows this five-step pattern:

1. **API data** — add a route to `app/routes/api_routes.py` (or a new blueprint).
2. **Page route** — add a route decorated with `@tab_required("my_tab_key")`.
3. **Template** — add `app/templates/<page>.html` extending `base.html`.
4. **JavaScript** — add `app/static/js/<page>.js`; reference it in the template's `{% block scripts %}`.
5. **Tab registry** — call `registry.register("my_tab_key", "Display Name", "blueprint.view")` in the route module.

The new tab key appears automatically in the Admin group-editor checklist. No build tools or transpilers — the entire front end is plain HTML, CSS, and JavaScript.
