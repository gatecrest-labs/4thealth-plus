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

Two sections on a single page: a full **Policy Rules** viewer and a **Hygiene Analysis** panel. All analysis is read-only.

### Policy Rules

1. Select an **ADOM** and **Policy Package** — the full rule table loads automatically.
2. Search using the full-text search box (supports regex). Optionally scope the search to a single field.
3. Click any address group or service group triangle to expand its members inline.
4. Page through rules using 10 / 25 / 50 / 100 per-page pagination.
5. Export as **CSV**, **JSON**, or **PDF** — each export includes a filter context header.

### Hygiene Analysis

1. Select an **ADOM** and **Policy Package** (independent from the viewer selectors above).
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

### AI Explain

*Admin-gated (`ai_assist_enabled` in Admin → AI Assist).* Each finding row can be expanded to reveal an **Explain** button. One click sends that single finding (never the whole result set) to the configured LLM, which returns a plain-English explanation of why it matters plus a suggested FortiOS CLI remediation snippet — the LLM never runs or overrides a check, and the snippet is a suggestion for a human reviewer, not something the app applies automatically.

---

## Device Review

Runs configurable security checks against the management-plane interfaces of every device in a selected ADOM.

### Workflow

1. Select an ADOM — the device grid loads with all devices selected by default.
2. Filter or deselect devices using the searchable grid.
3. Choose which checks to run (all enabled by default).
4. Click **Run Analysis** — findings appear in a filterable, paginated table.
5. Export results as **CSV**, **JSON**, or **PDF** (PDF includes ADOM, timestamp, and device count — suitable as compliance evidence).

### Result Values

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

### AI Summary

*Admin-gated (`ai_assist_enabled` in Admin → AI Assist).* After running an analysis, a **Summarize with AI** button generates a short plain-English summary of the results — overall posture and which devices/checks need attention first — from the aggregated check counts plus the FAIL/INSECURE findings (capped, never the full per-interface result set). The same summary is generated automatically (best-effort) for scheduled Device Review email/PDF reports when the flag is enabled.

### Adding a New Check

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

Device Review scheduled reports include a **Host Summary** table at the top of both the email body and the attached file, showing per-device counts for each result type (PASS, FAIL, INSECURE, WARN, CONFIG_MISSING, INFO, Total). The existing per-check aggregate summary remains in the email body below the host summary.

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

*Admin-gated (`ai_assist_enabled` in Admin → AI Assist).* Alongside the bulk CSV/XLSX table workflow above, **AI Assist** is a single-request mode: describe one change (source/destination/service/target firewalls, plus an optional ticket ID and justification) and get back a deterministic verdict — computed by the same ported, tested change-planning engine (`app/planner/`), never by the LLM — an AI-written narrative report, and a peer-review package. Multi-provider: Claude (default), Codex, or Ollama, selected server-wide via `AI_PROVIDER` in `.env`. If narration fails, the deterministic plan is still returned with a `narrative_error` note rather than a lost result.

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
  "last_updated": "2026-08-24T15:00:00Z"
}
```

**Metrics:**
- `hygiene_score` — findings-density across five cheap hygiene checks (unnamed, unlogged, disabled, expired, unhit), expressed as a 0–100 percentage; `null` if no policy packages are found.
- `version_compliance_pct` — percentage of devices matching an admin-configured target version list; `null` if the list is not configured (see below).
- `pending_config_diff_count` — total devices with out-of-sync or modified configuration across all ADOMs.
- `firewall_online_count` / `firewalls_total` — connected vs. total FortiGate device count.
- `status` — one of `pending`, `running`, `ok`, or `error`; lets consumers distinguish "not computed yet" from "real data."
- `last_updated` — ISO 8601 timestamp of the last successful refresh.

**Configuring Version Compliance:** In **Admin → External API**, add a comma-separated list of compliant firmware versions (e.g., `v7.4.1, v7.4.2`) to **Executive Compliant Versions**. Devices matching any version in that list count as compliant. Leave empty to report `version_compliance_pct: null` (better than a fabricated number with no target configured).

**Note:** `last_backup_status` is intentionally omitted — this app backs up its own application config, not firewall device configs, so including it would mislead an executive about the firewall backup posture.

### Runtime Files

| File | Purpose |
|---|---|
| `app_settings.json` | Stores `external_api_enabled` flag (created automatically) |
| `api_tokens.json` | Stores SHA-256 token hashes (created automatically) |

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

A single `ai_assist_enabled` flag gates every AI feature in the app — Rule Validation's AI Assist, Device Review's AI Summary, Config-Delta's AI Summary, Rule Hygiene's AI Explain, and the Admin AI Trend Summary below. Toggle it in **Admin → AI Assist**, which also shows an AI usage/cost chart (calls, tokens, estimated cost) sourced from every LLM call the app has made.

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
