# API Reference

All endpoints require an authenticated session (HTTP 401 otherwise).
`*` = admin role required.

## Core / Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/api/infrastructure` | Health data for all devices in `infra_targets.json` |
| GET | `/api/infrastructure/raw` `*` | Raw FortiManager responses — for debugging field names |
| GET | `/api/summary` | Managed network summary (firewall total, rule total) — served from in-memory cache |
| POST | `/api/summary/refresh` `*` | Trigger an immediate background recalculation |
| GET | `/api/adoms` | List all ADOMs visible to the authenticated user |
| GET | `/api/adoms/<adom>/devices` | List all devices in an ADOM |
| GET | `/api/adoms/<adom>/devices/<name>/health` | Full live health for a device |
| GET | `/api/adoms/<adom>/devices/<name>/raw` `*` | Raw proxy payloads per health endpoint |
| GET | `/api/search?q=<query>` | Search all ADOMs by device name or IP |

## Rule Review (Hygiene)

| Method | Path | Description |
|---|---|---|
| GET | `/api/hygiene/adoms/<adom>/packages` | List policy packages in an ADOM |
| POST | `/api/hygiene/policies` | Fetch policy rules for a package |
| POST | `/api/hygiene/run` | Run selected hygiene checks against a package |
| GET | `/api/hygiene/ai-explain-status` | Is AI Explain available (`ai_assist_enabled`)? |
| POST | `/api/hygiene/explain-finding` | Explain one hygiene finding; body is the finding object itself; returns `{narrative, narrative_error}`, never a 500 |

## Device Review

| Method | Path | Description |
|---|---|---|
| GET | `/api/device-review/adoms/<adom>/devices` | List devices in an ADOM for the Device Review tab |
| POST | `/api/device-review/run` | Run selected security checks against chosen devices |
| GET | `/api/device-review/ai-summary-status` | Is AI Summary available (`ai_assist_enabled`)? |
| POST | `/api/device-review/ai-summary` | Summarize an already-computed run; body: `{adom, results, checks}`; returns `{narrative, narrative_error}` |

## Rule Validation

| Method | Path | Description |
|---|---|---|
| GET | `/api/rule-review/adoms` | List ADOMs for the Rule Validation package selector |
| GET | `/api/rule-review/adoms/<adom>/packages` | List policy packages in an ADOM |
| POST | `/api/rule-review/parse-import` | Parse an uploaded CSV or XLSX file into flow rows |
| GET | `/api/rule-review/zone-status` | Check whether the zone policy integration is reachable |
| POST | `/api/rule-review/analyze` | Analyze flows against selected policy packages |
| GET | `/api/rule-review/ai-assist-status` | Is AI Assist available (`ai_assist_enabled`)? |
| POST | `/api/rule-review/ai-assist` | Single-request AI Assist: deterministic plan + AI narrative + peer-review package |

## Zone Policy

| Method | Path | Description |
|---|---|---|
| POST | `/api/zone/query` | Query flows against the zone policy database |
| GET | `/api/zone/zones` | List all zones |
| GET | `/api/zone/policies` | List all segmentation policies |
| GET | `/api/zone/validate` | Validate the zone policy database schema |

## Config-Delta

| Method | Path | Description |
|---|---|---|
| GET | `/api/pending-changes/adoms` | List ADOMs accessible to the current user |
| GET | `/api/pending-changes/adoms/<adom>/devices` | Device list with `conf_status`, `db_status`, and `pkg_status` |
| POST | `/api/pending-changes/adoms/<adom>/device/<device>/preview` | Trigger FortiManager install-preview and return parsed CLI diff |
| GET | `/api/pending-changes/ai-summary-status` | Is AI Summary available (`ai_assist_enabled`)? |
| POST | `/api/pending-changes/adoms/<adom>/device/<device>/ai-summary` | Summarize a parsed diff; body: `{summary, vdoms}`; returns `{narrative, narrative_error}` |

### Admin — SMTP Config

| Method | Path | Description |
|---|---|---|
| GET | `/admin/api/smtp` | Get SMTP configuration (password masked) |
| PUT | `/admin/api/smtp` | Save SMTP configuration |
| POST | `/admin/api/smtp/test` | Send a test email; body: `{"to": "..."}` |

### Admin — Scheduled Config-Diff Jobs

| Method | Path | Description |
|---|---|---|
| GET | `/admin/api/config-diff/jobs` | List all jobs with run history |
| POST | `/admin/api/config-diff/jobs` | Create a job |
| PUT | `/admin/api/config-diff/jobs/<id>` | Update a job |
| DELETE | `/admin/api/config-diff/jobs/<id>` | Delete a job |
| POST | `/admin/api/config-diff/jobs/<id>/run` | Trigger immediate run (returns 202) |
| GET | `/admin/api/config-diff/jobs/<id>/status` | Poll run status: `{"running": bool, "last_run": {...}}` |

## Map

| Method | Path | Description |
|---|---|---|
| GET | `/api/map/devices` | Cached device list with lat/lon (filtered to user's allowed ADOMs) |
| GET | `/api/map/regions` | Region definitions (name, states, colour) used by the map |
| GET | `/api/map/status` | Lightweight cache status poll |
| POST | `/api/map/refresh` `*` | Trigger an immediate background map cache refresh |

## Admin `*`

| Method | Path | Description |
|---|---|---|
| GET | `/admin/api/groups` | List all groups |
| POST | `/admin/api/groups` | Create a group |
| PUT | `/admin/api/groups/<name>` | Update a group's members, tabs, and ADOM access |
| DELETE | `/admin/api/groups/<name>` | Delete a group |
| GET | `/admin/api/users` | List local users (for group member picker) |
| GET | `/admin/api/tabs` | List registered tab keys and display names |
| GET | `/admin/api/adoms` | List known ADOMs from the background cache |
| GET | `/admin/api/map-regions` | Get current map region configuration |
| PUT | `/admin/api/map-regions` | Update map region names, state assignments, and colours |
| GET | `/admin/api/logs` | Fetch log entries (filter by level and component) |
| POST | `/admin/api/logs/level` | Change the active log capture level at runtime |
| DELETE | `/admin/api/logs` | Clear the in-memory log buffer |
| GET | `/admin/api/settings` | Get app feature flags (e.g. `external_api_enabled`, `ai_assist_enabled`) |
| PUT | `/admin/api/settings` | Update app feature flags |
| GET | `/admin/api/host-metrics?range=` | Bucketed host CPU/mem/disk history (`1h\|4h\|12h\|1d\|7d\|14d`) |
| GET | `/admin/api/host-metrics/ai-summary` | Deterministic 7-day trend stats plus AI narrative; returns `{trends, narrative, narrative_error}` |
| GET | `/admin/api/ai-usage` | Bucketed AI Assist call/cost history (`?range=` or `?start=&end=`) |
| GET | `/admin/api/tokens` | List external API bearer tokens |
| POST | `/admin/api/tokens` | Create a new bearer token (plaintext returned once) |
| DELETE | `/admin/api/tokens/<id>` | Revoke a bearer token |

## External API (bearer-token, no session required)

All external API endpoints require `Authorization: Bearer <token>` and return `503` when the feature is disabled.

| Method | Path | Description |
|---|---|---|
| POST | `/external/api/zone/query` | Query src→dst flows against the zone policy DB |
| GET | `/external/api/zone/zones` | List all zones and subnets |
| GET | `/external/api/zone/policies` | List all segmentation policies |
| GET | `/external/api/executive/summary` | Fleet-wide metrics for the 4tExecutive dashboard (hygiene score, version compliance, pending config diffs, firewall online count) |

See [features.md](features.md#external-api) for setup and usage details.
