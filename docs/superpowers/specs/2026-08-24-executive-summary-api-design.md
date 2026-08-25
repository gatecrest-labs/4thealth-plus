# Executive Summary API — Design

## Context

`4tExecutive` (a separate repo, `~/code/github/web/4tExecutive`) is a small
dashboard app that polls named "sources" on a schedule and caches whatever
they return in a local SQLite snapshot table. It already has a `4thealth`
source type wired up end-to-end on its side:

- `app/sources.py` stores `{id, system, base_url, token, poll_interval_minutes}`
  per source and builds `Authorization: Bearer <token>` headers.
- `app/collector.py` polls `GET {base_url}/external/api/executive/summary`
  on each source's interval and caches the raw JSON response.
- `app/widgets.py` defines a `4thealth.*` widget catalog that reads specific
  fields out of that cached JSON: `hygiene_score`, `version_compliance_pct`,
  `pending_config_diff_count`, `last_backup_status`, `firewall_online_count`.

4thealth-plus has no such endpoint today. This design adds it, reusing the
external-API scaffolding (`app/api_tokens.py`, `app/routes/external_api_routes.py`,
`external_api_enabled` feature gate) that already backs the zone-policy
endpoints used by FW-Analyst — the executive summary endpoint is a second
consumer of that same bearer-token auth layer, not a new auth mechanism.

None of the five metrics 4tExecutive expects currently exist as fleet-wide,
cheaply-readable values in 4thealth-plus:

- **hygiene_score** — Rule Hygiene only runs on demand, per ADOM + per policy
  package, via a live FortiManager call from the request handler
  (`hygiene_routes.py`). No aggregate score, no persistence.
- **version_compliance_pct** — `versions_cache.py` caches each device's raw
  version string (scheduled, all ADOMs, 30 min), but 4thealth-plus has no
  concept of a "compliant" or "target" version to compare against.
- **pending_config_diff_count** — `pending_status_cache.py` caches
  `conf_status`/`db_status` per device (scheduled, all ADOMs, 30 min), but
  only exposes it per-ADOM (`get_cached_devices(adom)`); nothing sums across
  ADOMs today.
- **last_backup_status** — `backup_scheduler.py` backs up 4thealth-plus's own
  application config (`.env`, `users.json`, etc.), not firewall/device
  configs. There is no firewall-config-backup feature anywhere in this repo.
  Decision: **omit this field from the payload entirely** rather than report
  a number that would mislead an executive about firewall backup posture.
- **firewall_online_count** — `conn_status` is only fetched live, per-ADOM,
  inside the interactive device-list route (`api_routes.py`). No cache
  captures it fleet-wide.

## Decisions

**1. New background job + in-memory store, following the existing
`summary_job.py` / `pending_status_cache.py` pattern — not on-demand
computation in the route handler.**
Every other cheap-to-read aggregate in this codebase (`/api/summary`,
`/api/pending-changes/...`, `/api/hygiene` package lists via `versions_cache`)
is served from a background-refreshed in-memory store, never a live FMG call
inside the request. The new route follows the same convention: instant reads,
no live calls, no risk of a slow executive-dashboard poll cascading into FMG
load. A new module, `app/executive_summary_cache.py`, owns the store and the
scheduler wiring (`init_scheduler(app)`, called once from the app factory
alongside the other `init_scheduler` calls).

**2. One new per-ADOM device sweep computes both `firewall_online_count` and
the raw data for `version_compliance_pct` — not two separate FMG round-trips.**
The job enumerates ADOMs via the existing `adom_cache.get_adom_names()` and,
for each, calls `client.get_devices(adom)` once (same call `summary_job.py`
already makes for `firewalls_total`). From that single response per ADOM it
derives:
- `firewalls_total` / `firewall_online_count`, from each device's
  `conn_status` (same field/semantics as the live `api_routes.py` device-list
  route: `conn_status == 1` → online).
- the version list feeding `version_compliance_pct` (see decision 3) — reusing
  the version string already present on the same device record, rather than
  also polling `versions_cache.py`'s data path separately.

**3. `version_compliance_pct` is defined by a new admin setting,
`executive_compliant_versions: list[str]`.**
Stored via the existing `app_settings.py` key/value store (new default:
`[]`), editable from a small addition to the Admin → External API screen (a
textarea or comma-separated input, following the same admin-settings
PUT pattern already in `admin_routes.py`). Percentage = `count(devices whose
version is in executive_compliant_versions) / firewalls_total`, from the
device sweep in decision 2. If the setting is empty, `version_compliance_pct`
is reported as `null` (no target configured — better than a fabricated
number) rather than silently defaulting to some heuristic like "most common
version."

**4. `pending_config_diff_count` aggregates the existing
`pending_status_cache.py` cache via one new public accessor.**
Add `get_all_cached_devices() -> dict[str, list[dict]]` to
`pending_status_cache.py`, returning a snapshot of every cached ADOM's device
list under its existing lock (mirrors `get_cached_devices(adom)`'s snapshot
pattern, just unfiltered by ADOM). The new job sums, across all cached
ADOMs, devices whose `conf_status` indicates an out-of-sync/pending change —
no new FMG calls, since this cache already refreshes independently every 30
minutes.

**5. `hygiene_score` comes from a periodic sweep using only the cheap
checks, scored as a simple findings-density percentage.**
The job runs `hygiene.run_checks()` across every ADOM/policy package for the
five checks that need no live per-object lookups — `unnamed`, `unlogged`,
`disabled`, `expired`, `unhit` — and explicitly **excludes `shadow`**, which
requires address/service resolvers and would multiply the cost of an
already fleet-wide sweep. Score:

```
hygiene_score = 100 * (1 - total_findings / total_policies)
```

clamped to `[0, 100]`; `null` if `total_policies` is `0` (no packages found).
This is intentionally simple (unweighted finding count, not severity-scored)
— a reasonable fleet-wide signal for an executive dashboard, not a
replacement for the interactive Rule Hygiene tab's detailed findings.

**6. Refresh cadence: new env var `EXEC_SUMMARY_REFRESH_MINUTES`, default 15.**
Matches 4tExecutive's default `poll_interval_minutes` for a `4thealth`
source (see `config/examples/sources.example.json` on that side). Wired
through `init_scheduler(app)` the same way `summary_job.py` does: an
APScheduler interval job plus a one-time fire-on-startup (with the same
retry-after-15s-if-not-ok pattern `summary_job.py` uses, since the first
container boot races FMG availability).

**7. New route: `GET /external/api/executive/summary`.**
Added to the existing `app/routes/external_api_routes.py`, gated by the same
`_gate()` (feature flag + bearer token) as the zone endpoints — no new auth
path. Response shape:

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

`status` mirrors `summary_job.py`'s `pending | running | ok | error` so a
consumer can distinguish "not computed yet" from "computed, this is real
data." `last_backup_status` is not present (decision, see Context). Any
individual metric can independently be `null` per its own decision above
(missing compliant-version config, zero policies, etc.) without failing the
whole response.

**8. Out of scope for this change (4tExecutive repo, not touched here):**
`app/widgets.py` in 4tExecutive still defines a `4thealth.last_backup_status`
widget that will never receive data once this ships, since the field is
omitted. Removing that widget is a follow-up on the 4tExecutive side, tracked
separately — not part of this 4thealth-plus change.

## Testing

- `tests/test_executive_summary_cache.py` — aggregation logic unit tests:
  online-count math, compliance-percentage math (including the empty-setting
  → `null` case), pending-diff summation across multiple cached ADOMs,
  hygiene score math (including the zero-policies → `null` case), and that
  `shadow` findings are never included.
- Route test (in the existing external-API test file or a new
  `test_external_api_executive.py`): 401 with no/bad token, 503 when
  `external_api_enabled` is false, 200 with the expected shape when enabled
  and the cache has data.

## Documentation

- `docs/api-reference.md` — add `GET /external/api/executive/summary` to the
  External API table.
- `docs/features.md` — extend the External API section with the new
  endpoint and the new `executive_compliant_versions` admin setting.
- `CLAUDE.md` — add the new scheduled job to wherever the existing background
  jobs (SNMP poller, summary job, pending-status cache, etc.) are documented.
