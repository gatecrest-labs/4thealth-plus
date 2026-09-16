# License Status in the Executive Summary — Design

## Context

PR #80 (`feature/firewall-license-status`, ported from `web/4thealth`
commit `785a1bf`) added a license status badge to the firewall detail
panel: `app/fmg_client.py`'s `PROXY_ENDPOINTS` gained a `license_status`
entry (`/api/v2/monitor/license/status`), and `_assemble_health()` in
`app/routes/api_routes.py` parses `forticare.support.enhanced` out of the
FortiOS response into `{"status": "licensed"|"expired"|"unknown",
"expires": "YYYY-MM-DD"|None}` for one device at a time, on-demand, when
an operator opens that device's detail panel.

`~/code/github/web/4texecutive` (a separate repo) is a read-only
executive dashboard that polls `GET /external/api/executive/summary` on
each configured 4thealth-plus source and caches the response verbatim.
It already has an established pattern for fleet-wide device rollups —
`device_backup` (daily sweep, `app/device_backup_cache.py`) and
`lifecycle` (hardware EOS, computed inline during the 15-min device
sweep) are the two closest analogs. This design adds a third: fleet-wide
license status, exposed as a new `license_status` field group in the
executive summary payload, surfaced in 4tExecutive as a Board widget, a
Lifecycle & Support domain row, and fleet-devices drilldown rows — see
decisions below for exactly what it does and does not touch.

**Explicitly out of scope (per discussion):** feeding this into any
domain's *score* formula. This ships as an informational field group
only, the same tier as `infra` and `by_adom` — Lifecycle & Support's
score keeps its existing three inputs (version compliance, EOL version
share, hardware EOS share) unchanged.

## Decisions

**1. One new proxy call per device, so it needs its own sweep —
it cannot ride the existing 15-min device sweep.**
Unlike `firewall_online_count`/`version_compliance_pct` (both read off
the bulk `get_devices_with_sync_status()` dvmdb response, one call per
ADOM) and unlike `lifecycle`'s hardware-EOS counts (derived from
`platform_str`, already present on that same bulk record — no extra
call), license status only exists behind FortiOS's own monitor API,
fetched through FMG's per-device proxy (`FMGClient._proxy()`, `target:
["adom/<adom>/device/<name>"]`). There is no bulk/fleet-wide FMG
endpoint for it. This is the same cost profile as `device_backup`'s
sweep (one extra round-trip class per device/ADOM), not the cheap
dvmdb-only device sweep — hence its own daily cadence, matching
`device_backup_cache.py`'s existing precedent rather than the tighter
15-minute interval.

**2. New module `app/license_status_cache.py`, structurally identical to
`app/device_backup_cache.py`.**
Daily sweep (`DEVICE_LICENSE_REFRESH_HOUR`/`_MINUTE` env vars, default
`03:00` — staggered from `device_backup`'s `02:00` and `summary_job`'s
`01:00`), enumerating non-`forti*` ADOMs via `client.get_adoms()`, then
`client.get_devices(adom)` for the roster per ADOM. For each device, a
`ThreadPoolExecutor(max_workers=4)` (same concurrency as
`bulk_device_review_adom()`) calls a new `FMGClient.get_device_license_status(adom,
device)` method (one `_proxy()` call to `/api/v2/monitor/license/status`).
Persisted to `license_status.json` (gitignored, project root) via
`atomic_write_json` — same single-latest-record, "a failed sweep leaves
the prior result in place" convention as `device_backup.json`. Because
this is a plain JSON file on shared disk (not an in-memory store), it
needs no SQLite collector/web split treatment — same reasoning that
already applies to `device_backup_cache.py` today.

**3. Shared parsing logic — one function, two callers.**
The `_parse_license()` closure added inline to `_assemble_health()` in
PR #80 is extracted verbatim into a new small module,
`app/license_status.py::parse_license_payload(raw_payload) -> dict`.
`_assemble_health()` (live, single-device) and
`license_status_cache._run_sweep()` (fleet-wide sweep) both import and
call it, so the "licensed / expired / unknown" classification logic
never has two independent implementations to drift out of sync.

**4. Aggregation and `details` shape — surfaces problems, not clean
state.**
Sweep output:
```json
{
  "devices_licensed": 41,
  "devices_expired": 2,
  "devices_unknown": 1,
  "details": [
    {"device": "FW-Branch12", "adom": "Corp", "status": "expired", "expires": "2026-08-01"},
    {"device": "FW-Branch7", "adom": "Corp", "status": "unknown", "expires": null}
  ],
  "collected_at": "2026-09-16T03:00:00Z"
}
```
`details` lists only non-`"licensed"` devices — same convention as
`models_unknown`/`silent_devices_details` (a clean fleet produces an
empty list, not 43 redundant "licensed" rows). `devices_unknown` counts
devices where the proxy call failed or the response didn't parse as a
recognizable license status (FMG unreachable for that device, license
API not supported on that FortiOS build, etc.) — same "unknown never
renders as a false negative" posture as `app.model_eos`.

**5. Executive-summary payload — new top-level `license_status` key,
alongside `device_backup`.**
`app/routes/external_api_routes.py` gains `_license_status()` (identical
shape to `_device_backup()`): reads `app.license_status_cache.get_latest()`,
returns the counts + `details` + `collected_at`, or all-`None`/`[]` if no
sweep has completed yet. Added to the `/executive/summary` response dict
and to `_freshness()` (key: `"license_status"`, value:
`license_status.get("collected_at")`).

**6. 4tExecutive: new field group, informational tier, on the Lifecycle &
Support domain page.**
- `docs/integrations.md` — new `license_status` section, modeled on the
  existing `lifecycle` section: field meanings, the `details` list shape
  (added to the existing "Optional `details` lists" table:
  `license_status` → `details` → `{device, adom, status, expires}`),
  and an explicit note that this field group does **not** feed any
  domain score.
- `app/widgets.py` — `WIDGET_CATALOG` gains a "License Status" widget
  (source_system `4thealth`). RAG: green when `devices_expired == 0`,
  red otherwise; `devices_unknown` is shown but not scored red/green on
  its own (informational, same treatment `models_unknown` gets).
  `_FIELD_GROUP_FRESHNESS["license_status"]` set to a ~2-day staleness
  threshold (daily sweep + daily poll headroom, same reasoning as
  `device_backup`'s threshold).
- `app/domains.py` — one new informational row on the **Lifecycle &
  Support** domain detail page (`devices_expired`, `devices_unknown`),
  explicitly not part of `compute_domain()`'s score formula for that
  domain.
- `app/devices.py` — `license_status.details` merged into the fleet
  devices drilldown (`/devices` and the Lifecycle & Support domain's
  "Devices" section), same merge pattern as `device_review.details`.
- `app/metric_extract.py` — `extract_all()` gains
  `license_status.devices_licensed`, `license_status.devices_expired`,
  `license_status.devices_unknown` metric_points (for Board sparklines/
  history); `license_status` and `license_status.details` themselves
  are composite and always extract to nothing, same as `psirt`/
  `psirt.top_advisory`.

**7. Schema version — additive, no bump required.**
4thealth-plus is already on `schema_version: 2`. `license_status` is a
new optional top-level key, exactly like `change_control`/`lifecycle`/
`by_adom`/`infra` were when they were added — 4tExecutive already
treats an absent field group as "no data yet," so no version bump and
no 4tExecutive-side branching on schema version is needed.

## Testing

- `tests/test_license_status_cache.py` (4thealth-plus) — unit tests for
  the pure aggregation function (mirrors `test_device_backup_cache.py`):
  licensed/expired/unknown counting, `details` list content and
  ordering, empty-fleet edge case.
- `tests/test_license_status.py` (4thealth-plus) — unit tests for the
  extracted `parse_license_payload()` against representative FortiOS
  response shapes (licensed-with-expiry, expired, missing/malformed
  `forticare` block).
- 4tExecutive: a widget/freshness test asserting the new field group
  renders "no data yet" when absent and the correct RAG color when
  present, plus a `metric_extract` test for the three new metric_points.
- Manual end-to-end check once both sides are deployed: trigger a sweep
  (`refresh_now()`), confirm `/external/api/executive/summary` includes
  `license_status`, register/refresh the source in 4tExecutive, confirm
  the Board row and Lifecycle & Support drilldown render.

## Non-goals

- No domain score changes (per explicit decision above).
- No change to the live, single-device path added in PR #80
  (`_assemble_health()`/`renderHealthModal()`) beyond extracting the
  shared parser — the detail-panel badge keeps working exactly as
  shipped.
- No bulk/batched FMG proxy call — out of scope unless a future FMG
  version is confirmed to support multi-target `/sys/proxy/json`
  requests (not confirmed against the lab FMG as of this writing).
