# 4tlog: `/external/api/log-usage` Endpoint — Design (handoff spec)

Date: 2026-09-23
Status: Approved for planning
**Repo this is implemented in: `~/code/github/web/4tlog` — NOT 4thealth-plus.**
This document is a handoff spec, written from the 4thealth-plus repo for
context continuity. It is not implemented as part of the companion document
[2026-09-23-log-hygiene-rule-review-design.md](2026-09-23-log-hygiene-rule-review-design.md)'s
session — run this spec through 4tlog's own planning/implementation cycle
in that repo.

## Problem

4thealth-plus's new Log-Based Rule Review feature needs to know, for one
FortiManager policy rule (`policyid`) installed on a known set of
FortiGate devices, which source IPs, destination IPs, and destination ports
actually appeared in that rule's traffic over the last N days. 4tlog already
owns the FortiAnalyzer connection (`app/faz_client.py`) and the exact
log-search plumbing this needs (`search_logs()`,
`log_search_filters.py::parse_ip_entries`/`parse_port_entries`). No FAZ
connectivity code should be duplicated into 4thealth-plus.

## Scope

- One new route: `POST /external/api/log-usage`, added to
  `app/routes/external_api_routes.py` (or a new sibling module if that file
  is judged too large — see that file's current size before deciding).
- Bearer-token authenticated, same gate as `executive/summary`
  (`app.api_tokens.validate_token`, `app.app_settings.get_setting("external_api_enabled")`).
- Returns only aggregated distinct values (`srcips`, `dstips`, `dstports`) —
  never raw log rows — to 4thealth-plus.
- Read-only: this endpoint only searches existing FAZ logs. It changes
  nothing in FortiAnalyzer or any managed device.

## Out of scope

- Any new UI in 4tlog.
- Any change to the existing internal `/api/log-search` route.
- Caching of results (each call runs a live FAZ search, same as internal
  Log Search today — no new background sweep).

## Request / response contract

`POST /external/api/log-usage`

```json
{
  "adom": "Enterprise Services",
  "devices": ["FW-DC-01", "FW-DC-02"],
  "policyid": 123,
  "days": 30
}
```

Validation:
- `adom`: required, non-empty string.
- `devices`: required, non-empty list of strings (FortiGate hostnames as
  FMG/4thealth-plus knows them — these are *not* FAZ device serials).
- `policyid`: required, positive integer.
- `days`: required, integer 1–60 inclusive; reject (`400`) outside that
  range rather than silently clamping — clamping is 4thealth-plus's job on
  its own inputs, this endpoint should be strict about its contract.

**Target resolution:** match `adom` case-insensitively against each
`faz_targets.json` entry's `"adom"` field. Zero matches → `404`
(`{"error": "No FortiAnalyzer target configured for ADOM '<adom>'"}`).
Multiple matches → query all matched targets and merge results (a
multi-FAZ ADOM split is a valid, if unusual, deployment).

**Device resolution:** for each matched target, call the existing
`FAZClient.get_devices()` to get `{devid, name, platform}` and match
requested `devices` entries by `name` (case-insensitive). Devices not found
on any matched target go into `devices_not_found` — non-fatal.

**Log search:** for each resolved `devid`, build a filter expression
`policyid==<policyid>` (extend `FAZClient.build_filter_expression` or
compose the raw filter string directly — `policyid` needs no IP/port
parsing, unlike the existing `srcip`/`dstip`/`dstport` clause builders) and
call `search_logs(logtype="traffic", device=devid, filter_expression=...,
start_time=..., end_time=..., limit=Config.LOG_SEARCH_MAX_RESULTS, ...)`
with a time range computed as `now - days` to `now` in the target's local
time (`local_time_range()` already exists for this). Run once per resolved
device (FAZ's `device` param in `search_logs` takes one device — confirm
whether a multi-device search is possible via a device list per the existing
code's `[{"devid": device}]` shape; if the API does support multiple devids
in one call, prefer that over N sequential calls per device to reduce FAZ
load and endpoint latency).

**Aggregation:** across all rows from all queried devices, collect the
distinct values of the `srcip`, `dstip`, and `dstport` log fields (field
names should be confirmed against a real FAZ traffic log response — verify
these are the actual field keys, not assumed, the same way `get_devices()`'s
docstring notes its own field-name confirmations against real hardware).
`log_count` is the total row count actually returned (post-cap).
`truncated` is `true` if any per-device search hit `limit` exactly (an
indicator, not a guarantee, that more distinct values exist beyond the cap
— note this caveat in the response so 4thealth-plus can surface it).

**Response:**
```json
{
  "policyid": 123,
  "days": 30,
  "time_range": {"start": "2026-08-24T00:00:00", "end": "2026-09-23T00:00:00"},
  "srcips": ["10.1.1.5", "10.1.1.6"],
  "dstips": ["10.2.2.10"],
  "dstports": [443, 8443],
  "log_count": 15234,
  "truncated": false,
  "devices_queried": ["FW-DC-01"],
  "devices_not_found": ["FW-DC-02"]
}
```

Zero matching devices across all targets is **not** a `404` — it means
"we know the ADOM, but named devices weren't found there," which is
`200` with `devices_queried: []`, `devices_not_found: [...]`, and empty
observed-value arrays. Zero log rows for devices that *were* found is also
`200` with empty arrays — a valid "no traffic" result.

## Error handling

| Failure | Status | Notes |
|---|---|---|
| `external_api_enabled` is false | `503` | Same as `executive/summary` |
| Missing/invalid bearer token | `401` | Same as `executive/summary` |
| Missing/invalid request fields | `400` | Names the offending field |
| No FAZ target for `adom` | `404` | |
| FAZ search error (`FAZError`) on a given device | Non-fatal per-device — collect into a `device_errors: {devname: message}` field in the response rather than failing the whole request, so one bad device doesn't block results from the others |
| All devices error out | `502` with the first/representative error message |

## Testing

- Route tests for the auth/feature-gate matrix (disabled, no token, bad
  token, valid token) — reuse whatever pattern `executive_summary()`'s
  existing tests use, if any exist; add them if not.
- Unit tests for ADOM→target matching (single match, multi-match, no
  match) and device-name→devid resolution (found, not found, mixed),
  mocking `FAZClient`.
- Unit tests for response aggregation (dedup, `truncated` detection,
  `log_count`) using a fixture set of mock log rows.
- Confirm field names (`srcip`/`dstip`/`dstport` vs. e.g. `srcport`
  confusion) against a real FAZ instance or existing test fixtures before
  marking this endpoint production-ready — the existing `search_logs()`
  docstrings note several FAZ behaviors that only became clear once
  confirmed against live hardware; treat this endpoint's field-name
  assumptions the same way until verified.

## Dependency for the 4thealth-plus side

Once this endpoint is live, 4thealth-plus's Admin → Log Hygiene panel
needs: this 4tlog instance's base URL, and a bearer token created via
4tlog's existing `manage_api_tokens.py` (or its Admin → External API token
UI, if 4tlog has one — confirm) with `external_api_enabled` turned on in
4tlog's own Admin settings.
