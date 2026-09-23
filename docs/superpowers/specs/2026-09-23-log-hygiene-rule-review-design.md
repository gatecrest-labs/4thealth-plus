# Log-Based Rule Log Hygiene Review — Design

Date: 2026-09-23
Status: Approved for planning

## Problem

Business review of firewall rules needs to know, for a specific rule, whether
every configured host member (in source/destination, including group
members) and every configured service port is actually being used in live
traffic — not just whether the rule itself was hit. Today's `unhit` check
(Audit Review → Hygiene Analysis) only reports whether the *rule* fired at
all; it says nothing about which individual members or ports within it are
dead weight.

4tlog (`~/code/github/web/4tlog`) already owns the FortiAnalyzer connection
and log-search machinery this needs (`app/faz_client.py::search_logs()`,
`app/log_search_filters.py`). 4thealth-plus should not duplicate FAZ
connectivity — it should call 4tlog's log data over a new authenticated
API, the same way FW-Analyst calls 4thealth-plus's own `/external/api/`
today.

This is a two-repo change. This document covers the **4thealth-plus**
consumer side. The companion document
[2026-09-23-log-usage-endpoint-design.md](2026-09-23-log-usage-endpoint-design.md)
specs the new 4tlog-side endpoint this feature depends on — that repo's
spec is handed off for separate implementation in that repo; only this
document is implemented in this session.

## Scope

- One rule at a time. User selects ADOM → Policy Package → a single rule,
  and a day-range (1–60, default 30).
- Flags only single-host address members (type `ipmask` with a /32 mask,
  including members reached through address-group expansion) and single
  discrete service ports as Used/Unused, based on observed traffic.
- Subnets, ranges, FQDN objects, `all`/`any`, and multi-port service ranges
  are informational-only ("not evaluated") — never flagged, consistent with
  how existing hygiene checks treat non-enumerable objects.
- No scheduling, no email reports, no bulk/all-rules mode in this phase.
- Read-only throughout: this feature only reads FMG policy data and 4tlog
  log data. It writes nothing to FortiManager or FortiGate.

## Out of scope (explicitly deferred)

- Scheduled/bulk log-hygiene runs across a whole package or ADOM.
- Subnet-range or service-range partial-usage detection (flagging a /24 or
  a port range as unused because zero traffic fell inside it).
- Any UI on the 4tlog side — 4tlog only exposes the new API.

## Architecture

```
[Audit Review UI] -> POST /api/audit-review/log-usage-check
                          |
                app/log_hygiene.py::check_rule_log_usage()
                          |  (1) fetch rule + expand src/dst/service members
                          |      via existing hygiene.py group-expansion logic
                          |  (2) resolve package device scope via
                          |      FMGClient.get_pkg_scope_members()
                          |  (3) call 4tlog
                          v
                app/log_usage_client.py --(bearer token, HTTPS)--> 4tlog
                                              POST /external/api/log-usage
                          |
                          v (aggregated srcips/dstips/dstports)
                app/log_hygiene.py diffs configured vs observed
                          |
                          v
                    JSON result -> UI tables
```

## Admin configuration

New Admin sub-tab **"Log Hygiene"**, alongside External API / AI Assist /
Scheduled / Backup / Zone Policy.

Fields: 4tlog base URL, bearer token (write-only in the UI after first
save — displayed masked, same convention as SMTP password fields), `verify_ssl`
checkbox, `enabled` toggle, and a "Test Connection" button that calls 4tlog's
`GET /external/api/executive/summary` (or a lighter existing endpoint) with
the stored token to confirm reachability/auth without needing a real policy
query.

**Storage:** new `app/log_source.py`, same atomic-JSON-write pattern as
`app/app_settings.py` / `app/api_tokens.py`. Config file:
`log_source_config.json` (gitignored, project root; ship
`log_source_config.example.json`).

```json
{
  "enabled": false,
  "base_url": "https://4tlog.internal:5443",
  "token": "",
  "verify_ssl": true
}
```

Unlike `app/api_tokens.py` (which stores SHA-256 hashes of *inbound* tokens
this app verifies), this token is an *outbound* credential 4thealth-plus
must send on every request, so it is stored reversibly — the same pattern
already used for `infra_targets.json`'s per-device `"token"` field and
`FMG_API_TOKEN`.

**Feature gate:** `log_hygiene_enabled` — reusing the same on/off UX as
`ai_assist_enabled` (section stays visible, shows a disabled notice, disables
the Run button when off). This is a distinct flag from `external_api_enabled`
(that one gates *inbound* access to 4thealth-plus's own API; this gates an
*outbound* call to another system).

**Admin API endpoints** (all `admin_required`):
- `GET /admin/api/log-source-settings` — returns config with `token` masked
  (e.g. `"token_set": true`, never the plaintext back to the browser)
- `PUT /admin/api/log-source-settings` — updates config; omitting `token` in
  the request body keeps the existing stored token unchanged (so the admin
  isn't forced to re-paste it on every unrelated edit)
- `POST /admin/api/log-source-settings/test` — test-connection probe

## Client — `app/log_usage_client.py`

Thin wrapper, mirrors `app/fmg_client.py`'s request style but far smaller —
a single POST, no session/login lifecycle (4tlog's external API is
stateless bearer-token auth):

```python
class LogUsageError(Exception):
    """Raised on any failure talking to 4tlog: disabled, unauthorized,
    unreachable, or a well-formed error response."""

def get_rule_log_usage(adom: str, devices: list[str], policy_id: int,
                        days: int) -> dict:
    """POST {base_url}/external/api/log-usage. Raises LogUsageError with
    a human-readable message on any failure — the route catches this and
    surfaces it as a non-500 error, same guarantee as every other
    external/AI integration in this app."""
```

Errors are never allowed to become a 500: not-configured, disabled,
unreachable, timeout, and non-2xx responses from 4tlog all raise
`LogUsageError` with a message identifying which of those happened, and the
route translates that into a `502` (or `503` if the feature just isn't
configured) JSON error — same convention as `PlannerDataError` /
`FMGError` handling elsewhere in this app.

## Check engine — `app/log_hygiene.py`

```python
def check_rule_log_usage(adom: str, pkg: str, policy_id: int, days: int) -> dict:
    """Fetch one rule, expand its src/dst/service members, call 4tlog for
    observed traffic over `days`, and return a Used/Unused diff.
    Raises LogUsageError (propagated) or PlannerDataError-style errors for
    FMG-side failures — never partial/garbage results."""
```

Steps:
1. **Fetch the rule.** Reuse the existing package-policy fetch path
   `hygiene.py` uses (so results reflect the live package, not a stale
   cache); locate the rule by `policyid`. 404-equivalent error if not found
   (rule renumbered/deleted since the package list was loaded — same
   "stale finding" concept `hygiene_fix.py` already handles for other
   flows).
2. **Expand members.** Reuse the same address/service group BFS expansion
   `hygiene.py` already performs for `srcaddr_exp`/`dstaddr_exp`/
   `service_exp` (the shared helper backing `/api/hygiene/policies`).
   Classify each resolved leaf member:
   - **Eligible (evaluated):** address objects of type `ipmask` with a
     `/32` mask; service objects with a single discrete TCP/UDP port.
   - **Not evaluated (informational only):** subnets/CIDRs wider than
     /32, IP ranges, FQDN/wildcard-FQDN objects, `all`/`any`, and service
     objects representing a port range or a non-TCP/UDP protocol.
3. **Resolve device scope.** `FMGClient.get_pkg_scope_members(adom,
   pkg_path)` → list of device names the package is installed on. Empty
   scope is a clear error ("package not installed on any device — no logs
   to check"), not a silent empty result.
4. **Call 4tlog.** `log_usage_client.get_rule_log_usage(adom, devices,
   policy_id, days)`.
5. **Diff.**
   - Source hosts: eligible src members vs. response `srcips`.
   - Destination hosts: eligible dst members vs. response `dstips`.
   - Service ports: eligible ports vs. response `dstports`.
   Each entry: `{name, value, status: "used"|"unused"}`.
6. **Return.**
```python
{
  "rule": {"policy_id": 123, "name": "Allow-DC-to-App"},
  "days": 30,
  "time_range": {"start": "...", "end": "..."},
  "log_count": 15234,
  "truncated": false,
  "devices_queried": ["FW-DC-01"],
  "devices_not_found": [],
  "source": {"evaluated": [...], "not_evaluated": [...]},
  "destination": {"evaluated": [...], "not_evaluated": [...]},
  "service": {"evaluated": [...], "not_evaluated": [...]},
}
```

## API routes (`app/routes/audit_review_routes.py`)

- `GET /api/audit-review/log-usage-status` — `{ available: bool }`, reads
  `log_hygiene_enabled` AND whether `log_source_config.json` has a
  `base_url`+`token` set. Mirrors `ai-summary-status`'s contract exactly.
- `POST /api/audit-review/log-usage-check` — body
  `{ adom, pkg, policy_id, days }`. `days` clamped server-side to [1, 60]
  regardless of what the client sends. `check_adom_access(adom)` enforced
  like every other ADOM-scoped route. Returns the `check_rule_log_usage()`
  result, or a `502`/`400`/`503` error object — never a 500.

## UI

New section on `/audit-review` (`audit_review.html` + `audit_review.js`),
below Hygiene Analysis: **"Log-Based Rule Review"**.

1. ADOM selector (existing pattern) → Package selector (existing pattern,
   same package list Policy Rules/Hygiene Analysis already load) → Rule
   picker: search-as-you-type over the package's rule names/IDs (reuses
   the rule list already fetched for the package), single-select.
2. Day-range number input, 1–60, default 30.
3. **Run** button — while the 4tlog call is in flight (can take the same
   10–60s FAZ log-search latency Config-Delta's preview already tolerates),
   show a spinner, same UX pattern as the Config-Delta diff panel.
4. **Results:**
   - Header: rule name + ID, days, actual time range queried, `log_count`.
   - Warning banner if `truncated` ("results may be incomplete — the
     underlying log search hit its row limit") or if `devices_not_found`
     is non-empty (names which devices weren't found in 4tlog).
   - Three filterable tables — **Source Members**, **Destination Members**,
     **Service Ports** — columns Name/Value | Status (Used/Unused, colored
     green/red same as other result tables in this app).
   - A collapsed "N objects not evaluated" panel per table listing the
     informational-only members with their type (subnet/range/FQDN/any/
     port-range), so nothing configured is silently hidden from the
     reviewer even though it wasn't scored.
5. Export CSV/JSON, same client-side pattern as every other export in this
   app (filter header block: package, ADOM, rule, days, timestamp).

Disabled state (feature flag off or not configured): section stays visible
with a disabled notice pointing at Admin → Log Hygiene, Run button disabled
— same pattern as AI Assist when `ai_assist_enabled` is off.

## Error handling summary

| Failure | Surfaced as |
|---|---|
| `log_hygiene_enabled` is false | `503` from `/log-usage-check`; status endpoint reports `available: false` |
| No `base_url`/`token` configured | Same as above — `available: false` |
| 4tlog unreachable / timeout | `502`, message identifies "could not reach 4tlog" |
| 4tlog returns 401 (bad token) | `502`, message identifies "4tlog rejected the configured token" |
| 4tlog returns 404 (ADOM not found there) | `502`, message passes through 4tlog's error text |
| Rule not found in package (stale) | `400`/`404`, "rule not found — package may have changed" |
| Package has no device scope | `400`, "package not installed on any device" |
| `truncated: true` in 4tlog's response | Not an error — `200` with a warning banner in the UI |

## Testing

- Unit tests for `check_rule_log_usage()`'s member-classification logic
  (ipmask /32 vs wider subnet vs range vs FQDN vs `all`; single port vs
  port range vs non-TCP/UDP service) using fixture policy/address/service
  data, mocking `log_usage_client.get_rule_log_usage()`.
- Unit tests for `log_usage_client.py` error paths (disabled, unreachable,
  non-2xx, malformed response) — all must raise `LogUsageError`, never
  propagate a raw exception.
- Route-level tests for `/api/audit-review/log-usage-status` and
  `/log-usage-check`: feature-flag-off, ADOM-access-denied, day clamping,
  and the full happy path with a mocked client.
- No live 4tlog dependency in tests — the client boundary is the mock
  point.

## Open items for the handoff spec

The exact FAZ device→devid resolution behavior, ADOM→FAZ-target matching
when ambiguous, and the `LOG_SEARCH_MAX_RESULTS` truncation threshold all
live in the 4tlog-side spec — see
[2026-09-23-log-usage-endpoint-design.md](2026-09-23-log-usage-endpoint-design.md).
