# Changelog

All notable changes to 4THealth+ are documented in this file.

## [Unreleased]

### AI features expansion
- **Added:** shared `app/ai_narrate.py` helper used by the new AI features.

### Scale foundations for 1,000+ FortiGates (all layers default off)
Four layer flags (`INVENTORY_CACHE`, `POLICY_STORE`, `AUDIT_SNAPSHOTS`, `JOB_QUEUE`) switch each area from live FortiManager reads to data the collector keeps in the shared SQLite store. With a flag off, behaviour is unchanged. Measured on a synthetic 1,000-device fleet, background FortiManager calls fell from 3,887.8 to 434.5 per hour (8.9x), and interactive Rule Review, Rule Lookup, hygiene, object lookups, Device Review and PSIRT workaround checks make no per-request FortiManager calls. Design: `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md`; results per phase: `docs/superpowers/measurements/`.
- **Added: FMG access layer.** One pooled session per process, a cap on in-flight calls (`FMG_MAX_INFLIGHT`), jittered retries (`FMG_RETRIES`; an `exec` is never replayed) and per-URL call metrics (Admin → FMG metrics, `FMG_METRICS=off` disables).
- **Added: `INVENTORY_CACHE`.** The collector keeps ADOMs, devices and per-VDOM package status; the dashboard, Map, Versions, Firewalls list and Config-Delta device list read it and fall back to a live call (counted) when data is missing or stale. Adds a staggered boot warm-up and a data-age badge with a Refresh button.
- **Added: Config-Delta gating.** Scheduled runs skip devices whose cached state is clean and fresh, with a periodic full sweep (`CONFIG_DELTA_GATING`, `CONFIG_DELTA_FULL_SWEEP_HOURS`, `CONFIG_DELTA_JOB_BUDGET_SECS`); a user-clicked preview stays live. Devices past the time budget are reported as errors, never as clean.
- **Added: `POLICY_STORE`.** Policy packages, policies, policy blocks and firewall objects are stored by the collector; a package's Refresh button and Rule Lookup's refresh queue a request the collector serves. The executive hygiene sweep reuses per-package results until a package changes or `HYGIENE_PACKAGE_TTL_HOURS` passes. Package Change Alerts, the Rule Validation planner, log hygiene and per-device reads stay live.
- **Added: `AUDIT_SNAPSHOTS`.** The collector captures each device's configuration (15 data keys) in a rolling window (`AUDIT_SNAPSHOT_WINDOW_DAYS`, default 7; served up to window + 1 day unless a device's FMG config revision is newer, which refreshes it within about an hour). Device Review and the PSIRT workaround checks read it; every row shows **Data as of** and **Source**, scheduled reports state the oldest data's age, a **Live (read devices now)** checkbox bypasses the store, and Audit Review shows "Snapshots cover N of M devices". A device FortiManager cannot reach keeps its last snapshot and is retried with backoff; a device answering 4xx/5xx is never stored as its configuration.
- **Added: `JOB_QUEUE`.** Device Review's Run Review and Hygiene Analysis's Run Analysis run as collector-executed jobs with progress, Cancel and resume after a page reload (`JOB_MAX_RUNNING`, `JOB_MAX_QUEUED_PER_USER`, `JOB_MAX_RESULT_BYTES`, `JOB_RETENTION_DAYS`). A user sees only their own jobs (admin sees all) and loses sight of a job once the ADOM is no longer accessible; jobs running during a collector restart are marked failed.
- **Added: proof tooling.** `scripts/measure_fmg_baseline.py` (`--inventory-cache --policy-store --audit-snapshots`), `scripts/verify_shared_store.py`, `verify_policy_store_load.py`, `verify_snapshot_load.py`, `verify_job_queue.py`, and a synthetic FortiManager (`app/synthetic_fmg.py`, `scripts/synthetic_fmg_server.py`). `docker-compose.rig.yml` now turns all four layers on for the Docker test rig.
- **Changed:** `FMGClient._proxy` can record swallowed device-read failures (`capture_proxy_failures`); `bulk_device_review_adom` and the Hygiene run endpoint now share functions (`compute_device_review`, `compute_hygiene_run`) with the job queue.
- **Operations:** run both systemd units with the same `.env`, restart both after changing a flag, and run the four proof scripts once on the RHEL host before enabling layers (`docs/deployment.md`). Rollback is turning a flag off and restarting.

### FortiManager 7.4 / 7.6 / 8.0 compatibility
- **Added: FMG version detection.** `FMGClient.version` reads the release from `/sys/status` (lazy, cached, `None` if unavailable) so code can branch on `>= (7, 6)`.
- **Added: Admin → API Self-Test.** A read-only check of the FMG calls the app depends on (system status, ADOMs, resource/audit-log, devices, revisions, packages, policies, objects, device proxy). Each reports ok / denied (`-11`, token profile lacks access) / error / skipped, with the feature that depends on it. Runs on an explicit click only and never stages an install preview.
- **Added: recorded FMG fixtures.** `FMG_RECORD_FILE` / `scripts/record_fmg_fixture.py` capture scrubbed JSON-RPC traffic; replay tests run the real client, the self-test and the install-preview chain offline against `tests/fixtures/fmg_8.0.2`. Add 7.4 and 7.6 captures the same way.
- The fixture scrubber also replaces UUIDs (device and object IDs) consistently, and `tests/fixtures/fmg_8.0.2` was re-recorded with it.
- **Added:** `FMG_PREVIEW_TIMEOUT_SECS` (default 120) and `FMG_PREVIEW_LOCK_WAIT_SECS` (default 900).
- **Changed: install previews are serialized per FMG + ADOM** with an OS file lock, covering every thread and gunicorn worker of a container (the collector container is still serialized only by FMG). A timeout now says the FMG may be busy. The log records whether the diff came from the preview or the stage task (7.4.x vs 7.6.7 / 8.0.2).
- **Changed: swallowed FMG failures are recorded** in `client.degraded` (performance, resource usage, audit log so far) and `FMGError` carries FMG's status `code`.
- **Fixed:** a device whose FGFM tunnel is down (`No tunnel`) was returned as if it were device data, producing blank license status; it is now a 502 with a `proxy_error`.
- **Fixed / Changed: one firmware-string formatter** (`format_fortios_version`) replaces seven copies. An unknown patch no longer shows as `v7.6.-1`, a string `os_ver` like `"7.0"` uses its leading integer, and a garbage patch value no longer raises.
- **Build:** `uv.lock` regenerated to match `pyproject.toml`.
- Verified against FortiManager 8.0.2 with FortiOS 8.0.2; no application change was needed for the 8.0 API.

### Added
- **Device Versions — Hardware Model charts:** bar charts under the firmware-version charts (global and per-ADOM) counting online physical units by model. HA clusters are expanded into individual members with Primary/Secondary badges; VM FortiGates group into "Virtual"; no model is "Unknown". New `/api/adoms/<adom>/units` endpoint; the global versions cache now stores `ip`, `serial`, `platform` and `ha_role` per unit.

### Changed
- **Renamed "Device Review" tab to "Audit Review"** and merged the Rule
  Review tab's Hygiene Analysis section into it. Internal tab key
  `device_review` → `audit_review`; URL `/device-review` → `/audit-review`.
  Audit Review now has three sections: **Device Review** (CIS/interface
  audit), **Hygiene Analysis** (policy package hygiene checks, moved from
  Rule Review), and **PSIRT Advisory Assessment** (unchanged location).
  Rule Review keeps Policy Rules, Object Lookup, Interface Lookup, and NAT
  Lookup.
- `/api/hygiene/adoms/<adom>/packages` (and `/packages/raw`) now accept
  either the `rule_hygiene` or `audit_review` tab key, since the package
  selector is shared by both pages; `/api/hygiene/run`,
  `/api/hygiene/unused-objects`, `/api/hygiene/ai-explain-status`, and
  `/api/hygiene/explain-finding` are now gated to `audit_review` only.
- Admin → Scheduled: "Device Review Jobs" section renamed to "Audit Review
  Jobs"; API path `/admin/api/device-review/jobs*` →
  `/admin/api/audit-review/jobs*`. Scheduled email subjects and reports
  updated from "Device Review" to "Audit Review". The underlying scheduler
  module, job file (`device_review_jobs.json`), and check-engine module
  (`app/device_review.py`) keep their filenames for backward compatibility.
- `tab_required` decorator now accepts multiple permission keys
  (`tab_required(*tab_keys)`), passing if the user has any of them.
- **Migration:** groups with `device_review` in `allowed_tabs` must be
  updated to `audit_review` (Admin → Groups & Permissions).

### Added
- **Package Change Alerts:** New Admin → Scheduled section. Rules watch policy
  packages in an ADOM and, at the end of each Config-Delta job run, email one
  message per package with a new pending policy diff (attachment 1:
  policy-section diff; attachment 2: policy "as is" with groups). Identical
  diffs are not resent; failed sends retry on the next run; device-group
  package scopes are expanded. Includes "Send test email". Rules live in
  `package_change_alerts.json`; endpoints under
  `/admin/api/package-alerts/rules*`. Ported from web/4thealth.
- **Dashboard ADOM Summary:** one tile per ADOM with firewall and rule counts
  (`adom_breakdown` in the summary job's store).
- **Map firewall search:** "Find firewall" box zooms to, opens and highlights
  a device marker, with not-found / hidden-by-ADOM feedback.
- **Zone Policy:** Query Flow results export (CSV/JSON/HTML); Admin → Zone
  Policy backup now also downloads the file, new Restore from Backup
  (`POST /api/zone/restore`, validated, auto-backs-up the live DB first), and
  a live rule preview when typing a policy index.
- **"Exempt" comment whitelist (Rule Hygiene):** add the word "Exempt"
  anywhere in a rule's comment (case-insensitive) and every hygiene check
  silently skips that rule on every future run — interactive and scheduled
  alike — no matter which checks are selected. Shadow/redundant analysis for
  *other* rules is unaffected: an exempted rule still counts as the
  earlier/broader rule when determining whether it shadows something else;
  only findings about the exempted rule itself are suppressed
  (`app/hygiene.py::_is_exempt()`, applied in `run_checks()`). Hygiene Fix's
  existing over-permissive "Exempt (keep enabled)" option already writes a
  `[HygieneFix EXEMPT YYYY-MM-DD]` comment tag — this closes the loop, so
  picking that fix now also stops the rule being re-flagged going forward.
- **Hygiene Fix findings grouped by rule:** the Hygiene Fix AI Assist mode's
  results (both the live view and the downloaded HTML report) are now
  stable-sorted by `policy_id` so every finding against the same rule is
  adjacent, instead of scattered in check-run order. Each finding also
  carries a `related_checks` list, surfaced as "Also flagged by: ..." in the
  UI, so a reviewer can catch two findings on the same rule recommending
  conflicting actions (e.g. Shadow's "narrow scope, keep enabled" vs.
  Unhit's "disable") before applying either.
- **Over-Permissive Rules check (Rule Hygiene):** flags enabled accept rules
  where 2 or more of the 3 traffic dimensions (source, destination, service)
  are set to ANY/ALL — `critical` when all three are unrestricted, `high`
  when exactly two are. Ported from the sibling
  [4THealth](https://github.com/Alski-MPLS/4thealth) repo.
- **Rule Hygiene Scheduled Jobs (Admin → Scheduled):** admins can create recurring
  Rule Hygiene audit jobs — choose an ADOM, select any subset of the 8 hygiene
  checks, optionally include unused-object analysis, set a day-of-week + time
  schedule, and email per-package reports (HTML, CSV, or JSON) as zip
  attachments. Jobs persist in `rule_hygiene_jobs.json` and are registered as
  APScheduler CronTriggers at startup, mirroring the existing Config-Delta and
  Device Review schedulers (`app/rule_hygiene_scheduler.py`). ADOMs with more
  packages than the configured batch size split into multiple `[Part N of M]`
  emails; the first carries the full per-package summary table. New
  `bulk_hygiene_adom()` session-free entry point in `app/routes/hygiene_routes.py`
  runs checks across all packages in an ADOM via a thread pool. Ported from the
  sibling [4THealth](https://github.com/Alski-MPLS/4thealth) repo.
- **PSIRT Advisory Assessment (Device Review tab):** New section — paste or
  upload a Fortinet PSIRT advisory email, get an LLM-assisted structured
  extraction (editable before running), then a deterministic per-device
  fleet scan across one ADOM or all accessible ADOMs: firmware version vs.
  the advisory's affected ranges, workaround-in-place verification against
  live FortiManager config, and exploit-aware priority scoring (CVSS band,
  Fortinet's own exploitation wording, CISA KEV catalog). Renders a
  self-contained HTML report. Ported from the sibling
  [4tanalyst](https://github.com/gatecrest-labs) `psirt/` package — see
  `app/psirt/VENDORED_FROM.md`. Enrichment against fortiguard.com/CISA KEV
  is opt-out via `PSIRT_ENRICHMENT_ENABLED` for air-gapped deployments. No
  disposition persistence in v1 — one-off analysis, same as NAT Lookup.
- 8 new Device Review CIS checks, ported from the sibling
  [4THealth](https://github.com/Alski-MPLS/4thealth) repo (18 -> 26 total
  checks): `admin_mfa`, `hostname_changed`, `admin_port_nondefault`,
  `prelogin_banner`, `timezone_set`, `vpn_weak_crypto`, `vpn_pfs`, and
  `vpn_ike_version`. The 3 VPN checks add `FMGClient.get_device_ipsec_phase1()`/
  `get_device_ipsec_phase2()` and new `ipsec_phase1`/`ipsec_phase2` data keys.
  Ported with upstream's same-day field-name fixes already applied
  (`admin-sport`/`adminsport` and `pre-login-banner`/`preloginbanner`
  fallback lookups, `None`-sentinel for timezone so a valid `0` isn't
  misread as unset).
- FQDN Allowlist mode in Rule Validation's AI Assist panel: submit a vendor's
  FQDN/wildcard-FQDN allowlist request — manual entry rows or an uploaded
  `.xlsx` sheet — and get a deterministic per-firewall coverage analysis plus
  proposed FortiGate CLI (address objects, destination group, policy) for
  anything not already covered, with the same best-effort LLM narration
  guarantee as the existing single-change mode
  (`app/planner/fqdn_intake.py`, `app/planner/engine.py::plan_fqdn_change`,
  `POST /api/rule-review/ai-assist-fqdn`). Existing `plan_change()` now
  rejects non-IP src/dst up front, pointing callers at `plan_fqdn_change()`.
- AI-generated trend summary on the Admin page's host resource graphs
  (CPU/Memory/Disk): deterministic 7-day trend statistics (percent change,
  slope, days-to-threshold projection) computed in Python, then phrased by
  the configured LLM provider on demand (`app/host_metrics_ai.py`,
  `GET /admin/api/host-metrics/ai-summary`). Reuses the existing
  `ai_assist_enabled` flag.
- AI-generated narrative summary for Config-Delta install-preview diffs, both
  on-demand (per-device "Summarize with AI" button) and in scheduled export
  emails (`app/pending_changes_ai.py`,
  `POST /api/pending-changes/adoms/<adom>/device/<device>/ai-summary`).
- Per-finding "Explain" action in Rule Hygiene Analysis: AI-written
  explanation plus a suggested FortiOS CLI remediation snippet for a single
  finding (`app/hygiene_ai.py`, `POST /api/hygiene/explain-finding`).
- AI-generated narrative summary for Device Review (CIS check) results, both
  on-demand and in scheduled email/PDF reports
  (`app/device_review_ai.py`, `POST /api/device-review/ai-summary`).
- AI Assist mode in Rule Validation: single-request change analysis powered by
  a ported deterministic planner (`app/planner/`) plus multi-provider LLM
  narration (`app/llm/` — Claude default, Codex, Ollama). Admin-gated via a
  new `ai_assist_enabled` setting; existing bulk CSV/XLSX workflow unchanged.
- Initial fork from [4THealth](https://github.com/) as the 4THealth+ base repository.
- Rebranded user-facing text (page titles, nav, CLI help, generated email/report
  content, documentation) from "4THealth" to "4THealth+". Internal identifiers
  (Python package name, systemd service name, Docker image/container names,
  file paths, RADIUS/AD literal values) intentionally left unchanged to match
  the existing deployment tooling.

### Fixed
- Hygiene Fix's "unnamed rule" remediation (`app/hygiene_fix.py::_fix_unnamed()`)
  fell back to applying the literal placeholder string "Unknown -- Requires
  additional research" as the rule's actual name via `set name` whenever it
  couldn't derive one from a non-generic source/destination pair (e.g. a
  rule whose source is `all` but whose destination is a specific object) —
  the placeholder also exceeded the app's own 35-character name limit. It
  now returns no automated fix in that case (info-only "manual naming
  required" explanation), matching the existing `missing_security_profile`
  pattern.
- NAT Lookup only searched ADOM-level shared VIP/IP-pool objects, missing
  VIPs installed on an individual device but never promoted to the shared
  object database. It now also sweeps every device's own VIP table (all
  VDOMs, 10-worker parallel fetch via new `FMGClient.get_device_vip_objects()`)
  and merges the results, tagging each hit with its source device (blank =
  "shared"). Also fixes fragile field parsing that under-matched real FMG
  data: `extip` returned as a list or as a range (`"1.2.3.4-1.2.3.9"`) instead
  of a bare IP, and `mappedip`/`mapped-ip` returned as a plain string,
  list-of-strings, or list-of-dicts depending on FMG version/context. The
  response now includes an `objects_checked` summary (shared VIPs, device
  VIPs, devices scanned, pools) shown in the UI results header; the results
  table, filter, and CSV/JSON/PDF exports gained a Device column. Ported from
  the sibling [4THealth](https://github.com/Alski-MPLS/4thealth) repo.
- `FMGClient.get_device_policy_package()` only matched a policy package's
  scope member when it named the device directly, so devices that receive a
  package via device-group membership (not a direct scope entry) showed no
  installed package. Now resolves device-group scope members too, in three
  passes that avoid O(N) extra API calls: collect unmatched scope names,
  intersect with a single device-group-name lookup, then fetch members only
  for that small intersection. New `FMGClient.get_device_group_names()`/
  `get_device_group_members()`. Ported from the sibling
  [4THealth](https://github.com/Alski-MPLS/4thealth) repo.
- CLI injection in generated FortiGate config: FQDN/vendor/category-derived
  object, group, and policy names/comments were interpolated into generated
  CLI without escaping. Closed with two defense layers — input sanitization
  in `app/planner/engine.py` plus `_safe_cli_str()` escaping at every CLI
  generation sink in `app/planner/cli_gen.py`, including `policy_cli()`
  (shared with the pre-existing IP-based planning path).
- FQDN Allowlist mode's rendered CLI showed the literal `<TICKET_ID>`
  placeholder in every object/group/policy comment even when a real ticket
  ID was supplied — the substitution was never wired through. Fixed for
  both the FQDN and IP-based planning paths (`app/planner/cli_gen.py`,
  `app/planner/engine.py`).
- `app/planner/fetch.py`'s routing-table parsing read the *static route
  config* field names (`dst`/`device`) instead of the field names FortiOS's
  live monitor API actually returns (`ip_mask`/`interface`), so the
  default-route/interface-resolution fallback silently found nothing
  against real FortiManager data even when a default route was plainly
  visible in the Firewalls tab.
- FQDN Allowlist mode's destination-interface resolution now looks up the
  device's default route (`0.0.0.0/0`) directly instead of inferring it by
  longest-prefix-matching a hardcoded `8.8.8.8` sentinel IP against the
  routing table — avoids a false match against an unrelated, more-specific
  static route that happens to cover that one sentinel IP.
- FQDN Allowlist mode no longer emits a spurious "'ANY' is not a valid
  IP/CIDR" warning alongside the correct built-in-`all`-object warning when
  the source IP is `any`/`all`/a named object.
- FQDN Allowlist mode's result panel now shows a labeled summary (policy
  name, target package, interfaces, service) above the generated CLI,
  split into "New Address/Service Objects", "New Destination Group", and
  "New Policy" sections, instead of one unlabeled block of concatenated
  CLI (`app/static/js/rule_review.js`).
