# Scale Phase 5: Device Audit Snapshots (F4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Device Review (interactive, bulk and scheduled) and PSIRT workaround checks read per-device configuration snapshots that the collector refreshes on a rolling window, instead of making up to ~15 FortiManager proxy calls per device on every run. Every result row carries when its data was collected; a **Live** toggle and a staleness ceiling keep compliance verdicts honest. A 1,000-device Device Review run drops from ~15,000 proxy calls to zero.

**Architecture:** `app/snapshot_store.py` holds one zlib-JSON row per (ADOM, device, data key) with `status`, `collected_at` and a fingerprint, written only by the collector job `app/snapshot_cache.py` (a small batch every few minutes: devices never captured first, then devices whose FMG config revision is newer than their snapshot, then the oldest snapshot). A facade `app/audit_data.py` mirrors the inventory/policy facades: per data key it serves a fresh snapshot, otherwise fetches that key live (counted), and returns provenance. The existing fetch code is moved to `app/device_data.py` and shared by routes and the collector. PSIRT gets an adapter object so the vendored engine is not edited.

**Tech Stack:** Python 3.14, SQLite (shared store), APScheduler, Flask, vanilla JS, pytest, ruff (strict), uv.

**Spec:** `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` (section 3 "decision 3, audit data", 4 F4, 5 Phase 5, 6, 7a). Builds on Phases 1-4 (`app/fmg_access.py`, `app/inventory*.py`, `app/policy*.py`).

## Decision for the owner to review (changes the spec's default)

The spec's accepted decision 3 says "max-age ceiling (default 24 h)" **and** "rolling window, one seventh of the fleet per night". Those conflict: with a 7-day window most snapshots are older than 24 h, so a 24 h ceiling would send 6 of 7 devices live on every run and save almost nothing. Options:

- **A. 24 h ceiling, full daily refresh:** 1,000 devices x ~15 calls per day = ~625 FMG calls/hour in the background (about double today's whole background floor of 309.5), but data is never older than a day.
- **B. (recommended, built as the default) 7-day window, ceiling = window + 1 day (192 h):** ~90 calls/hour (floor ~400/hour, about 9.7x below the original 3,887.8 baseline), plus **change-triggered refresh**: a device whose FMG config revision is newer than its snapshot is refreshed within the hour, so changed devices are not 7 days stale. Compliance rows show their age; the **Live** toggle checks the current device on demand.
- **C. 14-day window:** ~45 calls/hour (floor ~355, past the 10x target) with the same revision trigger.

Knobs: `AUDIT_SNAPSHOT_WINDOW_DAYS` (default 7), `AUDIT_SNAPSHOT_MAX_AGE_HOURS` (default window x 24 + 24). Set window 1 for option A. The baseline of 3,887.8 calls/hour did not include Device Review at all (it was only run on demand), so this phase adds a new background cost to buy a ~15,000-call saving per run.

## Global Constraints

- Branch `develop`; never push. Sonnet or cheaper only. Read-only toward Fortinet (only proxy GETs).
- Flag `AUDIT_SNAPSHOTS` (existing, default off). Off = byte-for-byte legacy: live fetch per run, no store access, no new scheduler jobs, responses without provenance fields.
- Provenance on every Device Review row and PSIRT device result: `collected_at` (the oldest data key used) and `source` (`snapshot` or `live`). Compliance verdicts are never shown without it.
- **A failure is never stored as "empty".** The device getters swallow errors and return `[]`/`{}`; a snapshot must record only data that FortiManager actually returned. A transport failure (FMG RPC error, device unreachable such as "No tunnel", exception) marks the key `unreachable` and keeps the previous snapshot; an HTTP 4xx answer from the device (e.g. no HA configured) is a legitimate empty result. Unreachable devices back off exponentially (15 min doubling to 24 h) so they are not retried every batch.
- The collector is the only writer; web workers read through the facade and never write snapshots. ADOM access (`check_adom_access`) stays in the routes.
- Per-device data stays per ADOM/device, never per user; blobs zlib-compressed JSON; request-path reads load only the keys the selected checks need.
- Fail open: a missing, stale (> `AUDIT_SNAPSHOT_MAX_AGE_HOURS`) or unreadable snapshot makes that read live for that device/key (counted). Never an empty answer.
- Collector concurrency is bounded by `AUDIT_SNAPSHOT_WORKERS` (default 2) and the Phase 1 in-flight cap; FMG serializes proxy work, so more workers do not help (lab: 4 workers ~1.3x).
- Vendored code (`app/psirt/`, `app/planner/`) is not edited. Rule Validation planner stays live.
- Ruff strict, `uv`, TDD, suite green (2,193 at start; bare `pytest`).

## Review Focus

- Failure handling: a tunnel-down device, an FMG RPC error, a timeout or an exception never overwrites a good snapshot and never appears as a clean "empty" configuration (which would flip checks to FAIL/PASS wrongly); a legitimate 4xx (no HA, no FAZ logging) is stored as empty; partial per-key failures keep the other keys; backoff doubles and resets.
- Provenance: every row from every path (interactive per-device loop, bulk run, scheduled job, PSIRT) has `collected_at` and `source`; a row built from several keys reports the OLDEST; live-fetched keys are labelled live; exports (CSV/JSON/PDF/HTML email) include the columns.
- Staleness: nothing older than the ceiling is served as a snapshot; a device removed from the inventory disappears from the store; a revision newer than the snapshot triggers a refresh within the revision-check period; the `Live` toggle really bypasses the store (and never writes).
- Equivalence: with fresh snapshots, `run_checks` output equals the live run for the same data (rows identical apart from the new fields), across all 26 checks and shared data keys (`system_global`, `admins`, `ipsec_*`, `device_meta`).
- PSIRT adapter: workaround checks see exactly what the live client would return; adoms/devices come from the inventory facade; unknown methods are not silently stubbed.
- Scheduling: rolling batch sizes meet the window (every device refreshed within `WINDOW_DAYS` even when some are unreachable); priority order; no overlapping batches; boot warm-up priority; a cold start does not storm FMG.
- Concurrency and size: writers lock only per row; readers lock-free; DB size for 1,000 devices x 17 keys; read latency for one device's keys.
- Access control: every new endpoint/field respects tab and ADOM permissions; status API exposes no configuration content.
- Flag-off identity and the `device_meta` change (inventory instead of a live `get_device`).

## File Structure

- Create `app/device_data.py`: `DATA_KEYS` registry (key -> getter name, default empty value), `fetch_device_data(client, adom, device, keys, device_meta=None)` (moved from `routes/audit_review_routes._fetch_device_data`, same behaviour), `fetch_device_data_checked(...)` returning per-key `(value, failure_or_None)`.
- Modify `app/fmg_client.py`: `capture_proxy_failures()` context manager (thread-local list that `_proxy` appends transport-level failures to).
- Create `app/snapshot_store.py`, `app/snapshot_cache.py`, `app/audit_data.py`, `app/psirt_adapter.py`.
- Modify `app/routes/audit_review_routes.py`, `app/device_review_scheduler.py`, `app/routes/api_routes.py` (status), PSIRT routes, `app/static/js/audit_review.js`, `app/templates/audit_review.html`, `app/synthetic_fmg.py` (the audit resources), `app/inventory.py` (`device(client, adom, name)`), `app/config.py`, `.env.example`.
- `scripts/measure_fmg_baseline.py` (`--audit-snapshots`), `scripts/verify_policy_store_load.py` or a sibling `scripts/verify_snapshot_load.py`, docs, `CLAUDE.md`, `docs/superpowers/measurements/2026-11-phase5-results.md`.
- Tests: `tests/test_device_data.py`, `tests/test_proxy_failure_capture.py`, `tests/test_snapshot_store.py`, `tests/test_snapshot_cache.py`, `tests/test_audit_data_facade.py`, `tests/test_audit_review_snapshots.py`, `tests/test_psirt_snapshots.py`, `tests/test_snapshot_status_api.py`.

---

### Task 1: Shared device-data fetch and proxy failure capture

**Files:** Create `app/device_data.py`; modify `app/fmg_client.py`, `app/routes/audit_review_routes.py`; Test `tests/test_device_data.py`, `tests/test_proxy_failure_capture.py`.

**Interfaces:**
- Produces: `fmg_client.FMGClient.capture_proxy_failures() -> contextmanager yielding list[str]`, filled by `_proxy` with one entry per *transport-level* failure (FMG RPC code != 0, wrapper `proxy_error` such as "No tunnel", or a raised exception); HTTP status 4xx/5xx from the device itself is NOT a transport failure. `device_data.DATA_KEYS: dict[str, tuple[str, object]]` (the 17 keys used by `CHECKS`: `interfaces, ntp, syslog, admins, system_global, password_policy, log_disk, log_faz, dns, snmp_community, snmp_sysinfo, snmp_users, ha_status, ipsec_phase1, ipsec_phase2, device_meta` plus any listed in `CHECKS_META`; each maps to the client getter name and the empty value the legacy code falls back to); `fetch_device_data(client, adom, device, keys: set[str], device_meta: dict | None = None) -> dict` (identical result to today's `_fetch_device_data`; the route function becomes a thin alias); `fetch_device_data_checked(client, adom, device, keys, device_meta=None) -> dict[str, tuple[object, str | None]]` giving `(value, failure_text_or_None)` per key by wrapping each getter call in `capture_proxy_failures()`.

- [ ] **Step 1: Write failing tests:** `test_fetch_device_data_equals_legacy_for_every_key` (run old and new on a synthetic device; compare), `test_capture_records_tunnel_down_rpc_error_and_exception` (scripted `_post` variants), `test_capture_ignores_http_404_from_the_device`, `test_capture_is_thread_local` (two threads), `test_checked_marks_only_the_failed_key` (one getter's proxy fails, others fine), `test_checked_empty_but_ok_is_not_a_failure`, `test_data_keys_cover_every_check_data_key` (union of `CHECKS_META[*].data_keys` is a subset of `DATA_KEYS` or `device_meta`).
- [ ] **Step 2: Run** `pytest tests/test_device_data.py tests/test_proxy_failure_capture.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** (move the 17 try/except branches into a table-driven loop; keep the original swallow semantics in `fetch_device_data`).
- [ ] **Step 4: Run** the two files plus `pytest tests/test_device_review*.py tests/test_fmg_client*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): shared device-data fetch with proxy failure capture`.

### Task 2: Snapshot store

**Files:** Create `app/snapshot_store.py`; modify `app/config.py`, `.env.example`; Test `tests/test_snapshot_store.py`.

**Interfaces:**
- Config: `AUDIT_SNAPSHOT_WINDOW_DAYS` (7), `AUDIT_SNAPSHOT_MAX_AGE_HOURS` (0 = window x 24 + 24), `AUDIT_SNAPSHOT_WORKERS` (2), `AUDIT_SNAPSHOT_BATCH_MINUTES` (10), `AUDIT_SNAPSHOT_REVISION_CHECK_MINUTES` (60).
- Table `device_snapshot(adom, device, data_key, collected_at, status, error, fingerprint, blob, PRIMARY KEY(adom, device, data_key))` and `device_snapshot_state(adom, device, last_attempt_at, fail_count, next_attempt_at, last_ok_at, PRIMARY KEY(adom, device))`. Same connection/lock conventions as `policy_store` (own `schema_id`).
- API: `put_keys(adom, device, values: dict[str, object]) -> None` (all keys one transaction), `mark_failed(adom, device, keys, error)` (keeps blobs, sets status `unreachable`, bumps `fail_count`, sets `next_attempt_at` with doubling backoff 15 min..24 h), `mark_ok(adom, device)` (resets backoff), `get_keys(adom, device, keys) -> dict[key, {value, collected_at, age_seconds, status}]` (only keys that have a blob), `device_meta_rows(adom) -> list[{device, last_ok_at, oldest_key_at, fail_count, next_attempt_at}]` (no blobs), `delete_missing_devices(adom, keep: set[str])`, `delete_missing_adoms(keep)`, `max_age_seconds()`, `SnapshotStoreError`.

- [ ] **Step 1: Write failing tests:** round trip of 17 keys; `test_failed_keys_keep_previous_blob_and_flag_status`; `test_backoff_doubles_then_caps_at_24h_and_resets_on_ok`; `test_empty_value_is_stored_as_collected_empty_vs_never_collected_none`; `test_put_is_atomic_for_readers`; `test_delete_missing_*`; `test_device_meta_rows_does_not_decompress`; `test_reads_do_not_wait_for_write_lock`; `test_unreadable_store_raises`; `test_blob_size_for_a_realistic_device_is_small` (17 keys under 8 KB compressed); `test_max_age_default_derives_from_window`.
- [ ] **Step 2: Run** `pytest tests/test_snapshot_store.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): device snapshot store`.

### Task 3: Collector job and synthetic audit data

**Files:** Create `app/snapshot_cache.py`; modify `app/synthetic_fmg.py`, `app/__init__.py`, `app/boot_warmup.py` (priority 3 slot); Test `tests/test_snapshot_cache.py`.

**Interfaces:**
- Consumes Tasks 1-2, `inventory.devices` (device list), `client.get_adom_revisions`.
- Produces: `snapshot_cache.refresh_batch(client=None, now=None) -> dict` (`{"selected","captured","failed","skipped_backoff","calls","seconds"}`; single-flight): selects up to `ceil(fleet / (WINDOW_DAYS x 24 x 60 / BATCH_MINUTES))` devices (at least 1) ordered (1) never captured, (2) config revision newer than `last_ok_at` (from the hourly revision check, `refresh_revisions(client)`), (3) oldest `oldest_key_at`; skips devices in backoff; fetches via `fetch_device_data_checked` with `AUDIT_SNAPSHOT_WORKERS` threads, stores keys without failures, marks the rest failed; removes devices that left the inventory; `snapshot_cache.init_scheduler(app) -> bool` (False when `AUDIT_SNAPSHOTS` off; jobs `snapshot_batch` every `BATCH_MINUTES` and `snapshot_revisions` every `REVISION_CHECK_MINUTES`; first run via `boot_warmup.defer("snapshot_cache", fn, 3)`). `SyntheticFMG` serves the audit CMDB/monitor resources for its devices with a deterministic mix of compliant and non-compliant values and supports a per-device "down" set (tunnel error) for tests.

- [ ] **Step 1: Write failing tests:** `test_first_batches_cover_every_device_within_the_window` (fleet 70, window 7 days, 10-minute batch: simulate ticks, every device captured, none twice before all), `test_batch_size_formula_and_minimum_of_one`, `test_priority_never_captured_then_newer_revision_then_oldest`, `test_unreachable_device_keeps_old_snapshot_backs_off_and_is_not_retried_until_due`, `test_partial_key_failure_keeps_other_keys`, `test_4xx_ha_answer_is_stored_as_empty_not_a_failure`, `test_removed_device_is_deleted`, `test_workers_cap_respected`, `test_single_flight`, `test_revision_check_makes_one_call_per_adom`, `test_scheduler_not_registered_when_flag_off`, `test_registered_jobs_and_boot_priority`, `test_calls_per_captured_device_at_most_20`.
- [ ] **Step 2: Run** `pytest tests/test_snapshot_cache.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** plus `pytest tests/test_synthetic_fmg.py tests/test_boot_warmup.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): collector device snapshot job`.

### Task 4: Audit data facade

**Files:** Create `app/audit_data.py`; modify `app/inventory.py` (`device(client, adom, name)`); Test `tests/test_audit_data_facade.py`.

**Interfaces:** `audit_data.device_data(client, adom, device, keys: set[str], device_meta: dict | None = None, live: bool = False) -> DeviceData` where `DeviceData` has `.data: dict` (same shape as `fetch_device_data`), `.collected_at: str | None` (oldest timestamp among snapshot-served keys; the fetch time for live keys), `.source: "snapshot" | "live" | "mixed"`, `.per_key: dict[key, {"source","collected_at"}]`; `audit_data.counters()` / `reset_counters()` (`hits`, `fallbacks`, `store_errors`, `live_requests`); `inventory.device(client, adom, name) -> dict` (the device record, from the inventory store when `INVENTORY_CACHE` is on, else `client.get_device`). Flag off or `live=True` -> straight `fetch_device_data` (`source "live"`, no store access); flag on -> per key: fresh `ok` snapshot (age <= `max_age_seconds`) served; otherwise that key fetched live (counted); `device_meta` always from the caller/inventory, never snapshotted.

- [ ] **Step 1: Write failing tests:** `test_flag_off_is_live_and_never_touches_the_store`, `test_live_true_bypasses_a_fresh_snapshot_and_writes_nothing`, `test_fresh_snapshot_zero_fmg_calls_and_provenance`, `test_stale_key_goes_live_others_stay_snapshot_source_mixed`, `test_missing_device_goes_live`, `test_unreachable_status_with_data_within_max_age_is_served_with_its_timestamp`, `test_store_error_goes_live`, `test_collected_at_is_the_oldest_key`, `test_data_equals_live_fetch_for_the_same_synthetic_device`, `test_device_meta_not_from_snapshots`, `test_inventory_device_lookup_from_store_and_live`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): audit data facade with provenance and fail-open fallback`.

### Task 5: Device Review reads snapshots; provenance and Live toggle

**Files:** Modify `app/routes/audit_review_routes.py` (per-device route, bulk route, `bulk_device_review_adom`), `app/device_review_scheduler.py`, `app/device_review.py` (row fields), `app/static/js/audit_review.js`, `app/templates/audit_review.html`; Test `tests/test_audit_review_snapshots.py`.

**Interfaces:** `POST /api/audit-review/run/device` and `/run` accept `live: bool` (default false); every returned row gains `collected_at` and `source`; `bulk_device_review_adom(adom, checks, check_params, max_workers=4, live=False)`; CSV/JSON/PDF exports and the scheduled-report summaries include "Data as of" and source; the UI adds a **Live (fetch current config)** checkbox and a "Data as of" column plus a notice listing devices whose data is older than 24 h; AI summary input unchanged (it narrates already-computed rows).

- [ ] **Step 1: Write failing tests** (flag on, populated store, client that raises on any proxy call): `test_per_device_run_rows_equal_live_rows_plus_provenance` (all 26 checks), `test_bulk_run_zero_proxy_calls_with_snapshots`, `test_live_true_fetches_current_config_and_labels_rows_live`, `test_row_reports_oldest_key_when_several_keys_used`, `test_stale_snapshot_rows_label_mixed_or_live`, `test_scheduled_bulk_uses_snapshots_and_email_states_oldest_data_age`, `test_exports_include_data_as_of_columns` (CSV header, JSON field, HTML), `test_restricted_user_403_other_adom_with_snapshots_on`, `test_flag_off_rows_have_no_new_fields_and_fmg_called_as_before`, `test_device_meta_from_inventory_not_live_get_device`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** (JS: checkbox sends `live`, new column; escape via `textContent`).
- [ ] **Step 4: Run** the file plus `pytest tests/test_device_review*.py tests/test_audit_review*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): Device Review reads device snapshots with provenance and a Live toggle`.

### Task 6: PSIRT reads snapshots through an adapter

**Files:** Create `app/psirt_adapter.py`; modify the PSIRT routes in `app/routes/audit_review_routes.py` (assess/device, assess); Test `tests/test_psirt_snapshots.py`.

**Interfaces:** `psirt_adapter.SnapshotFMGAdapter(client, live=False)` exposing exactly what the vendored `app/psirt` code calls: `get_adoms()`, `get_devices(adom)` (inventory facade), `get_system_status()` (delegated), `get_device_interfaces_all_vdoms(adom, device)` and `get_device_admins(adom, device)` (served via `audit_data.device_data`, recording provenance per device), `provenance(device) -> {"collected_at","source"} | None`; any other attribute access raises `AttributeError` (no silent stubs). The assess routes use the adapter when `AUDIT_SNAPSHOTS` is on and attach `data_as_of`/`source` to each device result and to the HTML report; request flag `live`.

- [ ] **Step 1: Write failing tests:** `test_assess_with_snapshots_equals_live_assessment_zero_proxy_calls`, `test_workaround_check_sees_snapshot_interfaces_and_admins`, `test_provenance_attached_to_device_results_and_report`, `test_live_flag_bypasses_snapshots`, `test_unknown_adapter_method_raises`, `test_adoms_and_devices_come_from_inventory_facade`, `test_star_adom_assessment_respects_adom_access`, `test_flag_off_unchanged`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** plus `pytest tests/test_psirt*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): PSIRT workaround checks read device snapshots`.

### Task 7: Snapshot status API and coverage badge

**Files:** Modify `app/routes/api_routes.py`, `app/static/js/audit_review.js`, `app/templates/audit_review.html`, `app/__init__.py` (context flag); Test `tests/test_snapshot_status_api.py`.

**Interfaces:** `GET /api/audit-snapshots/status?adom=` (login + `audit_review` tab + `check_adom_access`) -> `{enabled, adom, window_days, max_age_hours, devices_total, devices_captured, coverage_pct, devices_stale, devices_unreachable, oldest_at, newest_at}` (no config content); the Device Review section header shows "Snapshots cover N of M devices, oldest X ago" with stale/degraded styling (hidden when the flag is off).

- [ ] **Step 1: Write failing tests:** requires login/tab/ADOM access, disabled shape when flag off, counts and stale/unreachable classification, coverage math, no blobs in the response, page hook only when enabled.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): snapshot status API and coverage badge`.

### Task 8: Measure, load check, docs, full verification

**Files:** Modify `scripts/measure_fmg_baseline.py`, create `scripts/verify_snapshot_load.py`, docs (`docs/deployment.md`, `CLAUDE.md`, `.env.example`, `docs/superpowers/measurements/README.md`), create `docs/superpowers/measurements/2026-11-phase5-results.md`; Test `tests/test_measure_baseline.py`, `tests/test_snapshot_load_script.py`.

**Interfaces:** `measure(..., audit_snapshots=True)` adds source `snapshot_cache` (batch calls x batches per hour, steady state, plus the hourly revision check) and a Device Review comparison (`device_review_run_calls`: live run vs snapshot run on the same fleet); `verify_snapshot_load.py` writes a 1,000-device synthetic fleet through the collector code path while reader processes query it and prints DB size, write time, per-device read p50/p95, and a bulk Device Review run time with zero FMG calls.

- [ ] **Step 1: Write failing tests:** `test_measure_audit_snapshots_reports_snapshot_source_and_zero_review_calls`, `test_snapshot_load_script_small_run_passes`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement;** run `PYTHONPATH=. uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache --policy-store --audit-snapshots --out docs/superpowers/measurements/2026-11-phase5-1000.json` and `scripts/verify_snapshot_load.py`. Expected: background total ~400 calls/hour at the default 7-day window (the results note shows the 14-day and 1-day variants), Device Review run 0 calls, store size and latencies recorded.
- [ ] **Step 4: Docs:** the new settings, the window/ceiling trade-off (options A/B/C) and which to choose, the staleness statement (up to window + 1 day unless the revision trigger or Live is used), provenance columns, rollback (`AUDIT_SNAPSHOTS` off + restart), unreachable-device backoff, that the lab proof is the same two RHEL checks plus `verify_snapshot_load.py`.
- [ ] **Step 5: Run the full suite** (bare `pytest`) and `ruff check` + `ruff format --check` on changed files. Expected: all pass.
- [ ] **Step 6: Commit** `feat(scale): Phase 5 measurements and docs`.

## Self-review notes

- Spec coverage: F4 rolling window and per-device storage with `collected_at` (T2-T3), decision 3 hybrid with provenance, ceiling and Live toggle (T4-T5, flagged conflict resolved as option B), PSIRT reads (T6), F8 for these views (T7), acceptance targets 1 and 5 (T8).
- Builder's calls, challengeable: default window 7 days and ceiling 8 days (spec said 24 h; see "Decision for the owner"); revision-triggered refresh uses the ADOM revision list (one call per ADOM per hour, a hint not proof); multi-target proxy batching stays unused (unproven on one lab device); snapshots store raw getter output per data key rather than check results, so new checks reuse existing data.
- Not in this phase: job queue (Phase 6); changing the check engine; Config-Delta (Phase 3).
