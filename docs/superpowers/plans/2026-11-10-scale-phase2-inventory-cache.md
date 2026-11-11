# Scale Phase 2: Inventory Cache, Boot Stagger, Freshness UI (F2 + F7 + F8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The collector fetches the device inventory (ADOMs, devices, VDOMs, HA, conn/conf/db status, per-VDOM package status) once per ADOM every few minutes into the shared store; every consumer reads it from there instead of calling FortiManager itself, so steady-state background FMG calls fall from 3,887.8/h to <= 700/h at 1,000 synthetic devices (full 10x lands with Phases 3-4).

**Architecture:** A collector job (`app/inventory_cache.py`) writes per-ADOM rows to new tables in the shared SQLite store (`app/inventory_store.py`), replacing an ADOM's rows in one transaction. A facade (`app/inventory.py`) gives consumers the same shapes `FMGClient.get_adoms()/get_devices()/get_devices_with_sync_status()` return today; behind `INVENTORY_CACHE` it serves from the store and fails open to a live call only when an ADOM's data is older than a ceiling. Boot warm-up becomes ordered and jittered (F7). A status endpoint and a small shared badge show "data as of" (F8).

**Tech Stack:** Python 3.14, SQLite (WAL, existing `collector_store._connect`), APScheduler, Flask, vanilla JS, pytest, ruff (strict), uv.

**Spec:** `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` (sections 4 F2/F7/F8, 5 Phase 2, 6, 7a). Measurements: `docs/superpowers/measurements/2026-11-phase0-results.md`, `2026-11-baseline-1000.json`.

## Global Constraints

- Branch `develop`; never push. Sonnet or cheaper only. Layer flag `INVENTORY_CACHE` (existing `Config.INVENTORY_CACHE`, default off): off = byte-for-byte legacy behaviour at every seam.
- Read-only toward Fortinet: nothing here writes to FortiManager.
- Store ADOM data per ADOM, never per user. ADOM access control (`check_adom_access`, list filters) stays in the routes exactly as today; the facade never filters by user.
- Request-path store reads are indexed per-ADOM queries (no whole-fleet `json.loads`).
- Fail open: missing/stale/unreadable inventory means a live FMG call (counted), never an empty answer.
- ADOM filtering convention unchanged: names starting with `forti` (case-insensitive) are excluded by callers as today.
- Defaults: `INVENTORY_REFRESH_SECS=300`, `INVENTORY_MAX_AGE_SECS` default `3 x refresh` (900), `INVENTORY_PARALLEL_ADOMS=4`. FMG in-flight cap (Phase 1) still applies to every call.
- Facade returns defensive copies; stored data is never mutated by a consumer (legacy `get_devices_with_sync_status` mutated its dicts in place).
- Do not change vendored `app/psirt/` code or `app/planner/` (they keep calling the client live; planner is a single live request by design). `fmg_selftest` stays live (it exists to test FMG).
- Ruff strict, `uv`, TDD, suite green (1,777 at start; run bare `pytest`).

## Findings this plan relies on

- Lab probe (2026-11-10, FMG 8.0.2): `GET /pm/config/adom/<adom>/_package/status` returns one entry `{dev, vdom, pkg, status, ...}` per device/VDOM in a single call (same entries as the per-device URL). `pending_status_cache` currently makes one such call per device per VDOM (3,340/h of the 3,887.8/h baseline).
- The bulk device list already embeds each device's `vdom` records, `ha_slave`, `conn_status`, `conf_status`, `db_status`; the 5 listed consumers + Firewalls list/Versions/Map/Dashboard all derive from it.
- No package change marker exists (hash+TTL for Phase 4); FMG serializes proxy work, so inventory uses only dvmdb/pm reads (cheap) and parallelism across ADOMs is capped at 4.

## Review Focus

- A reader never sees a half-written ADOM (refresh replaces rows in one transaction); a crash mid-refresh leaves the previous data intact.
- A device or ADOM deleted in FMG disappears from the store on the next successful refresh; a *failed* ADOM fetch keeps its last good rows and is marked `error`, and the facade still serves them while within the max-age ceiling, then fails open live.
- `conf_status`/`db_status` normalization from cached raw rows equals the legacy `get_devices_with_sync_status` output exactly (including unknown/odd values), without mutating the stored rows.
- Per-device package-status derived from the bulk rows equals legacy `get_device_pkg_status` (modified if any listed VDOM modified/conflict; nomod if any installed; else empty) including multi-VDOM devices and VDOMs absent from the bulk answer.
- Flag off: no store reads/writes, no new scheduler job, no new endpoints behaviour change.
- Concurrency: facade reads while the collector refreshes; two web workers and the collector on one SQLite file; Refresh-now throttling cannot be used to hammer FMG.
- Stale-but-served data is visibly labelled (F8), never silently presented as fresh.

## File Structure

- Modify `app/fmg_client.py`: `get_adom_package_status(adom) -> list[dict]`; module functions `normalize_sync_status(devices: list) -> list`, `pkg_status_for(rows: list, device: str, vdom_names: list) -> str`; `get_devices_with_sync_status` delegates to `normalize_sync_status`.
- Modify `app/synthetic_fmg.py`: answer `/pm/config/adom/<adom>/_package/status[/<dev>[/<vdom>]]`.
- Create `app/inventory_store.py`: tables + `replace_adom`, `read_adoms`, `read_devices`, `read_pkg_status`, `read_meta`, `mark_adom_error`, `delete_missing_adoms`, refresh-request helpers.
- Create `app/inventory_cache.py`: `refresh_once(client=None) -> dict`, `init_scheduler(app)`.
- Create `app/inventory.py`: facade `adoms(client)`, `devices(client, adom)`, `devices_with_sync_status(client, adom)`, `pkg_status(client, adom, device, vdom_names)`, `freshness()`, counters.
- Modify consumers: `app/summary_job.py`, `versions_cache.py`, `map_cache.py`, `adom_cache.py`, `pending_status_cache.py`, `executive_summary_cache.py`, `device_backup_cache.py`, `license_status_cache.py`, `nat_report_scheduler.py`, `routes/api_routes.py`, `routes/rule_review_routes.py`, `routes/audit_review_routes.py`.
- Create `app/boot_warmup.py`; modify `app/__init__.py` (`start_all_schedulers`) and each cache's startup refresh.
- Create `app/static/js/freshness.js`; modify base template(s) and `routes/api_routes.py` (status + refresh endpoints).
- Modify `scripts/measure_fmg_baseline.py`; docs `docs/deployment.md`, `CLAUDE.md`, `.env.example`; write `docs/superpowers/measurements/2026-11-phase2-results.md`.
- Tests: `tests/test_fmg_pkg_status_bulk.py`, `tests/test_inventory_store.py`, `tests/test_inventory_cache.py`, `tests/test_inventory_facade.py`, `tests/test_inventory_consumers.py`, `tests/test_boot_warmup.py`, `tests/test_inventory_status_api.py`.

---

### Task 1: Bulk package status and shared normalizers

**Files:** Modify `app/fmg_client.py`, `app/synthetic_fmg.py`; Test `tests/test_fmg_pkg_status_bulk.py`.

**Interfaces:**
- Produces: `FMGClient.get_adom_package_status(adom: str) -> list[dict]` (GET `/pm/config/adom/{adom}/_package/status`; returns `[]` on a non-list answer, raises `FMGError` on FMG error like `_get`); `normalize_sync_status(devices: list) -> list[dict]` (module level; pure; returns **copies**, skips non-dicts, same int->string maps as today); `pkg_status_for(rows: list[dict], device: str, vdom_names: list) -> str`; `get_devices_with_sync_status` keeps its exact result by delegating to `normalize_sync_status` (it may keep mutating nothing it returns... it returns the normalized copies).

- [ ] **Step 1: Write failing tests:** `test_normalize_sync_status_matches_legacy_for_all_values` (parametrize conf 0/1/2/"x"/None/missing, db 0/1/2/"x"; compare to the legacy mapping table), `test_normalize_returns_copies_and_skips_non_dicts`, `test_pkg_status_for_modified_wins`, `test_pkg_status_for_conflict_counts_as_modified`, `test_pkg_status_for_nomod_when_installed`, `test_pkg_status_for_empty_when_unassigned_or_missing`, `test_pkg_status_for_only_considers_listed_vdoms`, `test_bulk_matches_per_device_legacy_on_synthetic_fleet` (SyntheticFMG with multi-VDOM devices: for every device, `pkg_status_for(bulk_rows, name, vdoms)` equals the legacy `get_device_pkg_status` result via a client whose `_post` is the synthetic), `test_get_adom_package_status_one_call_per_adom` (synthetic `calls` shows a single bulk URL).
- [ ] **Step 2: Run** `pytest tests/test_fmg_pkg_status_bulk.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the client method and the two pure functions; teach `SyntheticFMG` the bulk/per-device/per-vdom `_package/status` URLs (derive status deterministically from the seed; a fraction `modified`, some `conflict`, a few unassigned).
- [ ] **Step 4: Run** the new file plus `pytest tests/test_synthetic_fmg.py tests/test_fmg_replay_fixtures.py tests/test_pending_status_cache.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): bulk package status and shared device normalizers`.

### Task 2: Inventory store

**Files:** Create `app/inventory_store.py`; Test `tests/test_inventory_store.py`.

**Interfaces:**
- Consumes: `collector_store._connect()` (same DB file, WAL, `_retry_locked`).
- Produces: tables `inventory_adom(name PRIMARY KEY, json)`, `inventory_device(adom, name, json, PRIMARY KEY(adom,name))`, `inventory_pkg(adom, dev, vdom, pkg, status, PRIMARY KEY(adom,dev,vdom))`, `inventory_meta(adom PRIMARY KEY, collected_at, device_count, status, error)`, plus `inventory_request(id=1, requested_at)`. Functions: `replace_adom(adom, devices: list[dict], pkg_rows: list[dict] | None, collected_at: str) -> None` (single transaction; `pkg_rows=None` keeps existing pkg rows), `mark_adom_error(adom, error: str) -> None` (keeps data, sets status `error`), `write_adom_list(adoms: list[dict]) -> None` and `delete_missing_adoms(keep: set[str]) -> None`, `read_adom_list() -> list[dict] | None`, `read_devices(adom) -> list[dict] | None`, `read_pkg_status(adom) -> list[dict]`, `read_meta(adom=None) -> dict | list[dict]` (`{adom, collected_at, age_seconds, status, error, device_count}`), `request_refresh(min_interval_s: float) -> bool`, `pop_refresh_request() -> bool`.

- [ ] **Step 1: Write failing tests:** round trip of devices and pkg rows; `test_replace_is_atomic_for_readers` (reader thread loops while a writer replaces 500 devices with a different 500; every read returns a complete set from one generation), `test_crash_mid_replace_keeps_previous_rows` (simulate exception inside the transaction), `test_deleted_device_disappears_on_replace`, `test_delete_missing_adoms_removes_all_their_rows`, `test_mark_adom_error_keeps_rows_and_sets_status`, `test_read_returns_none_when_never_collected`, `test_age_seconds_computed`, `test_request_refresh_throttles_and_pop_clears`, `test_unreadable_store_raises_store_error_not_empty` (readers must distinguish "no data" from "store broken": raise `InventoryStoreError`).
- [ ] **Step 2: Run** `pytest tests/test_inventory_store.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with `INSERT ... ON CONFLICT`, `DELETE`/`INSERT` inside one `BEGIN IMMEDIATE`; indexes on `adom`.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): inventory store tables`.

### Task 3: Collector refresh job

**Files:** Create `app/inventory_cache.py`; Modify `app/config.py`, `app/__init__.py`, `.env.example`; Test `tests/test_inventory_cache.py`.

**Interfaces:**
- Consumes: Task 1 client method, Task 2 store.
- Produces: `Config.INVENTORY_REFRESH_SECS: int` (300), `INVENTORY_MAX_AGE_SECS: int` (0/unset -> 3 x refresh), `INVENTORY_PARALLEL_ADOMS: int` (4); `inventory_cache.refresh_once(client=None) -> dict` returning `{"adoms": n, "devices": n, "failed": [adom,...], "seconds": float, "fmg_calls": n}`; `inventory_cache.init_scheduler(app) -> None` (APScheduler interval job `inventory_refresh`, `max_instances=1`, plus a 10 s job `inventory_refresh_request_poll` that runs `refresh_once` when `pop_refresh_request()` is true); called first in `start_all_schedulers` only when `Config.INVENTORY_CACHE`.

- [ ] **Step 1: Write failing tests** using `SyntheticFMG(adoms=5, devices=200)` as `client._post`:
  `test_refresh_once_makes_one_adom_list_call_and_two_calls_per_adom` (1 + 5x2 = 11 calls), `test_non_forti_adoms_only_in_device_fetch_but_adom_list_stored_whole` (store keeps the raw ADOM list; devices fetched only for non-`forti*`), `test_failed_adom_keeps_previous_rows_and_marks_error_others_updated`, `test_adom_removed_in_fmg_is_deleted`, `test_parallel_fetch_respects_parallel_cap` (peak concurrent <= `INVENTORY_PARALLEL_ADOMS`), `test_refresh_is_single_flight` (second concurrent call returns `{"skipped": True}`), `test_scheduler_not_registered_when_flag_off`, `test_request_poll_triggers_refresh_once`, `test_bulk_pkg_status_failure_keeps_old_pkg_rows` (devices still refreshed), `test_refresh_records_metrics_role_collector`.
- [ ] **Step 2: Run** `pytest tests/test_inventory_cache.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `refresh_once` with a `ThreadPoolExecutor(INVENTORY_PARALLEL_ADOMS)` over ADOMs (each task: `get_devices(adom)` + `get_adom_package_status(adom)` -> `replace_adom`), then `write_adom_list` + `delete_missing_adoms`; run first refresh via Task 8's warm-up when available, else immediately.
- [ ] **Step 4: Run** the file. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): collector inventory refresh job`.

### Task 4: Inventory facade

**Files:** Create `app/inventory.py`; Test `tests/test_inventory_facade.py`.

**Interfaces:**
- Consumes: Task 2 store, Task 1 `normalize_sync_status`/`pkg_status_for`, `Config.INVENTORY_CACHE`/`INVENTORY_MAX_AGE_SECS`.
- Produces (client = an `FMGClient`, used only for the live fallback): `adoms(client) -> list[dict]`, `devices(client, adom) -> list[dict]`, `devices_with_sync_status(client, adom) -> list[dict]`, `pkg_status(client, adom, device, vdom_names) -> str`, `freshness() -> list[dict]` (per ADOM `{adom, collected_at, age_seconds, status, device_count, stale: bool}`), `counters() -> {"hits": n, "fallbacks": n, "store_errors": n}`, `reset_counters()`. Flag off -> straight client call, no store access, no counters. Flag on: serve when `age_seconds <= INVENTORY_MAX_AGE_SECS` and status `ok` or (`error` within max age), else live call (fallback counted); `InventoryStoreError` -> live call + `store_errors`.

- [ ] **Step 1: Write failing tests:** `test_flag_off_calls_client_and_never_touches_store`, `test_flag_on_fresh_serves_from_store_zero_fmg_calls`, `test_stale_adom_falls_back_live_and_counts`, `test_never_collected_falls_back_live`, `test_error_status_within_max_age_still_served`, `test_store_error_falls_back_live`, `test_devices_returns_copies` (mutating the result does not change the next read), `test_sync_status_equals_legacy_output_from_same_raw_devices`, `test_pkg_status_equals_legacy_for_multi_vdom`, `test_unknown_adom_in_store_but_listed_returns_empty_list_not_fallback_when_fresh` (a fresh, successfully collected ADOM with zero devices is a valid empty answer), `test_freshness_marks_stale`.
- [ ] **Step 2: Run** `pytest tests/test_inventory_facade.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the facade.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): inventory facade with fail-open fallback`.

### Task 5: Migrate background caches (summary, versions, map, ADOM list)

**Files:** Modify `app/summary_job.py` (`get_adoms`/`get_devices` at ~98/112), `app/versions_cache.py` (~81/93), `app/map_cache.py` (~79/96), `app/adom_cache.py` (~73); Test `tests/test_inventory_consumers.py`.

**Interfaces:** Consumes Task 4 facade. Each call site changes to `inventory.adoms(client)` / `inventory.devices(client, adom)`; nothing else in those modules changes.

- [ ] **Step 1: Write failing tests:** for each module, with the flag on and a populated store, run its refresh with a client whose `_post` raises on any call: result equals the flag-off result computed from the same synthetic fleet (`test_<module>_same_output_from_store_with_zero_fmg_calls`); with the flag off, the client is called as before (`test_<module>_flag_off_unchanged`).
- [ ] **Step 2: Run** `pytest tests/test_inventory_consumers.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the four call-site swaps.
- [ ] **Step 4: Run** `pytest tests/test_inventory_consumers.py tests/test_summary_job*.py tests/test_versions*.py tests/test_map*.py tests/test_adom_cache*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): background caches read inventory store`.

### Task 6: Migrate sweeps that dominate the baseline (pending status, executive summary, backup, license)

**Files:** Modify `app/pending_status_cache.py` (~102-170), `app/executive_summary_cache.py` (~414-463), `app/device_backup_cache.py` (~99/153), `app/license_status_cache.py` (~199/254); Test `tests/test_inventory_consumers.py`.

**Interfaces:** Consumes Task 4 (`devices_with_sync_status`, `devices`, `adoms`, `pkg_status`). In `pending_status_cache`, the per-device `get_device_pkg_status` thread pool is replaced (flag on) by `inventory.pkg_status(...)` per device (pure lookups); flag off keeps the pool. License sweep keeps its per-device proxy calls (only its device list comes from the store). Backup keeps its one revision call per ADOM.

- [ ] **Step 1: Write failing tests:** `test_pending_status_flag_on_makes_zero_fmg_calls_and_same_cache_content` (compare `_cache` to flag-off result on the same synthetic fleet incl. multi-VDOM and conflict devices), `test_pending_status_flag_off_still_uses_per_device_calls`, `test_exec_summary_device_sweep_from_store_same_numbers`, `test_backup_cache_device_list_from_store_revision_calls_unchanged`, `test_license_sweep_device_list_from_store_proxy_calls_unchanged`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** the swaps.
- [ ] **Step 4: Run** `pytest tests/test_inventory_consumers.py tests/test_pending_status_cache.py tests/test_executive_summary*.py tests/test_device_backup*.py tests/test_license_status*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): pending-status, exec summary, backup and license sweeps read inventory store`.

### Task 7: Migrate request-path lists

**Files:** Modify `app/routes/api_routes.py` (`/api/adoms` ~495, devices ~531), `app/routes/rule_review_routes.py` (~61, 99, 112), `app/routes/audit_review_routes.py` (~79, 272, 336), `app/nat_report_scheduler.py` (~370); Test `tests/test_inventory_consumers.py`.

**Interfaces:** Consumes Task 4 facade. `check_adom_access` and forti-prefix filtering stay in the routes, applied to the facade's result. Firewalls **detail** (live proxy calls) is not touched.

- [ ] **Step 1: Write failing tests:** per route, flag on + populated store + client that raises on any call: 200 and same JSON as flag off; `test_restricted_user_still_gets_403_for_other_adom_with_cache_on`; `test_adom_list_still_filters_forti_and_inaccessible_adoms_with_cache_on`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** the swaps.
- [ ] **Step 4: Run** `pytest tests/test_inventory_consumers.py tests/test_api_routes*.py tests/test_rule_review*.py tests/test_audit_review*.py tests/test_nat_report*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): request-path ADOM/device lists read inventory store`.

### Task 8: Ordered, jittered boot warm-up (F7)

**Files:** Create `app/boot_warmup.py`; Modify `app/__init__.py`, and the startup refresh sites of `summary_job`, `versions_cache`, `map_cache`, `pending_status_cache`, `executive_summary_cache`, `device_backup_cache`, `license_status_cache`, `adom_cache`; Test `tests/test_boot_warmup.py`.

**Interfaces:**
- Produces: `boot_warmup.defer(name: str, fn: Callable[[], None], priority: int) -> None`: with `Config.INVENTORY_CACHE` on, queues `fn`; a single worker runs priority 0 immediately, then each higher priority `priority x 15 s` later plus `uniform(0, 10 s)` jitter, but never before the inventory's first refresh has finished or 120 s has passed; flag off -> runs `fn` immediately in the caller's thread exactly as today. Priorities: inventory 0, adom/summary/versions/map 1, pending status/exec summary 2, backup/license/others 3. `boot_warmup.reset()` for tests; time seam `boot_warmup.sleep`.

- [ ] **Step 1: Write failing tests:** `test_flag_off_runs_immediately_in_caller`, `test_priority_order_and_stagger` (fake clock/sleep seam: order and minimum gaps), `test_waits_for_inventory_first_refresh_or_timeout`, `test_exception_in_one_job_does_not_stop_the_rest`, `test_web_boot_makes_zero_fmg_calls` (`create_app()` in web mode with a transport that raises on any call, import completes, `/` renders last snapshots), `test_collector_boot_first_fmg_call_is_adom_list` (collector mode against synthetic: the first recorded call is `get /dvmdb/adom`).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** `boot_warmup` and swap each startup refresh to `boot_warmup.defer(...)`.
- [ ] **Step 4: Run** `pytest tests/test_boot_warmup.py -q` plus the full suite subset for those modules. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): ordered jittered boot warm-up`.

### Task 9: Freshness status API and badge (F8, first views)

**Files:** Modify `app/routes/api_routes.py`; Create `app/static/js/freshness.js`; Modify the shared base template and the Dashboard, Firewalls, Versions and Map page templates/CSS; Test `tests/test_inventory_status_api.py`.

**Interfaces:**
- Produces: `GET /api/inventory/status` (login required; ADOM list filtered by the user's ADOM access) -> `{enabled: bool, refresh_seconds: int, max_age_seconds: int, adoms: [{adom, collected_at, age_seconds, status, device_count, stale}]}`; `POST /api/inventory/refresh` (admin only, CSRF-protected) -> 202 `{requested: true}` or 429 `{error, retry_after}` when requested within 60 s; `freshness.js` renders a badge "Data as of HH:MM (N min ago)" with classes `fresh` / `stale` / `degraded`, polling the status endpoint every 60 s, plus a Refresh button for admins; shown on the four pages. Badge is hidden when `enabled` is false.

- [ ] **Step 1: Write failing tests:** `test_status_requires_login`, `test_status_disabled_when_flag_off`, `test_status_filters_adoms_for_restricted_user`, `test_status_marks_stale_and_error`, `test_refresh_admin_only`, `test_refresh_throttled_429_with_retry_after`, `test_refresh_sets_request_row_for_collector`, `test_pages_include_freshness_script` (the four pages render the script tag only when enabled).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** endpoints, JS and template wiring.
- [ ] **Step 4: Run** `pytest tests/test_inventory_status_api.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): inventory freshness API and badge`.

### Task 10: Measure, document, full verification

**Files:** Modify `scripts/measure_fmg_baseline.py`, `docs/deployment.md`, `CLAUDE.md`, `.env.example`, `docs/superpowers/measurements/README.md`; Create `docs/superpowers/measurements/2026-11-phase2-results.md`; Test `tests/test_measure_baseline.py`.

**Interfaces:** `measure_fmg_baseline.py --inventory-cache` (flag on in-process, runs `inventory_cache.refresh_once` first at its real interval, then each sweep once; reports calls/hour per source including `inventory_cache`); the report shows before/after.

- [ ] **Step 1: Write failing test:** `test_measure_with_inventory_cache_reports_inventory_source_and_lower_total` (small fleet: total calls/hour with the flag < flag off; `inventory_cache` present; pending status calls == 0).
- [ ] **Step 2: Run** `pytest tests/test_measure_baseline.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** the option; run `PYTHONPATH=. uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache --out docs/superpowers/measurements/2026-11-phase2-1000.json`. Expected: total <= 700 calls/hour; record the per-source table and the remaining largest sources (exec hygiene ~446/h goes to Phases 3-4) in `2026-11-phase2-results.md`.
- [ ] **Step 4: Docs:** `INVENTORY_REFRESH_SECS`, `INVENTORY_MAX_AGE_SECS`, `INVENTORY_PARALLEL_ADOMS`, the rollback switch (`INVENTORY_CACHE=off` + restart), the new endpoints, the boot order; a "how to check the store is fresh" snippet; `CLAUDE.md` "Scale foundations" paragraph describing the facade seam ("new code that needs devices/ADOMs calls `app.inventory`, not the client").
- [ ] **Step 5: Run the full suite** (bare `pytest`) and `uv run ruff check <changed files> && uv run ruff format --check <changed files>`. Expected: all pass.
- [ ] **Step 6: Commit** `feat(scale): Phase 2 measurements and docs`.

## Self-review notes

- Spec coverage: F2 (T1-T7), F7 (T8), F8 first views (T9), acceptance target 1 partially (<= 700/h; the 10x needs Phases 3-4, exec hygiene 446/h), target 2 (cached pages make no FMG calls: T5-T7 tests), target 5 (boot serves snapshot, inventory <= 10 min old via 5 min refresh + max-age ceiling).
- Builder's calls, challengeable: store full device records (no `fields` trimming; the lab showed `fields` keeps `vdom` at ~5% size, easy to add later); 5-minute refresh; 4 parallel ADOMs; fail open to a live call rather than serve data older than 15 minutes; PSIRT, planner and self-test stay live.
- Deliberately not here: package/policy store (Phase 4), Config-Delta gating (Phase 3), per-device audit snapshots (Phase 5), job queue (Phase 6).
