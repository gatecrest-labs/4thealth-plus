# Scale Phase 3: Config-Delta Preview Gating (F5) and Hygiene Once-Per-Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (1) Scheduled Config-Delta runs preview only devices whose cached sync status shows pending changes (fail-open when unknown), with a periodic forced full sweep and a job time budget. (2) The executive hygiene sweep runs its checks once per package and refetches a package's policies only when its cached result has aged past a jittered TTL, cutting its FMG load from ~445 calls/hour to ~90 so the 1,000-device background total drops from 635.8 to <= ~390 calls/hour (the 10x target).

**Architecture:** F5 adds a small decision module (`app/config_delta_gate.py`) used only by `bulk_preview_adom`; the single-device preview a person triggers by clicking stays live and ungated. The hygiene part adds a per-package result cache table in the shared store (the first slice of the Phase 4 policy store, behind the `POLICY_STORE` flag) holding fingerprint, findings and referenced-object name sets; the sweep reuses entries younger than TTL and refetches the rest, so load spreads across sweeps instead of arriving as one 445-call burst.

**Tech Stack:** Python 3.14, SQLite (shared store), APScheduler, Flask, pytest, ruff (strict), uv.

**Spec:** `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` (section 4 F3/F5, 5 Phase 3, 6, 7a "Freshness defaults"). Measurements: `docs/superpowers/measurements/2026-11-phase2-results.md` (hygiene sweep is 445 of the remaining 636 calls/hour).

## Global Constraints

- Branch `develop`; never push. Sonnet or cheaper only. Read-only toward Fortinet: install preview stages and cancels a package lock on FMG as today; nothing new writes to devices.
- Gating is active only when `Config.INVENTORY_CACHE` is on and `CONFIG_DELTA_GATING` is not `off` (default `on`). The package cache is active only when `Config.POLICY_STORE` is on. Flags off = legacy behaviour exactly.
- Fail open everywhere: a device with unknown, empty, missing or stale status is previewed. "Stale" = cached status older than 2 x `INVENTORY_REFRESH_SECS` (spec 7a).
- Forced full sweep: every `CONFIG_DELTA_FULL_SWEEP_HOURS` (default 24) per ADOM, every device is previewed regardless of status. `conf_status` can lag real state (CLAUDE.md), so gating is a load saver with a bounded blind window, never the only signal.
- Job time budget `CONFIG_DELTA_JOB_BUDGET_SECS` (default 3600, `0` = none): devices not reached are reported as `status: "error"` (never as clean), so Package Change Alerts treat the package as unverified and leave state untouched.
- Skipped (gated) devices still appear in results (`status: "no_changes"`, `gated: true`, `cached_as_of`); nothing is silently dropped.
- Hygiene: `POLICY_STORE` TTL default 6 h (`HYGIENE_PACKAGE_TTL_HOURS`), per-package jitter x0.75..x1.25 derived from a stable hash of `adom/package` (spreads refetches); a failed refetch reuses the cached entry if it is younger than 2 x TTL, else the package is skipped with a warning (as today). Results (score, totals, details) must equal the legacy sweep's when the cache is cold.
- Per-package cached data is bounded: findings list + two sorted name lists; never the raw policy list.
- Ruff strict, `uv`, TDD, suite green (1,947 at start; run bare `pytest`). FMG metrics, Phase 1 access layer and Phase 2 inventory facade stay the only FMG paths.

## Review Focus

- Gate never skips a device whose status is unknown, empty, stale, or pending in any of conf/db/pkg; skipped devices are listed in results; the time budget leaves unvisited devices as errors; a forced full sweep really previews everything and is recorded per ADOM.
- Package Change Alerts: gated "no_changes" results do not clear dedupe state or send alerts incorrectly; budget errors keep state untouched.
- The scheduler's run record and digest email show how many devices were gated and the inventory age they relied on.
- Hygiene once-per-package equals running `run_checks` twice (same counts, same exempt handling).
- Cached-package reuse: counts/score/details equal the cold-cache result; mixing reused and refetched packages keeps totals consistent; deleted packages disappear within one sweep; ADOM unused-object detection from cached reference sets equals `find_unused_objects` over full policies.
- Flag off: no table reads/writes, same FMG calls as before.
- Concurrency: web workers never write the package cache; two overlapping sweeps are prevented by the existing overlap guard; a crash mid-sweep leaves valid rows.

## File Structure

- Create `app/config_delta_gate.py`: `decide_device(...)`, `select_devices(adom, devices) -> GateResult`, full-sweep bookkeeping.
- Modify `app/routes/pending_changes_routes.py` (`bulk_preview_adom`; ADOM list and cold device-list fallback to the inventory facade), `app/config_diff_scheduler.py` (run record fields), `app/inventory_store.py` (`config_delta_last_full` state helpers), `app/config.py`, `.env.example`.
- Modify `app/hygiene.py` (`find_unused_objects_from_refs`, shared `collect_policy_refs`), `app/executive_summary_cache.py` (`_run_hygiene_sweep`).
- Create `app/hygiene_pkg_store.py`: table + `get`, `put`, `touch`, `delete_missing`, `fingerprint`, `effective_ttl_seconds`.
- Modify `scripts/measure_fmg_baseline.py` (`--policy-store`), docs (`docs/deployment.md`, `CLAUDE.md`), write `docs/superpowers/measurements/2026-11-phase3-results.md`.
- Tests: `tests/test_config_delta_gate.py`, `tests/test_bulk_preview_gating.py`, `tests/test_hygiene_once_per_package.py`, `tests/test_hygiene_pkg_store.py`, `tests/test_hygiene_sweep_cache.py`.

---

### Task 1: Gate decision module

**Files:** Create `app/config_delta_gate.py`; modify `app/config.py`, `app/inventory_store.py`, `.env.example`; Test `tests/test_config_delta_gate.py`.

**Interfaces:**
- Consumes: Phase 2 `inventory.devices_with_sync_status(client, adom)`, `inventory.pkg_status_lookup(client, adom)`, `inventory_store.read_meta(adom)`.
- Produces: `Config.CONFIG_DELTA_GATING: bool` (env `CONFIG_DELTA_GATING`, default on), `CONFIG_DELTA_FULL_SWEEP_HOURS: int` (24), `CONFIG_DELTA_JOB_BUDGET_SECS: int` (3600); `inventory_store.last_full_sweep_age_seconds(adom) -> float | None` and `inventory_store.mark_full_sweep(adom) -> None`; `config_delta_gate.gating_enabled() -> bool`; `config_delta_gate.decide_device(conf_status: str, db_status: str, pkg_status: str, status_age_s: float | None, max_age_s: float) -> tuple[bool, str]` returning `(preview, reason)` where reason is one of `pending`, `unknown`, `stale`, `in_sync`; `GateResult` dataclass `{preview: list[dict], gated: list[dict], full_sweep: bool, status_age_s: float | None}`; `select_devices(client, adom, devices: list[dict]) -> GateResult` where each input dict has `name` and `ip`.

- [ ] **Step 1: Write failing tests:** `test_pending_in_any_signal_previews` (conf outofsync / db modified / pkg modified each alone -> preview, reason pending), `test_in_sync_everything_is_skipped` (insync + nomod + nomod, fresh), `test_unknown_or_empty_or_missing_signals_preview` (parametrize `unknown`, `""`, None for each field; pkg `""` with others in sync -> preview/unknown), `test_stale_status_previews` (age 2x+1 s), `test_age_none_previews`, `test_gating_disabled_when_inventory_cache_off`, `test_gating_disabled_by_env_off`, `test_select_devices_splits_and_records_status_age` (populated store from synthetic fleet; some devices modified), `test_full_sweep_due_previews_everything_and_marks` (no prior mark -> full; second call within 24 h gates again; after mark ages past 24 h -> full), `test_store_unreadable_previews_everything` (fail open).
- [ ] **Step 2: Run** `pytest tests/test_config_delta_gate.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the config fields, the two store helpers (state key `config_delta_full:<adom>` in `inventory_state`, remove with the ADOM in `delete_missing_adoms`), and the module.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): Config-Delta gate decision module`.

### Task 2: Gate `bulk_preview_adom`, time budget, digest fields, Config-Delta lists on the facade

**Files:** Modify `app/routes/pending_changes_routes.py`, `app/config_diff_scheduler.py`; Test `tests/test_bulk_preview_gating.py`.

**Interfaces:**
- Consumes: Task 1 `select_devices`.
- Produces: `bulk_preview_adom(adom, max_workers=10, budget_seconds: float | None = None) -> list[dict]` (default budget from config); each gated device yields `{"device","ip","status":"no_changes","pkg_status","summary":{},"vdoms":[],"raw":"","error":None,"gated":True,"cached_as_of": iso}`; devices not reached before the budget yield `status "error"`, `error "time budget exhausted before this device was previewed"`; the module attribute `bulk_preview_adom.last_stats` is NOT used; instead results carry the fields above and `config_diff_scheduler` records `devices_total`, `devices_previewed`, `devices_gated`, `devices_budget_skipped`, `full_sweep` in the run record; `pending_changes_adoms` and the cold-cache branch of `pending_changes_devices` use `inventory.adoms` / `inventory.devices_with_sync_status` / `inventory.pkg_status_lookup`. The single-device preview endpoint is unchanged and ungated.

- [ ] **Step 1: Write failing tests** (synthetic fleet; `FMGClient.get_install_preview` replaced by a counting stub): `test_flag_off_previews_every_device` (legacy), `test_gating_on_previews_only_pending_devices` (preview count == pending count), `test_gated_devices_appear_in_results_with_marker`, `test_unknown_status_device_is_previewed`, `test_full_sweep_previews_all_devices_once_then_gates`, `test_budget_exhaustion_marks_remaining_devices_as_errors_not_clean` (budget 0.01 s with a slow stub), `test_package_change_alerts_unaffected_by_gated_results` (call `evaluate_alerts` with a mix of gated/no_changes and error results: no state cleared for a package with an errored device), `test_scheduler_run_record_has_gate_counts`, `test_single_device_preview_endpoint_stays_live_and_ungated`, `test_adom_list_and_cold_device_list_from_store_with_zero_inventory_calls`.
- [ ] **Step 2: Run** `pytest tests/test_bulk_preview_gating.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** In `bulk_preview_adom`, build the device list as today, call `select_devices` when `gating_enabled()`, run `_preview_one` over `GateResult.preview` only, append gated entries; enforce the budget with a monotonic deadline checked before each submit (sequential scheduler path) and by cancelling pending futures in the pool path.
- [ ] **Step 4: Run** the new file plus `pytest tests/test_pending_changes*.py tests/test_config_diff*.py tests/test_package_change_alerts*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): gate scheduled Config-Delta previews on cached sync status`.

### Task 3: Hygiene checks once per package

**Files:** Modify `app/hygiene.py`, `app/executive_summary_cache.py`; Test `tests/test_hygiene_once_per_package.py`.

**Interfaces:**
- Produces: `hygiene.collect_policy_refs(policies) -> tuple[set[str], set[str]]` (public name for the existing `_collect_policy_refs`; keep the underscore alias), `hygiene.find_unused_objects_from_refs(addr_refs, svc_refs, addresses, addr_groups, services, svc_groups) -> dict` (same return shape as `find_unused_objects`, which now calls it).

- [ ] **Step 1: Write failing tests:** `test_subset_of_full_run_equals_separate_subset_run` (random policy fixtures incl. exempt comments, disabled, expired, unnamed, unlogged, unhit: `[f for f in run_checks(p, ALL) if f["check"] in SUBSET]` equals `run_checks(p, SUBSET)` element-for-element and in order), `test_find_unused_objects_from_refs_equals_full_version`, `test_sweep_calls_run_checks_once_per_package` (spy: one call per package), `test_sweep_totals_identical_to_legacy_on_synthetic_fleet` (compare store fields `hygiene_score`, `rule_count_total`, `rule_hygiene.rule_findings_by_type` between the old double-run implementation captured as a fixture value and the new one).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** In `_run_hygiene_sweep`, one `run_checks(policies, list(HYGIENE_CHECK_TYPES))` per package; `total_findings += sum(1 for f in all_findings if f["check"] in _HYGIENE_CHECKS)`; accumulate `addr_refs`/`svc_refs` per ADOM from `collect_policy_refs` instead of holding every policy list, then call `find_unused_objects_from_refs`.
- [ ] **Step 4: Run** the file plus `pytest tests/test_executive_summary_cache.py tests/test_hygiene*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `refactor(scale): hygiene sweep runs checks once per package and keeps reference sets, not policy lists`.

### Task 4: Per-package hygiene result store

**Files:** Create `app/hygiene_pkg_store.py`; modify `app/config.py`, `.env.example`; Test `tests/test_hygiene_pkg_store.py`.

**Interfaces:**
- Produces: `Config.HYGIENE_PACKAGE_TTL_HOURS: int` (6); table `hygiene_pkg(adom, pkg, fetched_at, fingerprint, policy_count, score_findings, findings_json, addr_refs_json, svc_refs_json, PRIMARY KEY(adom,pkg))`; `fingerprint(policies: list[dict]) -> str` (sha256 of canonical JSON, key-order independent); `effective_ttl_seconds(adom, pkg) -> float` (TTL x deterministic 0.75..1.25 factor from `zlib.crc32(f"{adom}/{pkg}")`); `get(adom, pkg) -> dict | None` (`{fetched_at, age_seconds, fingerprint, policy_count, score_findings, findings, addr_refs, svc_refs}`); `put(adom, pkg, *, fingerprint, policy_count, score_findings, findings, addr_refs, svc_refs) -> None`; `touch(adom, pkg) -> None` (refresh `fetched_at` when the fingerprint is unchanged); `delete_missing(adom, keep: set[str]) -> int`; errors raise `HygienePkgStoreError`; uses the same connection/lock convention as `inventory_store` (writers locked, readers not, schema once per file).

- [ ] **Step 1: Write failing tests:** round trip incl. findings and ref sets, `test_fingerprint_is_key_order_independent_and_change_sensitive`, `test_effective_ttl_is_stable_and_within_bounds` (1,000 package names: all within [0.75, 1.25] x TTL, same value on repeat, spread across the range), `test_touch_resets_age_keeps_content`, `test_delete_missing_removes_only_unlisted`, `test_get_none_when_absent`, `test_unreadable_store_raises_store_error`, `test_reads_do_not_wait_for_write_lock`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** the module.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): per-package hygiene result store`.

### Task 5: Hygiene sweep reuses cached packages

**Files:** Modify `app/executive_summary_cache.py`; Test `tests/test_hygiene_sweep_cache.py`.

**Interfaces:**
- Consumes: Tasks 3-4.
- Produces: with `Config.POLICY_STORE` on, `_run_hygiene_sweep` per package: cached entry with `age_seconds < effective_ttl_seconds` -> reuse (no `get_policies` call); else fetch, compute, `put` (or `touch` when the fingerprint is unchanged and recompute is skipped); a failed fetch reuses a cached entry younger than 2 x TTL, else skips the package with a warning; after listing an ADOM's packages call `delete_missing`; totals, `by_type`, `package_findings` and unused-object detection are built from fresh or cached entries identically.

- [ ] **Step 1: Write failing tests** (synthetic fleet, flag on): `test_cold_cache_results_equal_flag_off_results`, `test_second_sweep_makes_no_policy_fetches_inside_ttl` (synthetic `calls` shows zero `get .../firewall/policy` on the second run), `test_expired_entries_are_refetched_and_unchanged_fingerprint_is_touched_only`, `test_changed_policy_is_detected_by_fingerprint_and_findings_update`, `test_deleted_package_disappears_within_one_sweep`, `test_failed_refetch_reuses_entry_under_2x_ttl_else_skips`, `test_mixed_fresh_and_cached_totals_equal_full_refetch_totals`, `test_unused_objects_from_cached_refs_equal_full_detection`, `test_flag_off_never_touches_the_package_table`, `test_refetch_load_is_spread` (60 packages with jittered ages: one sweep at t = TTL x 0.8 refetches only some).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file plus `pytest tests/test_executive_summary_cache.py tests/test_hygiene*.py tests/test_inventory_consumers.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): hygiene sweep reuses cached per-package results (POLICY_STORE)`.

### Task 6: Measure, document, full verification

**Files:** Modify `scripts/measure_fmg_baseline.py`, `docs/deployment.md`, `CLAUDE.md`, `.env.example`, `docs/superpowers/measurements/README.md`; Create `docs/superpowers/measurements/2026-11-phase3-results.md`, `2026-11-phase3-1000.json`; Test `tests/test_measure_baseline.py`.

**Interfaces:** `measure(..., policy_store: bool = False)` turns on `POLICY_STORE`, runs the hygiene sweep cold then warm, and reports the source's steady state as `warm_calls x (60 / interval_min) + (cold_calls - warm_calls) / TTL_hours`; CLI `--policy-store`; `--inventory-cache --policy-store` together give the Phase 3 total.

- [ ] **Step 1: Write failing test:** `test_policy_store_run_lowers_hygiene_steady_state` (small fleet: steady-state calls/hour for `exec_hygiene_sweep` < the flag-off figure; total < Phase 2 total).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** the option; run `PYTHONPATH=. uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache --policy-store --out docs/superpowers/measurements/2026-11-phase3-1000.json`. Expected: total <= ~390 calls/hour; record per-source table and the remaining sources in `2026-11-phase3-results.md`, plus a Config-Delta note (previews per scheduled run with N% of devices pending: measured by a small synthetic run in the same write-up).
- [ ] **Step 4: Docs:** `CONFIG_DELTA_GATING`, `CONFIG_DELTA_FULL_SWEEP_HOURS`, `CONFIG_DELTA_JOB_BUDGET_SECS`, `POLICY_STORE`, `HYGIENE_PACKAGE_TTL_HOURS` in the deployment scale table; the gating blind window (<= 24 h plus inventory age) stated plainly; rollback (`POLICY_STORE`/`CONFIG_DELTA_GATING` off + restart); `CLAUDE.md` "Scale foundations" paragraph; note that the optional package change marker (`obj ver` on `/pm/pkg/adom/<adom>` entries) is unverified and an owner lab spike (edit a rule, compare `obj ver`) could later let the TTL stretch.
- [ ] **Step 5: Run the full suite** (bare `pytest`) and `uv run ruff check` + `ruff format --check` on changed files. Expected: all pass.
- [ ] **Step 6: Commit** `feat(scale): Phase 3 measurements and docs`.

## Self-review notes

- Spec coverage: F5 (T1-T2, incl. concurrency already 1/ADOM from the existing lock and the scheduler's `max_workers=1`, unknown fails open, job time budget, 2x-interval staleness rule), "hygiene runs once per package and only for changed packages" (T3-T5; "changed" = fingerprint on TTL refetch, since no verified cheap marker exists), acceptance target 1 (T6), target 3 (no overlapping previews: unchanged lock plus fewer previews).
- Builder's calls, challengeable: hygiene staleness up to 6 h x 1.25 (spec 7a policy-store default); full-sweep every 24 h; budget 3600 s; Config-Delta single-device click stays live; `POLICY_STORE` is used as the flag for this first slice so Phase 4 extends the same layer.
- Deliberately not here: policy lists in the store, Rule Lookup/Rule Review reads (Phase 4); device audit snapshots (Phase 5); job queue (Phase 6).
