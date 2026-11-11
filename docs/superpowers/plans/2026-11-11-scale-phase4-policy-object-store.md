# Scale Phase 4: Policy and Object Store (F3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The collector keeps every ADOM's policy packages, package policies, policy blocks and firewall objects in the shared store; Rule Review, Rule Lookup, Object/NAT lookups, Hygiene, the unused-object finder, the executive hygiene sweep, the summary rule counts and the scheduled hygiene/policy/NAT reports read them from the store instead of calling FortiManager. Interactive and scheduled readers then make zero FMG calls (except explicit refresh and the paths that must stay live), and Rule Lookup no longer builds a per-process cache from FMG.

**Architecture:** `app/policy_store.py` (tables, zlib-compressed JSON blobs, one row per package / policy block / object kind) is written only by the collector job `app/policy_cache.py` (TTL + fingerprint per package, one fetch of the shared global objects, strict fetchers so a swallowed FMG error is never stored as "empty"). A facade `app/policies.py` mirrors the Phase 2 inventory facade (flag `POLICY_STORE`, fail-open live fallback, copies, counters). Consumers swap their FMG calls for the facade one group at a time. Freshness (`data_as_of` per package) and a per-package "Refresh" (a request row the collector polls) cover the "I just edited a rule" case.

**Tech Stack:** Python 3.14, SQLite (shared store, WAL), zlib, APScheduler, Flask, vanilla JS, pytest, ruff (strict), uv.

**Spec:** `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` (section 4 F3, 5 Phase 4, 6, 7a). Builds on Phase 2 (`app/inventory*.py`) and Phase 3 (`app/hygiene_pkg_store.py`, `POLICY_STORE` flag already used by the hygiene sweep).

## Global Constraints

- Branch `develop`; never push. Sonnet or cheaper only. Read-only toward Fortinet.
- Flag `POLICY_STORE` (existing, default off). Off = byte-for-byte legacy FMG calls at every seam, no store reads/writes, no new scheduler jobs. `POLICY_STORE` on does not require `INVENTORY_CACHE`, but Rule Lookup package/device scope uses package entries, not inventory.
- The collector is the only writer. Web workers never write policy/object rows (only a tiny `policy_refresh_request` row for the Refresh button).
- Strict fetching: the refresh uses `strict=True` variants that raise on any FMG error or unexpected shape. A failed fetch keeps the previous rows and records an error; an empty package list or object list from a failed call must never replace good data. (Today `get_policy_packages`, `get_address_objects`, `get_address_groups`, `get_service_objects`, `get_service_groups`, `get_vip_objects`, `get_ippool_objects`, `get_pkg_settings`, `get_pkg_scope_members` swallow errors and return `[]`/`{}`.)
- Cache stores per-ADOM/per-package data, never per-user results; `check_adom_access` and ADOM list filters stay in the routes, applied to facade results.
- Request-path reads load only the rows they need (one package blob, one object kind), never the whole fleet; blobs are zlib-compressed JSON.
- Freshness: package TTL default 6 h jittered x0.75..x1.25 (`POLICY_PACKAGE_TTL_HOURS`, falls back to `HYGIENE_PACKAGE_TTL_HOURS` if set); objects refreshed every `POLICY_OBJECTS_REFRESH_MINUTES` (default 60); facade serves a row up to `POLICY_MAX_AGE_SECS` (default 0 = 2 x 1.25 x TTL = 15 h), older or missing -> one live call (counted).
- Stays live by design: Rule Validation planner (`app/planner/*`), `app/log_hygiene.py`, `app/fmg_selftest.py`, PSIRT, per-device proxy data (interfaces lookup, per-device VIP/IP pool sweep, hit-count overlay for the `unhit` check), and the policy report that Package Change Alerts attach (it must reflect the change that triggered the alert: `fresh=True`).
- Ruff strict, `uv`, TDD, suite green (2,016 at start; bare `pytest`).

## Review Focus

- A failed or partial FMG answer (error status, `[]` from a swallowed exception, wrong shape) never overwrites good store rows; the package list failing never deletes cached packages; a package that failed keeps its last rows and is flagged.
- Policy blocks (`_policy_block` entries) expand identically to today (same rule records as `rule_lookup_cache._fetch_package`), including a block that fails (reported in `package_errors`, not silence).
- Equivalence: every migrated reader returns the same JSON as the live path for the same fleet (policies, `srcaddr_exp` expansions, object lookups, where-used, NAT lookup, unused objects, hygiene run findings, Rule Lookup results incl. `skipped_count`, `package_errors`).
- Global objects are fetched once per cycle and merged with each ADOM's local objects exactly as `get_*_objects(adom, scope)` does for `local` / `global` / `all` (order and duplicates).
- Package Change Alerts' policy report and the hit-count overlay stay live; scheduled digests state their data age.
- Fail-open: missing/stale/unreadable rows go live for that read only; counters expose it; no request ever returns an empty answer because a row is absent.
- Size/CPU: DB size for 1,000 synthetic devices, parse time per package and per-ADOM Rule Lookup build, memory of two web workers each holding an ADOM index; writer holds the lock only for one package's write.
- Concurrency: refresh-request throttling, collector poll, overlapping refreshes (single flight), web readers while the collector writes a large package (atomic per-row replace).
- Access control: refresh endpoint and every new field respect tab and ADOM permissions; no policy content in logs.

## File Structure

- Modify `app/fmg_client.py`: `strict: bool = False` on the nine fetchers above (strict raises `FMGError` on failure/odd shape; default behaviour unchanged).
- Create `app/policy_store.py`: tables + API. Create `app/policy_cache.py`: collector refresh. Create `app/policies.py`: facade.
- Modify consumers: `app/routes/hygiene_routes.py`, `app/rule_lookup_cache.py`, `app/summary_job.py`, `app/executive_summary_cache.py`, `app/hygiene_pkg_store.py` (findings keyed by store fingerprint), `app/rule_hygiene_scheduler.py` / `bulk_hygiene_adom`, `app/rule_policy_scheduler.py`, `app/nat_report_scheduler.py`, `app/routes/rule_review_routes.py` where it reads packages/objects, `app/package_change_alerts.py` (pass `fresh=True`).
- API/UI: `app/routes/api_routes.py` (status + refresh endpoints), `app/static/js/` (extend `freshness.js` or a small `policy_freshness.js`), `hygiene.html`/`audit_review.html` header placeholders.
- `scripts/measure_fmg_baseline.py` (`--policy-store` includes the refresh job), `scripts/verify_policy_store_load.py` (size and concurrency check, runs on any machine), docs.
- Tests: `tests/test_fmg_client_strict.py`, `tests/test_policy_store.py`, `tests/test_policy_cache.py`, `tests/test_policies_facade.py`, `tests/test_policy_consumers_background.py`, `tests/test_rule_lookup_store.py`, `tests/test_policy_consumers_routes.py`, `tests/test_policy_consumers_schedulers.py`, `tests/test_policy_freshness_api.py`.

---

### Task 1: Strict FMG fetchers

**Files:** Modify `app/fmg_client.py`; Test `tests/test_fmg_client_strict.py`.

**Interfaces:** `get_policy_packages(adom, strict=False)`, `get_pkg_settings(adom, pkg_path, strict=False)`, `get_pkg_scope_members(adom, pkg_path, strict=False)`, `get_address_objects/get_address_groups/get_service_objects/get_service_groups(adom, scope="all", strict=False)`, `get_vip_objects(adom, scope="all", strict=False)`, `get_ippool_objects(adom, scope="all", strict=False)`; `scope` for VIP/IP pool is new (`local`/`global`/`all`, default `all` = today). With `strict=True` an FMG error status, exception or non-list/dict answer raises `FMGError`; default behaviour is unchanged (swallow, return empty). `get_policies` already raises.

- [ ] **Step 1: Write failing tests** with a scripted `_post`: `test_default_calls_still_swallow_errors` (each getter returns `[]`/`{}` on an error answer), `test_strict_raises_on_fmg_error_status` (parametrized over all nine), `test_strict_raises_on_wrong_shape`, `test_scope_local_and_global_fetch_only_their_urls` (call counts per URL for address/addrgrp/service/vip/ippool), `test_vip_and_ippool_scope_all_unchanged_order` (local then global, as before), `test_strict_success_returns_same_data_as_default`.
- [ ] **Step 2: Run** `pytest tests/test_fmg_client_strict.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with a small private helper `_get_paged_strict(url)` and shared URL tables; keep default paths byte-compatible.
- [ ] **Step 4: Run** the file plus `pytest tests/test_fmg_replay_fixtures.py tests/test_synthetic_fmg.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): strict policy and object fetchers`.

### Task 2: Policy store tables

**Files:** Create `app/policy_store.py`; modify `app/config.py`, `.env.example`; Test `tests/test_policy_store.py`.

**Interfaces:**
- Config: `POLICY_PACKAGE_TTL_HOURS` (default: `HYGIENE_PACKAGE_TTL_HOURS` env if set else 6), `POLICY_OBJECTS_REFRESH_MINUTES` (60), `POLICY_MAX_AGE_SECS` (0 = derive), `POLICY_PARALLEL_FETCH` (4), `POLICY_REFRESH_MIN_INTERVAL_SECS` (30).
- Tables (same DB, own `schema_id`, shared `_Conn` from `inventory_store`): `policy_adom_pkgs(adom, fetched_at, json)` (the ADOM's flat package entries incl. `package settings`, `scope member`, `obj ver`, `oid`), `policy_pkg(adom, pkg, fetched_at, fingerprint, policy_count, status, error, blob)`, `policy_block(adom, block, fetched_at, fingerprint, status, error, blob)`, `policy_objects(scope_key, kind, fetched_at, fingerprint, status, error, blob)` with `scope_key` = ADOM name or `"global"` and `kind` in `address, addrgrp, service, svcgrp, vip, ippool`, `policy_refresh_request(adom, pkg, requested_at)`.
- API: `put_packages(adom, entries)`, `get_packages(adom) -> {entries, fetched_at, age_seconds} | None`, `put_policies(adom, pkg, policies, fingerprint)` / `get_policies(adom, pkg) -> {policies, fetched_at, age_seconds, fingerprint, policy_count, status, error} | None`, `touch_policies(adom, pkg)`, `mark_policies_error(adom, pkg, error)`, same trio for `block` and `objects`, `delete_missing_packages(adom, keep)`, `delete_missing_blocks(adom, keep)`, `delete_missing_adoms(keep)`, `package_meta(adom) -> list[{pkg, fetched_at, age_seconds, policy_count, status}]` (no blobs), `request_package_refresh(adom, pkg, min_interval_s) -> bool`, `pop_refresh_requests(limit) -> list[tuple[adom, pkg]]`, `PolicyStoreError`; `fingerprint(obj) -> str` reuses `hygiene_pkg_store.fingerprint`.

- [ ] **Step 1: Write failing tests:** round trip of packages/policies/blocks/objects (compressed blob smaller than JSON; content equal), `test_put_replaces_atomically_for_readers` (reader thread never sees a mix), `test_error_keeps_previous_blob_and_flags_status`, `test_never_collected_returns_none_vs_collected_empty_returns_empty`, `test_delete_missing_*`, `test_package_meta_does_not_load_blobs` (patch `zlib.decompress` to raise), `test_reads_do_not_wait_for_write_lock`, `test_refresh_request_throttle_per_package_and_pop_limit`, `test_unreadable_store_raises_policy_store_error`, `test_five_hundred_rule_package_blob_is_compressed_below_a_quarter` (synthetic rules), `test_config_ttl_falls_back_to_hygiene_env` (via helper, never reload `app.config`).
- [ ] **Step 2: Run** `pytest tests/test_policy_store.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): policy and object store tables`.

### Task 3: Collector refresh job

**Files:** Create `app/policy_cache.py`; modify `app/__init__.py` (register after inventory), `app/boot_warmup.py` priorities (policy refresh priority 3); Test `tests/test_policy_cache.py`.

**Interfaces:**
- Consumes Tasks 1-2, Phase 1 FMG access layer.
- Produces: `policy_cache.refresh_once(client=None) -> dict` (`{"adoms","packages","fetched","reused","failed":[...],"calls","seconds"}`; single-flight), `policy_cache.refresh_objects(client=None) -> dict`, `policy_cache.process_refresh_requests(client=None) -> int`, `policy_cache.init_scheduler(app) -> bool` (False when `POLICY_STORE` off). Per cycle: `get_policy_packages(strict=True)` per non-`forti*` ADOM from `inventory.adoms`; per package a store row younger than its jittered TTL (reuse Phase 3 `effective_ttl_seconds`) is skipped, else `get_policies` -> fingerprint -> `put` or `touch`; policy blocks referenced by stored policies (`_policy_block`) fetched with `get_pblock_policies(strict=True)` once per block per cycle; global objects once per cycle, local objects per ADOM, with `POLICY_PARALLEL_FETCH` workers; any failure marks the row (keeps data) and never deletes; `delete_missing_packages/blocks/adoms` only after a fully successful listing; a 10 s job `process_refresh_requests` fetches requested packages immediately (bypassing TTL), at most 20 per tick.

- [ ] **Step 1: Write failing tests** (synthetic fleet, `client._post = synth.post`): `test_first_cycle_fetches_everything_once` (call counts: 1 list per ADOM, 1 policy fetch per package, 1 per object kind per ADOM-local plus 6 global), `test_second_cycle_inside_ttl_makes_only_list_calls`, `test_changed_package_is_replaced_unchanged_is_touched`, `test_failed_package_fetch_keeps_previous_rows_and_marks_error`, `test_empty_or_failed_package_list_never_deletes_cached_packages`, `test_removed_package_deleted_only_after_successful_listing`, `test_policy_blocks_fetched_once_for_many_referencing_packages`, `test_block_failure_is_recorded_not_silent`, `test_global_objects_fetched_once_not_per_adom`, `test_parallel_fetch_respects_cap` (peak concurrent <= `POLICY_PARALLEL_FETCH`), `test_single_flight`, `test_request_row_fetches_that_package_now_and_clears`, `test_scheduler_not_registered_when_flag_off`, `test_registered_jobs_and_boot_priority`.
- [ ] **Step 2: Run** `pytest tests/test_policy_cache.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): collector policy and object refresh`.

### Task 4: Policy facade

**Files:** Create `app/policies.py`; Test `tests/test_policies_facade.py`.

**Interfaces:** `packages(client, adom, fresh=False) -> list[dict]` (entries as `get_policy_packages`), `pkg_entry(client, adom, pkg_path) -> dict` (settings/scope from the entry: replaces `get_pkg_settings`/`get_pkg_scope_members`: `pkg_settings(client, adom, pkg_path)`, `pkg_scope(client, adom, pkg_path)`), `policies(client, adom, pkg_path, fresh=False) -> list[dict]`, `pblock_policies(client, adom, block, strict=False) -> list[dict]`, `objects(client, adom, kind, scope="all") -> list[dict]` (`kind` in the six kinds; `local`+`global` merged in the same order as the client), `data_as_of(adom, pkg_path=None) -> str | None`, `counters()`, `reset_counters()`. Flag off or `fresh=True` -> straight client call. Flag on: serve rows `status ok` (or `error` with data) within max age; missing/stale/unreadable -> one live call (counted `fallbacks`/`store_errors`); results are fresh copies; `forti*` ADOMs -> empty without a call.

- [ ] **Step 1: Write failing tests:** `test_flag_off_calls_client_never_store`, `test_fresh_true_goes_live`, `test_serves_from_store_zero_fmg_calls`, `test_stale_or_missing_row_goes_live_and_counts`, `test_error_status_with_data_within_max_age_still_served`, `test_store_error_goes_live`, `test_results_are_copies`, `test_object_scopes_match_client_for_local_global_all`, `test_pkg_settings_and_scope_equal_client_methods`, `test_pblock_strict_raises_when_row_in_error_and_stale`, `test_data_as_of_is_oldest_involved_row`, `test_system_adoms_empty_without_calls`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): policy facade with fail-open fallback`.

### Task 5: Background consumers: hygiene sweep and summary counts

**Files:** Modify `app/executive_summary_cache.py` (`_package_hygiene`, sweep package/object reads), `app/hygiene_pkg_store.py`, `app/summary_job.py`; Test `tests/test_policy_consumers_background.py`.

**Interfaces:** With `POLICY_STORE` on the hygiene sweep reads packages, policies and objects through the facade (zero FMG calls in steady state); `hygiene_pkg_store` findings are reused when the policy fingerprint from the store equals the cached one (no recompute) and its own TTL logic is removed for that path; `rule_hygiene.data_as_of` = oldest package `fetched_at`; `summary_job` rule counts use `policy_count` from the store. Flag off: Phase 3 behaviour unchanged.

- [ ] **Step 1: Write failing tests:** `test_sweep_makes_zero_fmg_calls_with_populated_store` (client that raises on any call), `test_sweep_results_equal_live_results_cold_and_warm`, `test_findings_recomputed_only_when_fingerprint_changes` (spy on `run_checks`), `test_data_as_of_is_oldest_store_fetch`, `test_summary_rule_counts_from_store_equal_live`, `test_flag_off_unchanged`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file plus `pytest tests/test_hygiene_sweep_cache.py tests/test_executive_summary_cache.py tests/test_summary_job.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): hygiene sweep and summary rule counts read the policy store`.

### Task 6: Rule Lookup on the store

**Files:** Modify `app/rule_lookup_cache.py`, `app/routes/hygiene_routes.py` (rule-lookup endpoints); Test `tests/test_rule_lookup_store.py`.

**Interfaces:** `_build_adom` reads packages, per-package policies, policy blocks and objects through the facade; with `POLICY_STORE` on the first search of an ADOM builds the in-process index from the store in a request thread without FMG (no 202 "warming" unless the store has no rows for that ADOM, then the legacy warm-up path); the index is cached per process keyed by the store generation (`max(fetched_at)` over the ADOM's package rows) and rebuilt lazily when it changes; response gains `data_as_of`; `/refresh` requests package refreshes through the store request rows instead of calling FMG. Flag off: unchanged.

- [ ] **Step 1: Write failing tests:** `test_first_search_builds_from_store_with_zero_fmg_calls`, `test_results_equal_live_build` (same fleet, same queries incl. `skipped_count`, `package_errors`, port-only counts), `test_policy_blocks_expand_like_legacy`, `test_block_failure_listed_in_package_errors`, `test_index_rebuilt_when_store_generation_changes_not_otherwise`, `test_empty_store_falls_back_to_warming_path`, `test_refresh_endpoint_enqueues_requests_no_fmg_calls`, `test_response_includes_data_as_of`, `test_flag_off_unchanged`, `test_build_time_and_memory_for_24k_rule_adom` (synthetic 80 packages x 300 rules: build < 10 s, index RSS delta < 400 MB, a search < 1 s; thresholds asserted loosely, exact numbers recorded in Task 9).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file plus `pytest tests/test_rule_lookup*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): Rule Lookup index built from the policy store`.

### Task 7: Interactive hygiene and Rule Review routes

**Files:** Modify `app/routes/hygiene_routes.py` (package list, `/policies`, `/policies/raw`, `/policies/pblocks`, `/policies/objects`, `objects/lookup`, `objects/where-used`, `nat/lookup` shared part, `/run` policy+objects+scope, `unused-objects`, ADOM `packages/raw`), `app/routes/rule_review_routes.py` where it reads packages/objects; Test `tests/test_policy_consumers_routes.py`.

**Interfaces:** each call site swaps `client.get_*` for the facade; the `/run` unhit overlay (per-device hit counts) and per-device VIP/IP pool and interface lookups stay live; responses of the package-scoped endpoints gain `data_as_of`; `fresh=1` is not offered (use Refresh).

- [ ] **Step 1: Write failing tests** (flag on, populated store, client that raises on policy/object calls but serves proxy calls): per endpoint `test_<endpoint>_same_json_from_store_zero_policy_calls` for all listed endpoints; `test_where_used_scans_all_packages_from_store`; `test_run_hygiene_unhit_overlay_still_live` (hit-count proxy calls occur, policy fetch does not); `test_restricted_user_gets_403_other_adom_with_store_on`; `test_flag_off_unchanged`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file plus `pytest tests/test_hygiene*.py tests/test_rule_review*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): hygiene and Rule Review routes read the policy store`.

### Task 8: Scheduled reports, Package Change Alerts stay live

**Files:** Modify `app/rule_hygiene_scheduler.py` / `bulk_hygiene_adom` in `app/routes/hygiene_routes.py`, `app/rule_policy_scheduler.py`, `app/nat_report_scheduler.py`, `app/package_change_alerts.py`; Test `tests/test_policy_consumers_schedulers.py`.

**Interfaces:** scheduled Rule Hygiene, Rule Policy and NAT reports read through the facade and state "data as of <oldest fetched_at>" in the email body when it is older than 15 minutes; `rule_policy_scheduler._bulk_policy_adom(adom, ..., fresh: bool = False)`; `package_change_alerts` passes `fresh=True` so its attached policy report is live (the report must contain the change that triggered the alert).

- [ ] **Step 1: Write failing tests:** `test_bulk_hygiene_adom_zero_policy_calls_with_store`, `test_rule_policy_report_equals_live_content`, `test_nat_report_shared_objects_and_packages_from_store_device_sweep_live`, `test_pca_policy_report_uses_fresh_live_fetch` (policy store row differs from FMG; the attachment contains the FMG version), `test_digest_states_data_age_when_older_than_15_min`, `test_flag_off_unchanged`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file plus `pytest tests/test_rule_hygiene_scheduler.py tests/test_nat_report_scheduler.py tests/test_package_change_alerts.py tests/test_rule_policy*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): scheduled reports read the policy store; alerts stay live`.

### Task 9: Freshness API/UI, measurement, load check, docs

**Files:** Modify `app/routes/api_routes.py`, `app/static/js/freshness.js` (or new `policy_freshness.js`), `hygiene.html`, `audit_review.html`, `scripts/measure_fmg_baseline.py`, docs, `CLAUDE.md`; Create `scripts/verify_policy_store_load.py`, `docs/superpowers/measurements/2026-11-phase4-results.md`; Tests `tests/test_policy_freshness_api.py`, `tests/test_measure_baseline.py`.

**Interfaces:** `GET /api/policy-store/status?adom=` (login + `rule_hygiene` or `audit_review` tab + `check_adom_access`) -> `{enabled, adom, packages:[{pkg, fetched_at, age_seconds, policy_count, status, stale}], objects:{fetched_at, age_seconds, stale}}`; `POST /api/policy-store/refresh {adom, pkg}` (same access, CSRF, 202 / 429 with `retry_after`, throttled by `POLICY_REFRESH_MIN_INTERVAL_SECS` per package); the Rule Review and Audit Review hygiene sections show "Data as of ... (N min ago)" for the selected package with a Refresh button (text via `textContent`); `scripts/verify_policy_store_load.py [--db PATH --adoms 5 --packages 80 --rules 300 --readers 2]` writes a synthetic fleet through the collector code path while reader processes query, then prints DB size, write time, per-package read p50/p95 and any error (runs on any machine, no FMG); `measure(...)` includes the policy refresh as source `policy_cache` and every sweep reading the store.

- [ ] **Step 1: Write failing tests:** status filters ADOMs by access and marks stale/error rows, refresh admin-or-tab-user rules, 202 then 429 with `Retry-After`, refresh enqueues one request row and the collector processes it, `test_pages_include_policy_freshness_hooks_only_when_enabled`, `test_measure_policy_store_run_reports_policy_cache_source_and_zero_sweep_policy_calls`, `test_verify_policy_store_load_small_run_passes` (tiny parameters in a temp DB).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement;** run `PYTHONPATH=. uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache --policy-store --out docs/superpowers/measurements/2026-11-phase4-1000.json` and `uv run python scripts/verify_policy_store_load.py --adoms 5 --packages 80 --rules 300 --readers 2`. Expected: policy refresh plus remaining sources <= ~300 calls/hour; sweeps and summary read zero policy calls; record DB size, per-package read latency, Rule Lookup build time and memory in `2026-11-phase4-results.md`.
- [ ] **Step 4: Docs:** `POLICY_STORE` description updated (now the full layer), `POLICY_PACKAGE_TTL_HOURS`, `POLICY_OBJECTS_REFRESH_MINUTES`, `POLICY_MAX_AGE_SECS`, `POLICY_PARALLEL_FETCH`, `POLICY_REFRESH_MIN_INTERVAL_SECS`; staleness statement (policy data up to ~7.5 h old unless Refresh; PCA reports live); disk-size estimate and where the DB lives; rollback; `CLAUDE.md` Scale foundations paragraph ("new code that needs packages/policies/objects calls `app.policies`").
- [ ] **Step 5: Run the full suite** (bare `pytest`) and `ruff check` + `ruff format --check` on changed files. Expected: all pass.
- [ ] **Step 6: Commit** `feat(scale): Phase 4 freshness, measurements and docs`.

## Self-review notes

- Spec coverage: F3 per-package store with fingerprint and TTL (T2-T3), Rule Lookup replaces the per-process FMG-built cache (T6), Rule Review / Object / NAT / Interface (store parts) / Hygiene / unused objects (T7), exec hygiene sweep and summary counts (T5), Package Change Alerts handled deliberately live (T8), F8 for these views (T9), acceptance targets 2 (cached searches p95 < 2 s, measured in T6/T9), 4 (memory, T6/T9), 1 (T9). Policy-block expansion and shared global objects covered. The `obj ver` marker remains unverified, so TTL + fingerprint + Refresh stay the change-detection story.
- Builder's calls, challengeable: zlib JSON blobs per package (not normalised rule rows) because every reader needs whole packages and SQLite stays small; Rule Lookup index built in each web process from the store (not a SQLite search index) and measured; Refresh is a request row the collector serves within ~10 s, not a live web fetch; PCA's report is live; planner, log hygiene, PSIRT, self-test and per-device proxy data stay live.
- Not in this phase: device audit snapshots (Phase 5), job queue (Phase 6), a SQLite-side rule search index (revisit only if the Task 6 measurement misses the 2 s target).
