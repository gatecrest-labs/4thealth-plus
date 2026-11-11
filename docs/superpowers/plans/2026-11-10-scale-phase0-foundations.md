# Scale Phase 0: Foundations and Measurement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the measurement and safety foundation for the 1,000-FortiGate scale work: feature flags, a proven shared store, FMG call metrics, a synthetic 1,000-device FMG, a recorded baseline, and lab-FMG spike tooling, ending in a go/no-go gate for Phases 1-6.

**Architecture:** Phase 0 changes no user-visible behaviour (all new flags default off). It adds `app/fmg_metrics.py` hooked into `FMGClient._post`, makes the collector store's path/journal mode configurable and crash-tested, adds `app/synthetic_fmg.py` (a drop-in `_post` transport like `fmg_recorder.ReplayTransport`) plus scripts that use it to measure today's FMG call volume, and adds read-only spike scripts for the lab FMG.

**Tech Stack:** Python 3.12+, Flask, SQLite (stdlib), pytest, ruff, uv, Docker Compose (Mac test rig only).

**Spec:** `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` (this plan implements its Phase 0 only; Phases 1-6 get their own plans after the gate in Task 9).

## Global Constraints

- Branch `develop`; commit after each task. Commit messages end with the attribution lines the harness supplies.
- Strictly read-only toward Fortinet: scripts and spikes issue only read calls (`get`, proxy GET). Nothing may stage, install, or write on FMG.
- Production = bare RHEL, two systemd units (`4thealth`, `4thealth-collector`), no containers; Docker is the Mac test rig only. Nothing in `app/` may depend on Docker.
- FMG auth in production is an API token; username/password only warns.
- Every new layer flag defaults off: `INVENTORY_CACHE`, `POLICY_STORE`, `AUDIT_SNAPSHOTS`, `JOB_QUEUE`.
- `uv` only (`uv run pytest`, `uv run ruff check`, `uv run ruff format`); run `git checkout uv.lock` after if `uv run` dirtied it. Ruff here is strict: use `datetime.datetime.now(datetime.UTC)` (never `utcnow()`), and add `# noqa` only with the same comment text the repo already uses.
- New runtime files (`*.db`, `data/`) are gitignored; DB files mode 0600.
- A metrics or flag failure must never break an FMG call or a request.
- Acceptance targets (spec 7a) are measured against the baseline produced in Task 6.

## Review Focus

- Metrics recorder errors (full disk, locked DB) must not raise into `_post`; calls still succeed. Pinned in Task 3.
- `COLLECTOR_DB_JOURNAL` set to garbage must fall back to WAL with a logged warning, not crash the app at import. Pinned in Task 1.
- Collector never ran / metrics snapshot missing or stale: the admin endpoint returns web-only data plus a note, never 500. Pinned in Task 4.
- 16 threads hammering the metrics recorder lose no counts. Pinned in Task 3.
- Synthetic FMG asked for a URL it does not implement returns an FMG error object and is counted as `unsupported`, never raises. Pinned in Task 5.
- Non-admin users cannot read FMG metrics (403). Pinned in Task 4.

## File Structure

- Modify `app/config.py` (flags), `app/collector_store.py` (path/journal), `app/fmg_client.py` (`_post` hook), `app/routes/admin_routes.py` (+ `app/templates/admin.html`, `app/static/js/admin.js`), `.gitignore`, `.env.example`, `docker-compose.yml`, `docs/deployment.md`.
- Create `app/fmg_metrics.py`, `app/synthetic_fmg.py`, `scripts/verify_shared_store.py`, `scripts/measure_fmg_baseline.py`, `scripts/synthetic_fmg_server.py`, `scripts/fmg_spike.py`, `docs/superpowers/measurements/`.
- Tests: `tests/test_config_flags.py`, `tests/test_collector_store_config.py`, `tests/test_collector_store_crash.py`, `tests/test_fmg_metrics.py`, `tests/test_admin_fmg_metrics.py`, `tests/test_synthetic_fmg.py`, `tests/test_measure_baseline.py`, `tests/test_fmg_spike.py`.

---

### Task 1: Layer flags and configurable shared-store location

**Files:**
- Modify: `app/config.py`, `app/collector_store.py`, `.gitignore`, `.env.example`
- Test: `tests/test_config_flags.py`, `tests/test_collector_store_config.py`

**Interfaces:**
- Produces: `Config.INVENTORY_CACHE`, `Config.POLICY_STORE`, `Config.AUDIT_SNAPSHOTS`, `Config.JOB_QUEUE` (all `bool`, default `False`, env vars of the same names, truthy = `1/true/yes/on`); `collector_store._db_path() -> Path` (env `COLLECTOR_DB_PATH`, default the current project-root `collector_state.db`); `collector_store._journal_mode() -> str` (env `COLLECTOR_DB_JOURNAL`, `WAL` or `DELETE`, default `WAL`).

- [ ] **Step 1: Write failing tests.** `test_flags_default_off`, `test_flags_parse_truthy_values` (parametrized `"1","true","YES","on"` → True, `"0","","no"` → False) in `tests/test_config_flags.py`. In `tests/test_collector_store_config.py`: `test_db_path_env_override` (set `COLLECTOR_DB_PATH` to a tmp file; `write_snapshot`/`read_snapshot` round-trip lands in that file), `test_journal_delete_mode_applied` (env `DELETE` → `PRAGMA journal_mode` returns `delete`), `test_journal_invalid_falls_back_to_wal_and_warns` (env `bogus` → `wal`, a warning is logged via `caplog`).
- [ ] **Step 2: Run** `uv run pytest tests/test_config_flags.py tests/test_collector_store_config.py -v`. Expected: FAIL (attributes/functions missing).
- [ ] **Step 3: Implement** the four flags in `app/config.py` using the file's existing env-parsing style. In `app/collector_store.py` replace the module constant `_DB_PATH` use with `_db_path()`; the existing test fixture monkeypatches `_DB_PATH`, so keep `_DB_PATH` as the default value that `_db_path()` returns when the env var is unset. `_connect()` applies `_journal_mode()`; invalid values log a warning and use WAL. Create the parent directory if missing and `chmod 0600` the file on first create.
- [ ] **Step 4: Run** the two new test files plus `uv run pytest tests/test_collector_store.py -v`. Expected: all PASS (existing WAL test still passes).
- [ ] **Step 5: Add** `data/` and `*.db-wal`/`*.db-shm` to `.gitignore`; document the four flags, `COLLECTOR_DB_PATH`, `COLLECTOR_DB_JOURNAL` (default WAL; DELETE only if WAL proves unsafe on a given filesystem) in `.env.example`. `uv run ruff check . && uv run ruff format .`.
- [ ] **Step 6: Commit** `feat(scale): layer flags and configurable collector store path/journal`.

### Task 2: Shared-store crash and two-process proof

**Files:**
- Create: `scripts/verify_shared_store.py`
- Test: `tests/test_collector_store_crash.py`

**Interfaces:**
- Consumes: `collector_store.write_snapshot/read_snapshot` and the env vars from Task 1.
- Produces: `scripts/verify_shared_store.py --db PATH --seconds N` exiting 0 only if a writer process killed with SIGKILL mid-write leaves the DB passing `PRAGMA integrity_check` and a reader process still reading the last committed value. Operators run it on the real RHEL VM under the `4thealth` user.

- [ ] **Step 1: Write failing test** `test_sigkill_writer_leaves_store_consistent`: spawn a writer subprocess (`python -m` or `multiprocessing`) looping `write_snapshot("proof", {"n": i, "pad": "x"*200000})`; a reader process loops `read_snapshot("proof")` asserting the payload always parses and `n` never decreases; SIGKILL the writer after ~2 s; then assert `PRAGMA integrity_check` == `ok` and `read_snapshot("proof")["n"] >= 1`. Parametrize over journal mode `WAL` and `DELETE`.
- [ ] **Step 2: Run** `uv run pytest tests/test_collector_store_crash.py -v`. Expected: FAIL (script/module wiring missing) or, if the store is already safe, PASS. If it fails for a real reason, stop and report it (this is the Phase 0 gate input).
- [ ] **Step 3: Implement** `scripts/verify_shared_store.py` with `main(argv: list[str] | None = None) -> int` reusing the same writer/reader logic (factor shared helpers into the script and import them from the test) and printing a one-line verdict per journal mode.
- [ ] **Step 4: Run** the test and `uv run python scripts/verify_shared_store.py --db /tmp/proof.db --seconds 3`. Expected: PASS / exit 0.
- [ ] **Step 5: Commit** `test(scale): crash and two-process proof for the shared collector store`.

### Task 3: FMG call metrics

**Files:**
- Create: `app/fmg_metrics.py`
- Modify: `app/fmg_client.py:475-489` (`_post`)
- Test: `tests/test_fmg_metrics.py`

**Interfaces:**
- Produces: `normalize_url(url: str) -> str` (replaces ADOM/device/package/VDOM name segments with `{adom}`, `{device}`, `{pkg}`; `/sys/proxy/json` stays as-is); `record(method: str, url: str, seconds: float, ok: bool) -> None`; `snapshot() -> dict` shaped `{"role": str, "since": iso, "total": int, "errors": int, "by_url": {"<METHOD> <norm url>": {"count": int, "errors": int, "total_s": float, "p50_s": float, "p95_s": float}}}`; `flush(force: bool = False) -> None` writes `snapshot()` to `collector_store` key `fmg_metrics:<role>` at most every 30 s unless forced; `reset() -> None` (tests). `role` is `"collector"` when `Config.RUN_SCHEDULERS == "inline"` else `"web"`. Percentiles come from a bounded per-key sample (last 500).

- [ ] **Step 1: Write failing tests:** `test_normalize_url_examples` (`/dvmdb/adom/Ent/device` → `/dvmdb/adom/{adom}/device`; `/pm/config/adom/Ent/pkg/Pk/firewall/policy` → `/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy`; `/sys/proxy/json` unchanged), `test_record_and_snapshot_counts_and_percentiles`, `test_record_is_thread_safe` (16 threads x 1000 records → `total == 16000`), `test_record_failure_never_raises` (monkeypatch `collector_store.write_snapshot` to raise; `record` and `flush(force=True)` do not raise), and `test_post_records_metric` (an `FMGClient` whose `_http.post` is stubbed returns JSON → `snapshot()["by_url"]` has the called URL; a raising `_http.post` records `errors == 1` and still re-raises the original error).
- [ ] **Step 2: Run** `uv run pytest tests/test_fmg_metrics.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `app/fmg_metrics.py` (module-level lock + dicts) and wrap the body of `FMGClient._post` with timing that calls `fmg_metrics.record(...)` in a `try/except Exception: pass`, then `flush()`. URL/method come from `body["method"]` and `body["params"][0]["url"]`.
- [ ] **Step 4: Run** the new tests plus `uv run pytest tests/test_fmg_client_session.py tests/test_fmg_replay_fixtures.py -v`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): FMG call metrics (count, errors, latency per normalized URL)`.

### Task 4: Admin FMG metrics endpoint and view

**Files:**
- Modify: `app/routes/admin_routes.py` (new route near `api_fmg_selftest`, and add it to the module docstring route list), `app/templates/admin.html` (inside `#panel-api-selftest`), `app/static/js/admin.js`
- Test: `tests/test_admin_fmg_metrics.py`

**Interfaces:**
- Consumes: `fmg_metrics.snapshot()` and `collector_store.read_snapshot("fmg_metrics:collector" | "fmg_metrics:web")`.
- Produces: `GET /admin/api/fmg-metrics` (admin only) returning `{"web": {...}|null, "collector": {...}|null, "note": str|null}`; `note` explains a missing/stale (>5 min) collector snapshot. Never 500.

- [ ] **Step 1: Write failing tests** using the `client` fixture pattern from `tests/test_hygiene_routes_lookup.py` (admin session): `test_requires_admin` (viewer session → 403), `test_returns_web_and_collector_snapshots`, `test_missing_collector_snapshot_returns_note_not_500`, `test_stale_collector_snapshot_flagged_in_note`.
- [ ] **Step 2: Run** `uv run pytest tests/test_admin_fmg_metrics.py -v`. Expected: FAIL (404).
- [ ] **Step 3: Implement** the route with the module's existing `_admin_required` decorator. In the API Self-Test panel add an "FMG Call Metrics" table (URL, count, errors, p50, p95) with a Refresh button, following the self-test button's fetch/render style.
- [ ] **Step 4: Run** the new tests and `uv run pytest tests -k admin -q`. Expected: PASS. Manually load Admin → API Self-Test in the Mac rig and confirm the table renders.
- [ ] **Step 5: Commit** `feat(scale): admin FMG metrics endpoint and table`.

### Task 5: Synthetic 1,000-device FMG transport

**Files:**
- Create: `app/synthetic_fmg.py`
- Test: `tests/test_synthetic_fmg.py`

**Interfaces:**
- Produces: `class SyntheticFMG` with `__init__(self, adoms: int = 5, devices: int = 1000, multi_vdom_fraction: float = 0.4, packages_per_adom: int = 80, rules_per_package: int = 300, latency_ms: tuple[float, float] = (0.0, 0.0), error_rate: float = 0.0, seed: int = 1)`; `post(self, body: dict) -> dict` (drop-in for `FMGClient._post`, thread-safe, sleeps a random time within `latency_ms`, raises `requests.ConnectionError` on injected error); `calls: collections.Counter[str]` keyed by `"<METHOD> <normalized url>"` (use `fmg_metrics.normalize_url`); `unsupported: collections.Counter[str]`; `total_calls` property. Deterministic for a given seed. Supports at least: `/sys/status`, `/dvmdb/adom`, `/dvmdb/adom/{adom}/device` (with embedded `vdom` list, `ha_mode`, `conn_status`, `conf_status`, `db_status`, `os_ver/mr/patch`, `platform_str`, `sn`, `latitude/longitude`), `/dvmdb/adom/{adom}/revision`, `/pm/pkg/adom/{adom}`, `/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy` (paged by `range`), the address/addrgrp/service/vip/ippool object URLs the client's catalog methods use, and `/sys/proxy/json` for the license-status, system-status, interface and package-status resources. Any other URL returns the FMG error shape (`result[0].status.code == -3`) and increments `unsupported`.

- [ ] **Step 1: Write failing tests:** `test_deterministic_for_seed`, `test_device_counts_match_config` (real `FMGClient` with `c._post = SyntheticFMG(devices=50, adoms=2).post`: `get_adoms()` and `get_devices(adom)` totals equal 50 across ADOMs; some devices have >1 VDOM), `test_policy_paging_returns_all_rules` (via the client's `get_policies`), `test_proxy_license_status_parses_via_license_status_parse` (`app.license_status.parse_license_payload` on the synthetic payload yields a classified status), `test_unsupported_url_returns_error_object_and_counts` (no raise), `test_error_injection_raises_connection_error` (`error_rate=1.0`), `test_calls_counter_counts_per_normalized_url`.
- [ ] **Step 2: Run** `uv run pytest tests/test_synthetic_fmg.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `SyntheticFMG`. Response shapes must match what the corresponding `FMGClient` methods parse: read each method in `app/fmg_client.py` and the recorded `tests/fixtures/fmg_8.0.2/exchanges.json` for the exact shapes; add URL support incrementally until the sweeps in Task 6 run without `unsupported` hits for the calls they make.
- [ ] **Step 4: Run** the tests. Expected: PASS. `uv run ruff check . && uv run ruff format .`.
- [ ] **Step 5: Commit** `feat(scale): synthetic FMG transport for 1,000-device load tests`.

### Task 6: Baseline measurement of today's FMG call volume

**Files:**
- Create: `scripts/measure_fmg_baseline.py`, `docs/superpowers/measurements/` (with a `README.md` saying what is stored here)
- Test: `tests/test_measure_baseline.py`

**Interfaces:**
- Consumes: `SyntheticFMG` (Task 5); the sweep entry points `summary_job._run_job(app)`, `versions_cache._run_job(app)`, `map_cache._run_job(app)`, `adom_cache._run_refresh(app)`, `pending_status_cache._run_refresh(app)`, `executive_summary_cache._run_device_sweep(app)` and `_run_hygiene_sweep(app)`, `license_status_cache._run_sweep(app)`, `device_backup_cache._run_sweep(app)`.
- Produces: `measure(devices: int, latency_ms: tuple[float, float] = (0.0, 0.0)) -> dict` returning `{"devices": int, "sweeps": {"<name>": {"calls": int, "by_url": {...}, "interval_min": int}}, "calls_per_hour": float, "inventory_downloads_per_cycle": int}`; CLI `python scripts/measure_fmg_baseline.py --devices 1000 --out docs/superpowers/measurements/<date>-baseline.json`. `interval_min` comes from the same env/constants the schedulers use (for example `VERSIONS_CACHE_INTERVAL_MIN`, `_REFRESH_MINUTES`, `EXEC_SUMMARY_REFRESH_MINUTES`). Each sweep runs once, with `FMGClient._post` patched at class level to `SyntheticFMG.post`; per-sweep state (module caches, `collector_store` path) is isolated to a temp dir.

- [ ] **Step 1: Write failing tests:** `test_measure_small_rig_reports_each_sweep` (`devices=20`: every sweep name above is present with `calls > 0`), `test_inventory_is_downloaded_repeatedly` (`inventory_downloads_per_cycle >= 5`, which documents the duplicate device-list fetch finding C2), `test_measure_does_not_write_to_fmg` (no recorded call uses method `add`, `set`, `update`, `delete` or `exec` except the read-only ones the client already uses for `exec /sys/proxy/json`).
- [ ] **Step 2: Run** `uv run pytest tests/test_measure_baseline.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `scripts/measure_fmg_baseline.py` (`measure()` plus `main()`); count `inventory_downloads_per_cycle` as the number of `GET /dvmdb/adom/{adom}/device` calls divided by ADOM count.
- [ ] **Step 4: Run** tests, then `uv run python scripts/measure_fmg_baseline.py --devices 1000 --out docs/superpowers/measurements/2026-11-baseline-1000.json`. Expected: JSON written; commit it. Record `calls_per_hour` in `docs/superpowers/measurements/README.md` as the number later phases must beat by 10x.
- [ ] **Step 5: Commit** `feat(scale): baseline FMG call measurement and 1,000-device result`.

### Task 7: Docker test rig (Mac only)

**Files:**
- Create: `scripts/synthetic_fmg_server.py`
- Modify: `docker-compose.yml`, `docs/deployment.md` (a short "Mac/Docker test rig" note, clearly marked non-production)

**Interfaces:**
- Consumes: `SyntheticFMG`.
- Produces: `scripts/synthetic_fmg_server.py` serving `POST /jsonrpc` over HTTPS (reuses `certs/cert.pem`/`key.pem`), env `SYNTH_DEVICES`, `SYNTH_LATENCY_MS_MIN/MAX`, `SYNTH_ERROR_RATE`; a compose service `synthetic-fmg` under `profiles: ["rig"]`; `web` and `collector` use a shared `./data:/app/data` directory with `COLLECTOR_DB_PATH=/app/data/collector_state.db` (replacing the two single-file `collector_state.db` mounts at `docker-compose.yml:42,98`).

- [ ] **Step 1: Implement** the server (Flask app wrapping `SyntheticFMG.post`, plus `GET /_calls` returning `calls`/`unsupported` as JSON) and the compose changes.
- [ ] **Step 2: Verify** `docker compose --profile rig up -d`, set `FMG_PRIMARY_HOST=synthetic-fmg` and `FMG_VERIFY_SSL=false` for the rig, wait one collector cycle, then confirm `curl -k https://localhost:8100/api/health` is healthy, the Dashboard shows ~1,000 devices, and `GET /admin/api/fmg-metrics` shows both `web` and `collector` data. Confirm the collector's snapshot is visible from web (this proves the directory-mounted store is shared across the two containers).
- [ ] **Step 3: Commit** `feat(scale): Docker test rig with synthetic FMG and shared data directory`.

### Task 8: Lab-FMG spike script (read-only)

**Files:**
- Create: `scripts/fmg_spike.py`
- Test: `tests/test_fmg_spike.py`

**Interfaces:**
- Produces: pure functions `summarize_sizes(variants: dict[str, bytes]) -> dict[str, dict]` (bytes, relative to the largest), `percentiles(samples: list[float]) -> dict` (`p50`, `p95`, `max`), `diff_keys(a: dict, b: dict) -> dict` (keys only in a / only in b); CLI subcommands, each writing JSON to `docs/superpowers/measurements/` and printing a summary: `devices-fields` (the ADOM device list with no options vs `fields` vs `loadsub: 0`, reporting payload bytes and whether VDOM data survives), `proxy-multi` (one `/sys/proxy/json` call with several `target` entries vs single, reporting response shape, and what happens when one target is unreachable; uses only a GET monitor resource), `pkg-marker` (dumps every field of the package list entries and the ADOM revision / audit-log signals available, so a change marker can be chosen), and `latency` (N sequential and K concurrent proxy GETs, reporting `percentiles`). All use `app.fmg_helpers.make_client()` and read-only calls.

- [ ] **Step 1: Write failing tests** for the three pure functions (`test_summarize_sizes_relative`, `test_percentiles_known_samples`, `test_diff_keys`), plus `test_subcommands_only_use_read_methods` (run each subcommand against `SyntheticFMG` and assert no write-style method was recorded).
- [ ] **Step 2: Run** `uv run pytest tests/test_fmg_spike.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `scripts/fmg_spike.py`.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Run on the lab FMG** (manual; needs `.env` pointing at the lab with its token): `uv run python scripts/fmg_spike.py devices-fields`, `proxy-multi`, `pkg-marker`, `latency`. Commit the JSON outputs after reading them for sensitive data (the repo is public; scrub IPs, serials and names or leave the files uncommitted and summarise instead).
- [ ] **Step 6: Commit** `feat(scale): read-only lab FMG spike tooling`.

### Task 9: Phase 0 gate

**Files:**
- Modify: `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` (add "Phase 0 results"), `docs/deployment.md` (new env vars, store location, `verify_shared_store.py` step for RHEL), `CLAUDE.md` (new modules: `fmg_metrics`, `synthetic_fmg`, flags, store settings)
- Create: `docs/superpowers/measurements/2026-11-phase0-results.md`

- [ ] **Step 1: On the RHEL VM** (two systemd units, real filesystem) run `sudo -u 4thealth /opt/4thealth/.venv/bin/python scripts/verify_shared_store.py --db /opt/4thealth/collector_state.db --seconds 10`. Record the result for WAL and DELETE.
- [ ] **Step 2: Write** `phase0-results.md`: baseline calls/hour (Task 6), spike findings (Task 8: payload savings from `fields`/`loadsub`, multi-target proxy behaviour, available change marker, latency p50/p95), store proof (Tasks 2 and 7).
- [ ] **Step 3: Apply the gates from spec 7a** and write each outcome in the results file and the design doc: WAL fails on the VM then `COLLECTOR_DB_JOURNAL=DELETE` in deployment docs; no usable package change marker then Phase 4 uses hash + TTL only; no proxy batching then Phase 5 uses the rolling window only; no `fields`/`loadsub` saving then Phase 2 still ships for call-count reduction. Any gate whose fallback is unsafe: stop and ask the owner.
- [ ] **Step 4: Update** `docs/deployment.md` and `CLAUDE.md`; run `uv run ruff check . && uv run pytest -q`. Expected: green (note the known pre-existing failure `tests/test_pending_status_cache.py::test_get_cache_status_initial` only if it still fails on a clean baseline).
- [ ] **Step 5: Commit** `docs(scale): Phase 0 results and go/no-go gate`; then write the Phase 1 plan (shared FMG access layer) against the recorded numbers.
