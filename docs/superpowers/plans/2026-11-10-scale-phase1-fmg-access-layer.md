# Scale Phase 1: FMG Access Layer (F1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every FMG JSON-RPC call goes through one pooled HTTP session per process, a per-process in-flight cap and a safe retry/backoff policy, with the effect visible on the Admin metrics table.

**Architecture:** All changes live inside `FMGClient._post` (`app/fmg_client.py`) plus a small new module `app/fmg_access.py` holding the process-wide pool, semaphore and retry policy. `_post` is already the single choke point (Phase 0), so no caller changes. The semaphore wraps only the single HTTP round trip, never a whole operation, so install-preview polling and retry sleeps never hold a slot.

**Tech Stack:** Python 3.14, `requests` (`HTTPAdapter` pool), `threading.BoundedSemaphore`, pytest, ruff (strict), uv.

**Spec:** `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` (section 4 "F1 FMG access layer", 6 risks, 7a acceptance target 3). Phase 0 measurements: `docs/superpowers/measurements/2026-11-phase0-results.md` (lab latency: sequential p50 0.16 s; 4 workers gave only ~1.3x speedup, so the cap is a ceiling not a speed-up).

## Global Constraints

- Branch `develop`; never push. Model use: Sonnet or cheaper only.
- App-wide FMG in-flight requests <= 16 across web (2 workers) + collector: defaults collector 8, each web worker 4 (total 16).
- The semaphore wraps only the HTTP round trip inside `_post`; never held while sleeping for backoff or polling a task.
- Retries must never replay a non-idempotent request that may have reached FMG: retry on connection errors raised before a response (any method); retry on 5xx and read timeouts only when `body["method"] == "get"`. Max attempts 3 (`FMG_RETRIES`, default 2 retries; `0` disables).
- `FMG_MAX_INFLIGHT` (int; `0` = unlimited/disabled; unset = role default above).
- No FMG-level `status.code != 0` replies are retried (they are answers, not transport failures).
- All FMG traffic stays inside `_post`; tests replace `client._post`, so F1 tests must exercise the real `_post` with a fake session.
- Read-only project: nothing here writes to Fortinet devices.
- Ruff strict, `uv`, TDD, suite must stay green (1,739 passing at start; run bare `pytest`).

## Review Focus

- Thread safety: 100 concurrent callers never exceed the cap (peak in-flight metric proves it); a caller that raises releases its slot (no leak after exceptions).
- Retry never duplicates an `exec` (install/stage) request after a read timeout or 5xx.
- `FMG_MAX_INFLIGHT=0` and `FMG_RETRIES=0` restore exact pre-Phase-1 behaviour.
- `FMGClient.__exit__` must not close the shared pool (other threads still use it); per-client `_http` for tests/recorder still works.
- Password-auth sessions (`login`/`logout`) keep working through the shared pool; `verify_ssl` differences give separate pools.

## File Structure

- Create `app/fmg_access.py`: `get_session(verify_ssl) -> requests.Session`, `inflight_cap() -> int`, `slot()` context manager, `backoff_delay(attempt) -> float`, `is_retryable(method, exc_or_status) -> bool`, `reset()` (tests).
- Modify `app/fmg_client.py`: `_post` uses the three helpers; `__init__` takes the pooled session; `__exit__` stops closing it.
- Modify `app/config.py`: `FMG_MAX_INFLIGHT`, `FMG_RETRIES`.
- Modify `app/fmg_metrics.py`, `app/routes/admin_routes.py`, `app/static/js/admin.js`, `app/templates/admin.html`: access counters.
- Modify `app/__init__.py` (or collector startup): password-auth warning when any layer flag is on.
- Tests: `tests/test_fmg_access.py`, `tests/test_fmg_post_access_layer.py`, additions to `tests/test_fmg_metrics.py`, `tests/test_admin_fmg_metrics.py`.
- Docs: `docs/deployment.md`, `.env.example`, `CLAUDE.md`.

---

### Task 1: Config knobs and the shared session pool

**Files:**
- Modify: `app/config.py`, `.env.example`
- Create: `app/fmg_access.py`
- Test: `tests/test_fmg_access.py`

**Interfaces:**
- Produces: `Config.FMG_MAX_INFLIGHT: int | None` (None = role default), `Config.FMG_RETRIES: int` (default 2); `fmg_access.get_session(verify_ssl: bool) -> requests.Session` (one per `verify_ssl` value per process, `HTTPAdapter(pool_connections=4, pool_maxsize=32)` mounted on `https://`, thread-safe creation); `fmg_access.reset() -> None`.

- [ ] **Step 1: Write failing tests** `test_same_session_returned_for_same_verify`, `test_different_verify_gives_different_session`, `test_session_creation_is_thread_safe` (32 threads, `get_session` returns one object), `test_adapter_pool_maxsize_is_32`, `test_config_defaults` (`FMG_RETRIES == 2`, `FMG_MAX_INFLIGHT is None` when env unset; env parsed with `int`, bad value falls back to default).
- [ ] **Step 2: Run** `pytest tests/test_fmg_access.py -v`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement** the config fields in `app/config.py` and `get_session`/`reset` in `app/fmg_access.py` (module-level dict + `threading.Lock`).
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): shared FMG session pool and config knobs`.

### Task 2: In-flight cap

**Files:**
- Modify: `app/fmg_access.py`
- Test: `tests/test_fmg_access.py`

**Interfaces:**
- Produces: `fmg_access.inflight_cap() -> int` (explicit `Config.FMG_MAX_INFLIGHT` wins, `0` means unlimited; else `8` when `fmg_metrics.role() == "collector"`, else `4`); `fmg_access.slot()` context manager that blocks on a process-wide `BoundedSemaphore(cap)` and yields the seconds waited (float); `fmg_access.peak_inflight() -> int`; the semaphore is created lazily and recreated by `reset()`.

- [ ] **Step 1: Write failing tests**: `test_cap_defaults_by_role` (monkeypatch role), `test_explicit_cap_overrides_role`, `test_zero_means_unlimited_and_slot_does_not_block`, `test_peak_never_exceeds_cap_under_100_threads` (cap 3, each holds the slot 5 ms, assert `peak_inflight() == 3`), `test_slot_released_after_exception` (raise inside `with slot()` 10 times with cap 1, an 11th call still gets in within 1 s), `test_slot_yields_wait_seconds` (second caller's wait > 0 while first holds it).
- [ ] **Step 2: Run** `pytest tests/test_fmg_access.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement** `inflight_cap`, `slot`, `peak_inflight` (counter guarded by a lock).
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): per-process FMG in-flight cap`.

### Task 3: Retry policy and wiring into `_post`

**Files:**
- Modify: `app/fmg_access.py`, `app/fmg_client.py` (`__init__`, `_post`, `__exit__`)
- Test: `tests/test_fmg_post_access_layer.py`

**Interfaces:**
- Consumes: Task 1 `get_session`, Task 2 `slot`.
- Produces: `fmg_access.backoff_delay(attempt: int) -> float` (attempt 1-based; base 0.5 s doubling, capped at 8 s, full jitter `uniform(0.5x, 1.0x)`); `fmg_access.is_retryable(method: str, exc: Exception | None, status: int | None) -> bool` per the Global Constraints; `FMGClient._http` is `fmg_access.get_session(verify_ssl)`; `__exit__` no longer calls `self._http.close()`; module-level `fmg_access.sleep = time.sleep` seam so tests do not wait.

- [ ] **Step 1: Write failing tests** using a fake session object (`post()` pops scripted outcomes: a response with `status_code`/`json()`, or an exception) injected as `client._http`:
  - `test_get_retried_on_503_then_succeeds` (503, 503, 200: 3 posts, success)
  - `test_get_gives_up_after_retries_and_raises` (503 x3 raises `requests.HTTPError`, exactly 3 posts)
  - `test_exec_not_retried_on_503` and `test_exec_not_retried_on_read_timeout` (1 post, raises)
  - `test_exec_retried_on_connection_error_before_response` (`requests.ConnectionError` then 200: 2 posts)
  - `test_get_retried_on_read_timeout`
  - `test_fmg_level_error_code_not_retried` (HTTP 200, `status.code=-11`: 1 post, returned)
  - `test_retries_zero_disables_retry`
  - `test_backoff_sleep_happens_outside_the_slot` (cap 1; while caller A sleeps in backoff, caller B completes a call; use the `sleep` seam to run B)
  - `test_backoff_delay_bounds` (attempt 1..5 within [0.25, 8.0], never above cap)
  - `test_exit_does_not_close_shared_session`
  - `test_inflight_zero_restores_unlimited_behaviour`
- [ ] **Step 2: Run** `pytest tests/test_fmg_post_access_layer.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** In `_post`, loop `attempt in 1..retries+1`; each attempt `with fmg_access.slot() as waited:` wrap only `self._http.post(...)` and `raise_for_status()`; on failure decide with `is_retryable`, sleep via `fmg_access.sleep(backoff_delay(attempt))` after leaving the slot; keep the existing `fmg_metrics.record` (one record per `_post` call, `ok` of the final outcome) and recorder call. Keep `timeout` semantics unchanged.
- [ ] **Step 4: Run** the new file plus `pytest tests/test_fmg_metrics.py tests/test_fmg_client*.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): retry with jittered backoff and slot-wrapped FMG round trips`.

### Task 4: Access counters on the Admin metrics view

**Files:**
- Modify: `app/fmg_metrics.py`, `app/routes/admin_routes.py`, `app/templates/admin.html`, `app/static/js/admin.js`
- Test: `tests/test_fmg_metrics.py`, `tests/test_admin_fmg_metrics.py`

**Interfaces:**
- Produces: `fmg_metrics.record_access(retries: int, wait_seconds: float, peak_inflight: int)` accumulating a per-process `access` dict `{retries, wait_seconds, peak_inflight, calls_waited}`; `snapshot()` includes `"access"`; `merge()` sums `retries`/`wait_seconds`/`calls_waited` and takes the max `peak_inflight`; `/admin/api/fmg-metrics` returns `access` per role and combined; the table shows one line "Retries / avg wait / peak in-flight" under the call table. `_post` calls `record_access` once per call.

- [ ] **Step 1: Write failing tests**: `test_record_access_accumulates`, `test_merge_sums_and_maxes_access`, `test_snapshot_contains_access_and_reset_clears_it`, `test_admin_endpoint_returns_access_block` (collector and web values both present).
- [ ] **Step 2: Run** the two test files. Expected: new tests FAIL.
- [ ] **Step 3: Implement** in `fmg_metrics.py`, wire `_post`, add the field to the admin route response and the JS/HTML line.
- [ ] **Step 4: Run** the two files. Expected: PASS.
- [ ] **Step 5: Commit** `feat(scale): surface retries, slot wait and peak in-flight on Admin`.

### Task 5: Auth warning, guard test, soak check, docs

**Files:**
- Modify: `app/__init__.py` (or the shared startup path used by both web and `app/collector.py`), `docs/deployment.md`, `.env.example`, `CLAUDE.md`
- Test: `tests/test_fmg_access_guard.py`

**Interfaces:**
- Produces: `fmg_access.warn_if_password_auth(logger) -> bool` (True and logs one WARNING when `Config.FMG_API_TOKEN` is empty, `Config.FMG_USERNAME` is set, and any of `INVENTORY_CACHE`/`POLICY_STORE`/`AUDIT_SNAPSHOTS`/`JOB_QUEUE` is on), called once at web and collector startup.

- [ ] **Step 1: Write failing tests**: `test_warns_for_password_auth_with_layer_on`, `test_silent_for_token_auth`, `test_silent_when_no_layer_flag_on`, and `test_no_direct_http_post_outside_post` (scan `app/**/*.py`: the only occurrence of `.post(` on an `_http`/session object in a code path that reaches FMG is inside `FMGClient._post`; allow-list `app/fmg_access.py`).
- [ ] **Step 2: Run** `pytest tests/test_fmg_access_guard.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `warn_if_password_auth` and call it from both startups.
- [ ] **Step 4: Verify on the rig script** (no new code): run `PYTHONPATH=. uv run python scripts/measure_fmg_baseline.py --devices 1000` and confirm total calls/hour is unchanged from the 3,887.8 baseline (F1 must not change call volume); run a 200-thread synthetic burst (inline in the test file as `test_burst_against_synthetic_fmg_respects_cap`) asserting `peak_inflight() <= cap`. Expected: counts equal, peak <= cap.
- [ ] **Step 5: Docs**: add `FMG_MAX_INFLIGHT` and `FMG_RETRIES` to the Scale settings table in `docs/deployment.md` and `.env.example`, a short "FMG access layer" paragraph in `CLAUDE.md` ("Scale foundations"), and a one-line note that unlimited (`0`) and retries off (`0`) are the rollback switches.
- [ ] **Step 6: Run the full suite** (bare `pytest`) and `uv run ruff check . && uv run ruff format --check .`. Expected: all pass, no lint errors.
- [ ] **Step 7: Commit** `feat(scale): FMG access layer warnings, guard test, docs`.

## Self-review notes

- Spec coverage: pooled session (T1/T3), per-process cap with role defaults (T2), retry/jittered backoff on 5xx/connection errors with the exec-safety restriction (T3), counters on Admin (T4), session-limit warning from the auth recommendation (T5), acceptance target 3 proved by peak-in-flight tests (T2/T5). Circuit breaker is deliberately skipped, as decided earlier.
- Not in this phase: any reduction in call volume (that is Phase 2 onward); the baseline must stay 3,887.8 calls/hour.
