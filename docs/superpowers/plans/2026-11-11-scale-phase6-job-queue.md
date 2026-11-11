# Phase 6: Job queue for long interactive actions (F6) Implementation Plan

> **For agentic workers:** execute inline, task by task, TDD (failing test, watch it fail, implement, pass). Ledger via `task-start`/`task-done`. Models: Sonnet only. Do not push or merge without the owner's say-so.

**Goal:** long interactive actions (Device Review run over a whole ADOM, Hygiene Analysis run) become server-side jobs that survive a closed tab, do not pin a web worker thread for minutes, and show progress, with results kept for 7 days. Flag `JOB_QUEUE` (default off, off = byte-for-byte legacy).

**Design source:** `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` section F6 and the Collector/Jobs notes (lines ~65, ~97, ~102).

## Decision for the owner to review

The spec says jobs run "in the collector or a bounded worker". Phase 5 already made Device Review a pure store read (200 devices in 0.09 s), so a Device Review **job** only matters when snapshots are off, when **Live** is ticked, or for the per-device live fallbacks. Options:

- **A (recommended): collector worker pool, results in the shared store.** Web enqueues and polls; the collector runs a bounded pool (default 2 jobs at a time). Fits the single-writer rule; survives web restarts and tab close.
- **B: web-process thread pool.** Simpler, but a gunicorn restart loses running jobs and each job pins a web thread (the problem being solved).
- **C: skip Device Review jobs, only Hygiene run + Live Device Review.** Smallest scope; least value now that snapshots exist.

Built as A. Which job kinds ship first is the second question: default **`device_review`** (only the Live / snapshots-off path does real work) and **`hygiene_run`** (runs `run_checks` over a package, seconds to minutes when `unhit` live overlay is on).

## Global Constraints

- Flag off or `live` path unchanged: with `JOB_QUEUE` off the existing endpoints and JS behave exactly as today.
- Web only enqueues and reads; the collector is the only executor and the only writer of job state, except that web writes the initial `queued` row and cancel requests (documented; both are single-row inserts/updates under `collector_store._lock`).
- Owner scoping: a job row stores `owner` (username), `adom`, and the request; a user reads only their own jobs, admin sees all; `check_adom_access(adom)` is re-applied on every read and on cancel (an ADOM removed from the user's group stops showing its jobs).
- Jobs run with the creator's ADOM scope captured at creation, never wider; the worker re-validates `adom` against the stored scope before running.
- Progress: `done`/`total` plus a short `message`; results are stored zlib-JSON, never returned from the list endpoint, only from the single-job endpoint.
- Cancel is cooperative (checked between devices/packages), owner or admin only; a cancelled job keeps partial results marked `cancelled`.
- Bounded: global running cap (`JOB_MAX_RUNNING`, default 2), per-user queued cap (`JOB_MAX_QUEUED_PER_USER`, default 5), result size cap (`JOB_MAX_RESULT_BYTES`, default 20 MB, over-cap results fail with a clear message).
- A job that was `running` when the collector died is marked `failed: collector restarted` at next start, never left running forever.
- Prune finished jobs and results after `JOB_RETENTION_DAYS` (7).
- No secrets in job rows: the stored request holds only parameters the UI sent (adom, checks, params), never tokens.
- Read-only application: jobs only run existing read-only checks.

## Review Focus

1. Owner/ADOM authorization on every job endpoint (IDOR: guessing another user's job id).
2. Crash recovery and stuck `running` rows; single-flight claim so two collector pools never run one job.
3. Flag-off identity for the two existing endpoints and the JS.
4. Result size and zlib handling; list endpoint never loads result blobs.
5. Cancel races (cancel after completion, double cancel).

## File Structure

- Create `app/job_store.py` (tables `job`, helpers: enqueue, claim, progress, finish, cancel, list_for, get, prune, recover_orphans); reuses `inventory_store._Conn`.
- Create `app/job_runner.py` (collector: bounded pool, claim loop, handler registry, recovery, pruning, `init_scheduler`); register in `start_all_schedulers` and `boot_warmup`.
- Create `app/job_handlers.py` (`device_review`, `hygiene_run`: pure functions `(request, progress, should_cancel) -> result`, reusing `bulk_device_review_adom` / `run_checks` code paths).
- Create `app/routes/job_routes.py` (blueprint `/api/jobs`): `POST /api/jobs`, `GET /api/jobs`, `GET /api/jobs/<id>`, `POST /api/jobs/<id>/cancel`.
- Modify `app/config.py`, `.env.example`, `app/__init__.py` (flag in template context), `audit_review.html`/`audit_review.js` and `hygiene` JS (submit as job, poll, resume from `localStorage` job id), `scripts/measure_fmg_baseline.py` (web-thread pinning is not an FMG-call metric, so only a small job smoke measure), docs.
- Tests: `tests/test_job_store.py`, `tests/test_job_runner.py`, `tests/test_job_handlers.py`, `tests/test_job_routes.py`, `tests/test_job_ui_hooks.py`.

## Tasks

### Task 1: Job store
Tables `job(id, kind, owner, adom, request_blob, status, done, total, message, created_at, started_at, finished_at, result_blob, error, cancel_requested)`; statuses `queued|running|done|failed|cancelled`. API: `enqueue` (enforces per-user cap), `claim_next` (atomic, one row), `progress`, `finish`, `fail`, `request_cancel`, `list_for(owner|None, adom_filter)`, `get`, `prune`, `recover_orphans`, size cap on `finish`. Tests: atomic single claim across two threads, caps, cancel race, orphan recovery, prune, list never returns blobs.

### Task 2: Handlers
`device_review` (wraps the per-device loop with progress and cancel checks; uses `audit_data`, so honours snapshots and `live`) and `hygiene_run`. Handlers are pure and tested against `SyntheticFMG` with equal output to the legacy endpoints.

### Task 3: Runner (collector)
Bounded pool, claim loop every 2 s, `recover_orphans` at start, hourly prune, handler exceptions become `failed` with a short message (no stack to the user), `boot_warmup` registration. Tests: concurrency cap respected, crash recovery, cancel between items, exception isolation.

### Task 4: Routes
Four endpoints, `login_required` + tab gate per kind (`audit_review` for both initially), `check_adom_access`, owner scoping, CSRF as other POSTs, 404 (not 403) for another user's job id, 503 when `JOB_QUEUE` off. Tests for every authorization path including an ADOM removed from the user's group.

### Task 5: UI
When the flag is on, Run Review and Run Analysis submit a job, show progress, and poll; the job id is kept in `localStorage` so a reloaded page resumes; a "Cancel" button; results render through the existing table code. Flag off: untouched code path. Tests: page hooks only when enabled, JS syntax check, flag-off identity.

### Task 6: Measure, docs, verification
Smoke measure (job latency, pool cap, result size), `docs/deployment.md` (settings, retention, restart behaviour, rollback), `CLAUDE.md` "Scale foundations", `docs/superpowers/measurements/2026-11-phase6-results.md`, full suite, ruff, one Sonnet whole-branch review and a fix pass with RED to GREEN tests.

## Self-review notes

- Spec coverage: F6 (jobs, progress polling, owner scoping, cancel, 7-day prune, collector executes, no new process).
- Builder's calls, challengeable: only two job kinds in this phase; cancel is cooperative; results stored in the shared SQLite file (a 20 MB cap protects it); 404 for foreign ids to avoid confirming a job exists.
- Not in this phase: Config-Delta bulk previews as jobs (already scheduled and gated), Rule Validation planner, any new FMG call reduction (this phase is about web-thread pinning and resilience, so it adds no FMG savings and the background floor is unchanged).
