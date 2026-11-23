# Config-Delta batched emails + run visibility Implementation Plan

> **For agentic workers:** use superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** Port `web/4thealth` commits `e38a5fe` (batched emails), `fea5dde` (persisted in-progress run record) and `ccfadfc` (changelog) into `develop`.

**Architecture:** Hand-merge into `app/config_diff_scheduler.py`; local code diverged (AI narrative, `_gate_counts`, ruff-strict UTC handling), so patches are adapted, not applied. AI summary + digest summary stay in Part 1 only.

**Tech Stack:** Flask, APScheduler, pytest, ruff, docker compose.

**Spec:** upstream commit messages `e38a5fe`, `fea5dde`.

## Global Constraints
- `batch_size`: devices per email, default 100, valid 1-500 (ValueError otherwise).
- Subject of later parts: `[Part N of M] <base subject>`; attachment filename gains `-partNofM`.
- No `datetime.utcnow()` (ruff DTZ003): use `datetime.datetime.now(datetime.UTC).replace(tzinfo=None)`.
- `config_diff_jobs.json` is already mounted into web + collector.

## Review Focus
- Exactly `batch_size` devices -> one email, no Part tag.
- Zero devices -> still one email.
- Part N send fails -> run `error`, earlier `emails_sent` retained.
- Lock held by another worker at startup -> `running` record untouched.
- Legacy jobs without `batch_size` -> default 100.

### Task 1: Batched emails (`e38a5fe`)
Files: `app/config_diff_scheduler.py`, `app/static/js/admin.js`, `app/templates/admin.html`, `tests/test_config_diff_scheduler.py`
- [ ] Add upstream tests (batch validation, small single email, 250 -> 3 parts, failed part).
- [ ] Add `_parse_batch_size`, `_chunk`, `part` param on `_build_attachment`; loop sends in `_execute_job`; admin form field.
- [ ] `uv run pytest tests/test_config_diff_scheduler.py`, ruff.

### Task 2: In-progress run record (`fea5dde`)
Files: same + `app/routes/admin_routes.py`
- [ ] Add upstream tests (running visible then updated in place, failure updates record, interrupted at startup, live lock left alone).
- [ ] Add `_now_iso`, `_start_run`, `_update_run`, `_mark_interrupted_runs`; call from `init_scheduler`; `/status` trusts persisted `running`; admin table RUNNING…/INTERRUPTED badges.

### Task 3: Docs + deploy
- [ ] CLAUDE.md Config-Delta scheduled jobs section, CHANGELOG entry if present.
- [ ] Full test + ruff, commit on `develop`, rebuild web + collector containers, verify.
