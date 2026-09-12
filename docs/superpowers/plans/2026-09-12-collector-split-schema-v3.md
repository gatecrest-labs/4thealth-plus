# Collector Process Split and Schema v3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate background collection from web request-serving so the executive summary is consistent across Gunicorn workers and survives container restarts, per `~/Documents/4thealth-notes/scale-review-1000-devices.md` sections C1/C2, without breaking any existing in-process (`RUN_SCHEDULERS=inline`) developer workflow.

**Architecture:** A single new entrypoint, `python -m app.collector`, starts every `BackgroundScheduler` job the app already has (via the existing per-module `init_scheduler(app)` functions — unchanged) by forcing `RUN_SCHEDULERS=inline` and calling the existing `create_app()` factory, then idling forever. `create_app()` itself gains one new gate: it only calls the (extracted, otherwise-unchanged) `start_all_schedulers(app)` function when `Config.RUN_SCHEDULERS == "inline"`. Every cache the executive-summary route reads gets a write-through/read-through layer backed by one new shared SQLite database (`collector_state.db`, WAL mode) via a new small module, `app/collector_store.py`: writers keep updating their existing in-memory dict exactly as today (so nothing regresses when running in the single-process `inline` mode) and additionally persist the same data to SQLite; readers keep reading the in-memory dict first, falling back to a SQLite read only when the in-memory value is still at its pending/never-populated default (i.e., a fresh worker that has never run a sweep itself) — an explicit read-through, not a replacement. `docker-compose.yml` splits into `web` (no schedulers) and `collector` (owns every job) services sharing one data volume. The executive summary payload gains `schema_version: 3` and a new `"freshness"` map; every v1/v2 key is kept unchanged (with one already-landed exception from the drill-down-lists plan, `psirt.top_advisory.devices`, which is unrelated to this plan).

**Tech Stack:** Python 3.14, Flask, `sqlite3` (stdlib, WAL mode), APScheduler (unchanged), pytest, ruff. No new dependencies.

**Spec:** `~/Downloads/4texecutive2.md` section "Wave 4", prompt W4-3 (P15) — 4thealth-plus only (the 4tlog and 4tExecutive thirds of that prompt are separate repos/sessions, out of scope here). Also read `~/Documents/4thealth-notes/scale-review-1000-devices.md` sections C1 ("Process model: duplicated schedulers and too few request threads") and C2 ("Five jobs re-download the same inventory") for the full rationale — C2's fix (a shared inventory cache) is explicitly **out of scope** for this plan; only C1's process-split fix is being built here.

## Global Constraints

- **Schema version:** this repo's `schema_version` is already `2` (shipped in PR #71, before this plan started — the original P15 prompt assumed it would still be `1`/`2` at this point, but it is not). This plan bumps it to **`3`**, purely additively — see Task 7. Do not skip the bump or reuse `2`.
- **No existing key changes shape or disappears.** Every currently-shipped field (v1 and v2) keeps exactly its current type and meaning after this plan. (The one type change in the whole Wave 4 effort — `psirt.top_advisory.devices` — belongs to the sibling drill-down-lists plan, not this one; if that plan hasn't merged yet when this one runs, don't worry about it.)
- **In-memory dicts are never removed**, only given a SQLite-backed fallback. `RUN_SCHEDULERS=inline` (the new default for anyone running the app outside the two-service Docker Compose setup — see Task 2) must reproduce **exactly today's behavior**: every sweep still updates its in-memory dict, every read still serves from that dict first.
- Every new SQLite write goes through the one shared module, `app/collector_store.py` (Task 1) — do not open ad hoc `sqlite3.connect()` calls in the individual cache modules for this feature; use `collector_store.write_snapshot()`/`read_snapshot()`.
- SQLite convention to follow (matches `app/ai_usage.py`/`app/host_metrics.py`/`app/psirt_store.py`, plus this plan's one addition — WAL mode): `_DB_PATH = Path(__file__).parent.parent / "<name>.db"`; a `_SCHEMA` string with `CREATE TABLE IF NOT EXISTS`; a private idempotent `_init_db()` run before every write/read; a short-lived `sqlite3.connect()` per call, closed in `finally:`; `conn.row_factory = sqlite3.Row` for reads; JSON-serialize nested structures into `TEXT` columns.
- Run `uv run pytest tests/ -v --tb=short` and `uv run ruff check app/ wsgi.py manage_users.py && uv run ruff format --check app/ wsgi.py manage_users.py` before each commit.
- Every commit message ends with:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
  ```

---

## Task 1: `app/collector_store.py` — shared SQLite snapshot store

**Files:**
- Create: `app/collector_store.py`
- Test: `tests/test_collector_store.py`

**Interfaces:**
- Produces: `write_snapshot(cache_key: str, payload: dict, collected_at: str | None = None) -> None`, `read_snapshot(cache_key: str) -> dict | None`. Every later task imports these two functions and nothing else from this module.

- [ ] **Step 1: Write the failing test**

Create `tests/test_collector_store.py`:

```python
import json

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Point collector_store at a throwaway DB file per test."""
    from app import collector_store

    db_path = tmp_path / "collector_state_test.db"
    monkeypatch.setattr(collector_store, "_DB_PATH", db_path)
    yield


def test_read_snapshot_missing_key_returns_none():
    from app.collector_store import read_snapshot

    assert read_snapshot("nope") is None


def test_write_then_read_snapshot_round_trips():
    from app.collector_store import read_snapshot, write_snapshot

    write_snapshot("device_review", {"devices_reviewed": 5}, collected_at="2026-09-12T00:00:00+00:00")

    result = read_snapshot("device_review")

    assert result == {"devices_reviewed": 5}


def test_write_snapshot_overwrites_previous_value_for_same_key():
    from app.collector_store import read_snapshot, write_snapshot

    write_snapshot("device_review", {"devices_reviewed": 5})
    write_snapshot("device_review", {"devices_reviewed": 9})

    assert read_snapshot("device_review") == {"devices_reviewed": 9}


def test_write_snapshot_is_wal_mode(tmp_path):
    from app import collector_store

    collector_store.write_snapshot("x", {"a": 1})
    conn = collector_store._connect()
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_collector_store.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'app.collector_store'`).

- [ ] **Step 3: Implement**

Create `app/collector_store.py`:

```python
"""Shared SQLite snapshot store for every cache the executive-summary
route reads, so the route stays consistent across Gunicorn web workers
and survives a container restart — see
~/Documents/4thealth-notes/scale-review-1000-devices.md section C1.

Each cache module keeps its own in-memory dict exactly as before (this
is a read-through/write-through addition, not a replacement) and calls
write_snapshot() every time it updates that dict; callers read the
in-memory value first and fall back to read_snapshot() only when the
in-memory value is still at its pending/never-populated default —
i.e. a fresh worker (RUN_SCHEDULERS != "inline") that has never run a
sweep itself, or a process that just restarted.

One key-value table, one row per named cache ("cache_key"), storing
that cache's latest snapshot as a JSON blob plus its own collected_at
(when the source data was produced) and updated_at (when this row was
last written) — no history, just "the latest known-good value."
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

_DB_PATH = Path(__file__).parent.parent / "collector_state.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache_snapshots (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    collected_at TEXT,
    updated_at TEXT NOT NULL
);
"""

_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    conn = _connect()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def write_snapshot(cache_key: str, payload: dict, collected_at: str | None = None) -> None:
    """Persist *payload* (JSON-serializable) as the latest snapshot for
    *cache_key*, replacing whatever was stored for that key before."""
    with _lock:
        _init_db()
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO cache_snapshots (cache_key, payload, collected_at, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(cache_key) DO UPDATE SET "
                "payload=excluded.payload, collected_at=excluded.collected_at, "
                "updated_at=excluded.updated_at",
                (
                    cache_key,
                    json.dumps(payload),
                    collected_at,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def read_snapshot(cache_key: str) -> dict | None:
    """Return the latest persisted payload for *cache_key*, or None if
    nothing has ever been written for it."""
    with _lock:
        _init_db()
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT payload FROM cache_snapshots WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        finally:
            conn.close()
    if row is None:
        return None
    return json.loads(row["payload"])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_collector_store.py -v`
Expected: PASS

- [ ] **Step 5: Add `collector_state.db` to `.gitignore`**

Check `.gitignore` for the existing `*.db` pattern (it already ignores `ai_usage.db`/`host_metrics.db`/`psirt.db` — likely via a `*.db` wildcard or explicit names). If it's an explicit name list rather than a wildcard, add `collector_state.db` to it.

- [ ] **Step 6: Commit**

```bash
git add app/collector_store.py tests/test_collector_store.py .gitignore
git commit -m "$(cat <<'EOF'
feat: add shared SQLite snapshot store for collector/web cache split

Foundation for the collector-process split: one WAL-mode SQLite table
(collector_state.db) that every cache the executive summary reads will
write its latest snapshot to, and read from as a fallback when its own
in-memory copy is empty.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 2: `RUN_SCHEDULERS` flag, `start_all_schedulers()` extraction, and `app/collector.py`

**Files:**
- Modify: `app/config.py`
- Modify: `app/__init__.py`
- Create: `app/collector.py`
- Test: `tests/test_scheduler_gating.py`

**Interfaces:**
- Produces: `Config.RUN_SCHEDULERS: str` (env `RUN_SCHEDULERS`, default `"off"`); `app._schedulers_enabled(config: dict) -> bool` (pure, takes anything with a `.get()` method — a Flask `app.config` or a plain dict); `app.start_all_schedulers(app: Flask) -> None` (the extracted, otherwise-verbatim body of the current 15 scheduler-init blocks); `python -m app.collector` as a standalone process entrypoint.

- [ ] **Step 1: Write the failing test for the gating logic**

Create `tests/test_scheduler_gating.py`:

```python
def test_schedulers_enabled_requires_inline_and_not_testing(monkeypatch):
    from app import _schedulers_enabled
    from app.config import Config

    monkeypatch.setattr(Config, "RUN_SCHEDULERS", "inline")
    assert _schedulers_enabled({"TESTING": False}) is True
    assert _schedulers_enabled({"TESTING": True}) is False

    monkeypatch.setattr(Config, "RUN_SCHEDULERS", "off")
    assert _schedulers_enabled({"TESTING": False}) is False
    assert _schedulers_enabled({"TESTING": True}) is False


def test_create_app_does_not_start_schedulers_by_default(monkeypatch):
    """RUN_SCHEDULERS defaults to "off" — create_app() must not call
    start_all_schedulers() unless a test/deployment explicitly opts in."""
    import app as app_module
    from app.config import Config

    monkeypatch.setattr(Config, "RUN_SCHEDULERS", "off")
    called = []
    monkeypatch.setattr(app_module, "start_all_schedulers", lambda a: called.append(a))

    app_module.create_app(test_config={"TESTING": False})

    assert called == []


def test_create_app_starts_schedulers_when_inline_and_not_testing(monkeypatch):
    import app as app_module
    from app.config import Config

    monkeypatch.setattr(Config, "RUN_SCHEDULERS", "inline")
    called = []
    monkeypatch.setattr(app_module, "start_all_schedulers", lambda a: called.append(a))

    created = app_module.create_app(test_config={"TESTING": False})

    assert called == [created]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_scheduler_gating.py -v`
Expected: FAIL (`ImportError: cannot import name '_schedulers_enabled' from 'app'`).

- [ ] **Step 3: Add the `RUN_SCHEDULERS` config flag**

In `app/config.py`, find the existing boolean-flag section (e.g. near `SNMP_ENABLED`/`RADIUS_ENABLED`) and add, following the plain-string (not `.lower()=="true"`) pattern since this flag has three meaningful values, not two:

```python
    # "inline" = start every BackgroundScheduler job in this same process
    # (the old, single-process behaviour — convenient for local dev and
    # for anyone not running the separate collector process). Anything
    # else (default "off") means this process starts NO schedulers and
    # expects `python -m app.collector` to be running separately. See
    # app/collector.py and docker-compose.yml's `collector` service.
    RUN_SCHEDULERS = os.environ.get("RUN_SCHEDULERS", "off").lower()
```

- [ ] **Step 4: Extract `start_all_schedulers()` and gate the call site in `app/__init__.py`**

In `app/__init__.py`, the scheduler-init section currently runs unconditionally as inline code inside `create_app()`, from the first `if not app.config.get("TESTING") and not app.config.get("_SUMMARY_STARTED"):` block through the last `_DEVICE_BACKUP_SCHEDULER_STARTED` block (currently the entire span between the `groups.KNOWN_TABS = registry.known_tabs()` line and the `@app.context_processor` decorator).

Cut that entire span out of `create_app()` and paste it, **unchanged, same indentation relative to a function body**, into a new module-level function placed directly above `def create_app(...)`:

```python
def _schedulers_enabled(config) -> bool:
    """True when this process should start every BackgroundScheduler job.

    config is anything with a dict-like .get() — normally a Flask app's
    .config, but tests pass a plain dict directly. Requires BOTH
    RUN_SCHEDULERS="inline" (see app/config.py) and TESTING not set,
    exactly like every individual scheduler guard used to check
    separately — this collapses those into one gate, checked once, at
    the single call site in create_app().
    """
    from app.config import Config

    return not config.get("TESTING") and Config.RUN_SCHEDULERS == "inline"


def start_all_schedulers(app: Flask) -> None:
    """Start every BackgroundScheduler job the app owns.

    Called from create_app() only when _schedulers_enabled() is True —
    i.e. RUN_SCHEDULERS=inline (the old single-process dev behaviour) or
    from app.collector.main(), which forces RUN_SCHEDULERS=inline before
    calling create_app(). Web workers in the split (default) deployment
    never call this at all.

    Each block below still carries its own app.config["_XXX_STARTED"]
    guard, unchanged from before this extraction — that guard now only
    protects against double-registration within a single process (e.g.
    Flask's debug-mode reloader), since the "should this process run
    schedulers at all" decision is made once, by the caller.
    """
    if not app.config.get("_SUMMARY_STARTED"):
        app.config["_SUMMARY_STARTED"] = True
        from app.summary_job import init_scheduler

        init_scheduler(app)

    # ... (every other block, verbatim, with the leading
    #      "not app.config.get('TESTING') and " clause removed from each
    #      condition since _schedulers_enabled() already covers it —
    #      see the note below)
```

Do this mechanically for **all 15** blocks (summary, versions_cache, adom_cache, map_cache, infra_health_cache, host_metrics, login_metrics, ai_usage, pending_status_cache, executive_summary_cache, config_diff_scheduler, device_review_scheduler, rule_hygiene_scheduler, backup_scheduler, psirt_reassess_scheduler, change_control_cache, device_backup_cache — 15 total per the current file): keep every block's body identical (including its own `try/except` wrapper where one exists, and its own `app.config["_XXX_STARTED"] = True` line), only removing the now-redundant `not app.config.get("TESTING") and ` prefix from each `if` condition so it reads e.g. `if not app.config.get("_VERSIONS_CACHE_STARTED"):` instead of `if not app.config.get("TESTING") and not app.config.get("_VERSIONS_CACHE_STARTED"):`.

Then, in `create_app()`, where that span used to be, put:

```python
    if _schedulers_enabled(app.config):
        start_all_schedulers(app)
```

Double-check nothing else in `create_app()` referenced any of the removed inline names — it shouldn't, since every block imports its own `init_scheduler` locally.

- [ ] **Step 5: Run the new tests**

Run: `uv run pytest tests/test_scheduler_gating.py -v`
Expected: PASS

- [ ] **Step 6: Run the full test suite to confirm nothing else broke**

Run: `uv run pytest tests/ -v --tb=short`
Expected: PASS. (Every existing test creates the app via `create_app(test_config={"TESTING": True})`, so `_schedulers_enabled` returns `False` regardless of `RUN_SCHEDULERS`, and `start_all_schedulers` is never called — behavior for the existing suite is unchanged.)

- [ ] **Step 7: Create the collector entrypoint**

Create `app/collector.py`:

```python
"""Collector process entrypoint — owns every BackgroundScheduler job.

Run as:

    python -m app.collector

This is the single process a split (default) deployment should run
separately from the Gunicorn web workers — see docker-compose.yml's
`collector` service and container.md. It reuses the exact same
create_app() factory the web process uses (so every scheduler module's
init_scheduler(app) call, and every Flask extension/config those
schedulers rely on via app.app_context(), works identically to today's
single-process mode) — the only difference is that this process forces
RUN_SCHEDULERS="inline" regardless of the deployment's own .env value,
so the schedulers start here even when the web service's own
RUN_SCHEDULERS is left at the split-mode default ("off").

The collector process does not serve HTTP. It has no gunicorn, no
bound port, nothing listening — it exists purely so the
BackgroundScheduler instances (and the daemon threads APScheduler's
executor pool spins up) stay alive. See
~/Documents/4thealth-notes/scale-review-1000-devices.md section C1 for
why this process split exists.
"""

from __future__ import annotations

import logging
import os
import time

# Must be set BEFORE `from app import create_app` triggers app.config's
# module-level `os.environ.get("RUN_SCHEDULERS", "off")` read.
os.environ["RUN_SCHEDULERS"] = "inline"

from app import create_app  # noqa: E402

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    logger.info(
        "collector: every BackgroundScheduler job started, entering idle loop"
    )
    with app.app_context():
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
```

- [ ] **Step 8: Add a smoke test that the module imports and wires `main` without starting real schedulers**

Add to `tests/test_scheduler_gating.py`:

```python
def test_collector_module_forces_run_schedulers_inline(monkeypatch):
    import os

    monkeypatch.delenv("RUN_SCHEDULERS", raising=False)
    import importlib

    import app.collector as collector_module

    importlib.reload(collector_module)

    assert os.environ["RUN_SCHEDULERS"] == "inline"
```

Do not call `collector_module.main()` in tests — it starts real schedulers and blocks forever. This test only confirms the module-level env-var side effect.

- [ ] **Step 9: Run tests**

Run: `uv run pytest tests/test_scheduler_gating.py -v`
Expected: PASS

- [ ] **Step 10: Add `RUN_SCHEDULERS` to `.env.example` (or wherever env vars are documented)**

Search for an `.env.example` file at the repo root; if it exists, add:

```
# "inline" runs every background sweep in this same process (old,
# single-process behaviour — simplest for local dev). Leave unset/"off"
# when running the separate `python -m app.collector` process (see
# docker-compose.yml and container.md).
RUN_SCHEDULERS=inline
```

If no `.env.example` exists, skip this step (check first with `ls .env.example`).

- [ ] **Step 11: Commit**

```bash
git add app/config.py app/__init__.py app/collector.py tests/test_scheduler_gating.py
git commit -m "$(cat <<'EOF'
feat: add RUN_SCHEDULERS flag, start_all_schedulers(), and app/collector.py

Web workers now start no schedulers by default (RUN_SCHEDULERS=off).
Set RUN_SCHEDULERS=inline to keep the old single-process dev behaviour,
or run `python -m app.collector` as a separate process — it forces
inline mode for itself and owns every scheduled job.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 3: `executive_summary_cache` — SQLite write-through + read-through

**Files:**
- Modify: `app/executive_summary_cache.py`
- Test: `tests/test_executive_summary_cache.py`

**Interfaces:**
- Consumes: `app.collector_store.write_snapshot`/`read_snapshot` (Task 1).
- Produces: `get_summary()`'s existing contract is unchanged (`dict`), but now transparently merges in SQLite-backed values for the device-sweep and hygiene-sweep field groups whenever the in-memory `_store` still shows those groups as never-populated (`device_sweep_status == "pending"` / `hygiene_sweep_status == "pending"`).

Two cache keys are used: `"executive_summary_device"` for every field `_run_device_sweep` writes into `_store`, and `"executive_summary_hygiene"` for every field `_run_hygiene_sweep` writes into `_store`. This mirrors the module's existing two-independent-sweeps design (see the module docstring) — a slow/failing hygiene sweep must not block the device sweep's SQLite write and vice versa.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_executive_summary_cache.py`:

```python
def test_get_summary_reads_device_sweep_from_sqlite_when_never_run_locally(
    monkeypatch, tmp_path
):
    """Simulates a fresh web worker: its own _store has never run a device
    sweep (still "pending"), but a collector process already wrote a
    snapshot to SQLite — get_summary() must surface that snapshot."""
    from app import collector_store, executive_summary_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    collector_store.write_snapshot(
        "executive_summary_device",
        {
            "firewall_online_count": 42,
            "firewalls_total": 50,
            "device_sweep_status": "ok",
            "device_sweep_collected_at": "2026-09-12T00:00:00+00:00",
        },
    )

    # This worker's own in-memory store has never run a sweep.
    assert executive_summary_cache._store["device_sweep_status"] == "pending"

    summary = executive_summary_cache.get_summary()

    assert summary["firewall_online_count"] == 42
    assert summary["firewalls_total"] == 50
    assert summary["device_sweep_status"] == "ok"


def test_get_summary_prefers_local_store_when_already_populated(monkeypatch, tmp_path):
    """Once THIS process has run its own sweep, its own value wins over
    whatever is in SQLite (e.g. an older snapshot from before this
    process's own most recent sweep)."""
    from app import collector_store, executive_summary_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    collector_store.write_snapshot(
        "executive_summary_device", {"firewall_online_count": 1}
    )

    with executive_summary_cache._lock:
        executive_summary_cache._store["device_sweep_status"] = "ok"
        executive_summary_cache._store["firewall_online_count"] = 999

    summary = executive_summary_cache.get_summary()

    assert summary["firewall_online_count"] == 999
```

Both tests must reset `_store` afterward (this module-level dict persists across tests in the same process) — add a fixture or explicit teardown. Check whether `tests/test_executive_summary_cache.py` already has a fixture resetting `_store` between tests (search for `autouse` or a `reset` helper); if one exists, use it. If not, add:

```python
@pytest.fixture(autouse=True)
def _reset_store():
    from app import executive_summary_cache

    original = dict(executive_summary_cache._store)
    yield
    with executive_summary_cache._lock:
        executive_summary_cache._store.clear()
        executive_summary_cache._store.update(original)
```

near the top of the file (import `pytest` if not already imported).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_executive_summary_cache.py -v -k sqlite`
Expected: FAIL (`KeyError`/`AssertionError` — `get_summary()` doesn't consult SQLite yet).

- [ ] **Step 3: Implement the write-through in both sweeps**

In `app/executive_summary_cache.py`, add the import near the top (with the other `from app...` imports, or as a local import matching this file's existing habit of importing inside functions — match whichever style the file already predominantly uses for its own intra-repo imports):

```python
from app import collector_store
```

In `_run_device_sweep`, immediately after the existing `with _lock: _store.update({...})` block that sets `"version_compliance_pct"`, `"devices_out_of_sync"`, `"by_adom"`, `"infra"`, etc. (the block ending with `return True` for that branch), add — still inside the `try:`, after releasing the lock (i.e. after the `with _lock:` block's own indentation ends), before `return True`:

```python
        collector_store.write_snapshot(
            "executive_summary_device",
            {
                k: v
                for k, v in _store.items()
                if k
                in {
                    "version_compliance_pct",
                    "pending_config_diff_count",
                    "firewall_online_count",
                    "firewalls_total",
                    "adom_count",
                    "status",
                    "last_updated",
                    "device_sweep_status",
                    "device_sweep_collected_at",
                    "devices_out_of_sync",
                    "devices_hw_eos",
                    "devices_hw_eos_12m",
                    "models_unknown",
                    "by_adom",
                    "infra",
                    "devices_silent",
                    "silent_devices_details",
                }
            },
            collected_at=_store.get("device_sweep_collected_at"),
        )
```

(If the drill-down-lists plan's Task 4 — `devices_silent`/`silent_devices_details` — hasn't been merged into this branch yet, drop those two keys from the set above; add them back once it has. Check with `grep -n "devices_silent" app/executive_summary_cache.py` before writing this step.)

Similarly, in `_run_hygiene_sweep`, immediately after its own `with _lock: _store.update({...})` block (the one setting `"hygiene_score"`, `"rule_count_total"`, `"rule_hygiene"`, `"hygiene_sweep_status"`, `"hygiene_sweep_collected_at"`), add:

```python
        collector_store.write_snapshot(
            "executive_summary_hygiene",
            {
                k: v
                for k, v in _store.items()
                if k
                in {
                    "hygiene_score",
                    "rule_count_total",
                    "rule_hygiene",
                    "hygiene_sweep_status",
                    "hygiene_sweep_collected_at",
                }
            },
            collected_at=_store.get("hygiene_sweep_collected_at"),
        )
```

Read the actual current end of each sweep function first (it may have log lines or other statements after the `_store.update()` call and before `return True`) and insert the snapshot write in the same place relative to the lock release — after the lock block, before the function returns.

- [ ] **Step 4: Implement the read-through in `get_summary()`**

Change:

```python
def get_summary() -> dict:
    """Return a copy of the current summary store (safe to serialise as JSON)."""
    with _lock:
        return dict(_store)
```

to:

```python
def get_summary() -> dict:
    """Return a copy of the current summary store (safe to serialise as JSON).

    Read-through: if THIS process has never completed its own device
    sweep and/or hygiene sweep (RUN_SCHEDULERS != "inline", i.e. a web
    worker in the split deployment — or a process that just restarted),
    fall back to the latest snapshot the collector process persisted to
    SQLite for that sweep. Once this process's own sweep has run, its
    own in-memory value always wins — this is a fallback for "nothing
    local yet," not a permanent alternate source of truth.
    """
    with _lock:
        local = dict(_store)

    if local.get("device_sweep_status") == "pending":
        snapshot = collector_store.read_snapshot("executive_summary_device")
        if snapshot:
            local.update(snapshot)

    if local.get("hygiene_sweep_status") == "pending":
        snapshot = collector_store.read_snapshot("executive_summary_hygiene")
        if snapshot:
            local.update(snapshot)

    return local
```

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_executive_summary_cache.py -v --tb=short`
Expected: PASS

- [ ] **Step 6: Run the full suite (guard against breaking existing sweep tests that assert exact `_store` contents post-sweep)**

Run: `uv run pytest tests/ -v --tb=short`
Expected: PASS. If an existing sweep test fails because it now also expects a `collector_store.write_snapshot` call to have hit a real file, check whether that test needs `tmp_path`/`monkeypatch` isolation for `collector_store._DB_PATH` (same as this task's own new tests) — add it if so, following Task 1's `_isolated_db` pattern.

- [ ] **Step 7: Commit**

```bash
git add app/executive_summary_cache.py tests/test_executive_summary_cache.py
git commit -m "$(cat <<'EOF'
feat: write-through/read-through executive_summary_cache via SQLite

Both sweeps now persist their result to collector_state.db right after
updating the in-memory store; get_summary() falls back to that
snapshot only when this process's own sweep has never run — a web
worker under the split deployment always serves the collector's latest
result instead of "pending" forever.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 4: `device_review_rollup`, `hygiene_rollup`, `change_control_cache` — move JSON-file persistence to SQLite

These three modules currently persist to `device_review_rollup.json`, `hygiene_rollup.json`, and `change_control.json` respectively (project-root JSON files, `atomic_write_json`). Per the spec these move to SQLite. Each module's public API (`get_history`/`get_latest`/`append_run` for the first two; `get_latest`/`_save` for the third) keeps its exact current signature and return shape — only the storage backend changes, via `collector_store`.

**Files:**
- Modify: `app/device_review_rollup.py`
- Modify: `app/hygiene_rollup.py`
- Modify: `app/change_control_cache.py`
- Test: `tests/test_device_review_rollup.py`
- Test: `tests/test_hygiene_rollup.py` (created in the drill-down-lists plan's Task 2 — if it doesn't exist yet in this branch, create it as a bare test file with just this task's tests)
- Test: `tests/test_change_control_cache.py`

**Interfaces:** unchanged — no other module's calls to `get_history()`/`get_latest()`/`append_run()`/`get_latest_by_adom()` need to change.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_device_review_rollup.py`:

```python
def test_history_persists_across_module_reload_via_sqlite(monkeypatch, tmp_path):
    """Two separate reads of get_history() (standing in for two separate
    app instances/processes) see the same data after one append_run() —
    proves persistence no longer depends on any in-memory list."""
    from app import collector_store, device_review_rollup

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    device_review_rollup.append_run({"ran_at": "t1", "adom": "root", "devices_reviewed": 1})

    # Simulate a second, independent reader by re-reading fresh — this
    # module keeps no in-memory list of its own, so a plain second call
    # already proves the data survived outside any Python-level cache.
    assert device_review_rollup.get_history() == [
        {"ran_at": "t1", "adom": "root", "devices_reviewed": 1}
    ]
    assert device_review_rollup.get_latest() == {
        "ran_at": "t1",
        "adom": "root",
        "devices_reviewed": 1,
    }


def test_history_caps_at_30_entries(monkeypatch, tmp_path):
    from app import collector_store, device_review_rollup

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    for i in range(35):
        device_review_rollup.append_run({"ran_at": f"t{i}", "adom": "root"})

    history = device_review_rollup.get_history()
    assert len(history) == 30
    assert history[0]["ran_at"] == "t34"  # newest first
```

Add analogous tests to `tests/test_hygiene_rollup.py` (same two shapes, using `hygiene_rollup.append_run`/`get_history`/`get_latest`).

Add to `tests/test_change_control_cache.py`:

```python
def test_get_latest_persists_via_sqlite_not_json_file(monkeypatch, tmp_path):
    from app import change_control_cache, collector_store

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    assert change_control_cache.get_latest() is None

    change_control_cache._save(
        {"admin_changes_24h": 3, "admin_changes_by_user": [], "collected_at": "t1"}
    )

    assert change_control_cache.get_latest() == {
        "admin_changes_24h": 3,
        "admin_changes_by_user": [],
        "collected_at": "t1",
    }
```

- [ ] **Step 2: Run tests to verify they fail (or pass vacuously against the old JSON-file backend, which won't be isolated by `tmp_path` monkeypatching `collector_store._DB_PATH` and will therefore pollute the real project-root files) — confirm by checking that no `collector_state.db`-backed data shows up yet:**

Run: `uv run pytest tests/test_device_review_rollup.py tests/test_hygiene_rollup.py tests/test_change_control_cache.py -v -k sqlite`
Expected: FAIL for the caps/round-trip assertions once the backend is swapped in Step 3 they should target SQLite; before Step 3 these tests may pass trivially by hitting the *old* JSON path (unaffected by the `collector_store._DB_PATH` monkeypatch) — that's fine, this is the acceptable "test doesn't yet prove the right thing" state; the meaningful check is Step 4 after the real swap.

- [ ] **Step 3: Implement the SQLite backend for `device_review_rollup.py`**

Replace the file-based `get_history`/`get_latest`/`append_run` trio:

```python
def get_history() -> list[dict]:
    """Return the rollup history, newest first, or [] if none exists yet."""
    if not _ROLLUP_PATH.exists():
        return []
    try:
        data = json.loads(_ROLLUP_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def get_latest() -> dict | None:
    """Return the most recent rollup record, or None if no history exists."""
    history = get_history()
    return history[0] if history else None


def append_run(record: dict) -> None:
    """Prepend a new rollup record, keeping at most _MAX_RUNS entries."""
    history = get_history()
    history.insert(0, record)
    atomic_write_json(_ROLLUP_PATH, history[:_MAX_RUNS])
```

with:

```python
_CACHE_KEY = "device_review_history"


def get_history() -> list[dict]:
    """Return the rollup history, newest first, or [] if none exists yet."""
    from app import collector_store

    snapshot = collector_store.read_snapshot(_CACHE_KEY)
    history = snapshot.get("history") if snapshot else None
    return history if isinstance(history, list) else []


def get_latest() -> dict | None:
    """Return the most recent rollup record, or None if no history exists."""
    history = get_history()
    return history[0] if history else None


def append_run(record: dict) -> None:
    """Prepend a new rollup record, keeping at most _MAX_RUNS entries."""
    from app import collector_store

    history = get_history()
    history.insert(0, record)
    history = history[:_MAX_RUNS]
    collector_store.write_snapshot(_CACHE_KEY, {"history": history})
```

Remove the now-unused `_ROLLUP_PATH`, `json` import, and `atomic_write_json` import if nothing else in the file uses them (check `get_latest_by_adom()` below — it calls `get_history()`, so it needs no change).

- [ ] **Step 4: Run the device_review_rollup tests**

Run: `uv run pytest tests/test_device_review_rollup.py -v --tb=short`
Expected: PASS

- [ ] **Step 5: Repeat Step 3's transformation for `app/hygiene_rollup.py`**

Same pattern, cache key `"hygiene_history"`:

```python
_CACHE_KEY = "hygiene_history"


def get_history() -> list[dict]:
    """Return the rollup history, newest first, or [] if none exists yet."""
    from app import collector_store

    snapshot = collector_store.read_snapshot(_CACHE_KEY)
    history = snapshot.get("history") if snapshot else None
    return history if isinstance(history, list) else []


def get_latest() -> dict | None:
    """Return the most recent rollup record, or None if no history exists."""
    history = get_history()
    return history[0] if history else None


def append_run(record: dict) -> None:
    """Prepend a new rollup record, keeping at most _MAX_RUNS entries."""
    from app import collector_store

    history = get_history()
    history.insert(0, record)
    history = history[:_MAX_RUNS]
    collector_store.write_snapshot(_CACHE_KEY, {"history": history})
```

Remove the now-unused `_ROLLUP_PATH`, `json`, `atomic_write_json` if this file has nothing else using them.

- [ ] **Step 6: Run the hygiene_rollup tests**

Run: `uv run pytest tests/test_hygiene_rollup.py -v --tb=short`
Expected: PASS

- [ ] **Step 7: Repeat for `app/change_control_cache.py`**

Replace:

```python
def get_latest() -> dict | None:
    """The last successfully persisted {admin_changes_24h,
    admin_changes_by_user, collected_at}, or None if no sweep has ever
    succeeded."""
    if not _STORE_PATH.exists():
        return None
    try:
        data = json.loads(_STORE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _save(record: dict) -> None:
    atomic_write_json(_STORE_PATH, record)
```

with:

```python
_CACHE_KEY = "change_control_latest"


def get_latest() -> dict | None:
    """The last successfully persisted {admin_changes_24h,
    admin_changes_by_user, collected_at}, or None if no sweep has ever
    succeeded."""
    from app import collector_store

    return collector_store.read_snapshot(_CACHE_KEY)


def _save(record: dict) -> None:
    from app import collector_store

    collector_store.write_snapshot(
        _CACHE_KEY, record, collected_at=record.get("collected_at")
    )
```

Remove the now-unused `_STORE_PATH`, `json`, `atomic_write_json` imports if nothing else in the file uses them.

- [ ] **Step 8: Run the change_control_cache tests**

Run: `uv run pytest tests/test_change_control_cache.py -v --tb=short`
Expected: PASS

- [ ] **Step 9: Run the full suite**

Run: `uv run pytest tests/ -v --tb=short`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add app/device_review_rollup.py app/hygiene_rollup.py app/change_control_cache.py tests/test_device_review_rollup.py tests/test_hygiene_rollup.py tests/test_change_control_cache.py
git commit -m "$(cat <<'EOF'
feat: move device_review/hygiene/change_control rollup persistence to SQLite

Replaces the per-module JSON-file-at-project-root pattern
(device_review_rollup.json, hygiene_rollup.json, change_control.json)
with the shared collector_state.db snapshot store. Public API
(get_history/get_latest/append_run) is unchanged.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 5: `pending_status_cache` — SQLite write-through/read-through for summary counts only

Per the spec, only the **summary counts** (`get_cache_status()`'s output) need to survive across workers/restarts — not the full per-ADOM device lists (which can be multi-MB per the scale-review's C2 finding; persisting those to SQLite would recreate the exact problem this plan is trying to avoid). `get_cached_devices()`/`get_all_cached_devices()` are unchanged and stay purely in-memory.

**Files:**
- Modify: `app/pending_status_cache.py`
- Test: `tests/test_pending_status_cache.py` (create if it doesn't exist — check with `ls tests/test_pending_status_cache.py` first)

**Interfaces:** `get_cache_status()` keeps its exact current return shape `{"status", "last_updated", "adoms_cached", "error"}`.

- [ ] **Step 1: Write the failing test**

Create (or append to) `tests/test_pending_status_cache.py`:

```python
def test_get_cache_status_reads_sqlite_when_local_state_never_ran(monkeypatch, tmp_path):
    from app import collector_store, pending_status_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    collector_store.write_snapshot(
        "pending_status_summary",
        {"status": "ok", "last_updated": "2026-09-12T00:00:00", "adoms_cached": 3, "error": None},
    )

    assert pending_status_cache._state["status"] == "pending"

    status = pending_status_cache.get_cache_status()

    assert status == {
        "status": "ok",
        "last_updated": "2026-09-12T00:00:00",
        "adoms_cached": 3,
        "error": None,
    }
```

Reset `pending_status_cache._state`/`_cache` after the test (add an autouse fixture mirroring Task 3's `_reset_store`, targeting `pending_status_cache._state` and `pending_status_cache._cache` instead).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pending_status_cache.py -v`
Expected: FAIL (`AssertionError` — `get_cache_status()` still returns the local "pending" state).

- [ ] **Step 3: Implement**

Change `get_cache_status()`:

```python
def get_cache_status() -> dict:
    """Return a snapshot of overall cache state."""
    with _lock:
        return {
            "status": _state["status"],
            "last_updated": _state["last_updated"],
            "adoms_cached": len(_cache),
            "error": _state.get("error"),
        }
```

to:

```python
def get_cache_status() -> dict:
    """Return a snapshot of overall cache state.

    Read-through: if THIS process has never completed its own refresh
    (RUN_SCHEDULERS != "inline"), falls back to the collector's latest
    persisted summary. Only the summary counts are persisted — the
    per-ADOM device lists (get_cached_devices/get_all_cached_devices)
    stay in-memory-only, since they can be multi-MB and this cache's
    consumers (the DIFF tab, executive summary's pending_config_diff
    aggregation) only need a fresh worker to answer "is the cache ready
    and how many ADOMs does it cover," not to re-derive the full device
    list without ever running its own refresh.
    """
    with _lock:
        local = {
            "status": _state["status"],
            "last_updated": _state["last_updated"],
            "adoms_cached": len(_cache),
            "error": _state.get("error"),
        }
    if local["status"] == "pending":
        from app import collector_store

        snapshot = collector_store.read_snapshot("pending_status_summary")
        if snapshot:
            return snapshot
    return local
```

Then, at the end of `_run_refresh` (the `try:` block's success path, right after `_state["status"] = "ok"` / `_state["last_updated"] = ts_done` / `_state["error"] = None` are set under `with _lock:`), add a write-through immediately after that `with _lock:` block:

```python
        from app import collector_store

        collector_store.write_snapshot(
            "pending_status_summary",
            {
                "status": "ok",
                "last_updated": ts_done,
                "adoms_cached": len(adom_names),
                "error": None,
            },
            collected_at=ts_done,
        )
```

Also add a write-through on the error path, in the `except Exception as exc:` block, right after `_state["status"] = "error"` / `_state["error"] = str(exc)` are set:

```python
        from app import collector_store

        collector_store.write_snapshot(
            "pending_status_summary",
            {
                "status": "error",
                "last_updated": _state["last_updated"],
                "adoms_cached": len(_cache),
                "error": str(exc),
            },
        )
```

(Read the surrounding lock/indentation carefully before inserting — both writes go *after* their respective `with _lock:` block ends, not inside it, matching Task 3's pattern of never holding the app's own lock while doing file/DB I/O.)

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_pending_status_cache.py -v --tb=short`
Expected: PASS

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest tests/ -v --tb=short`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/pending_status_cache.py tests/test_pending_status_cache.py
git commit -m "$(cat <<'EOF'
feat: write-through/read-through pending_status_cache summary via SQLite

Only get_cache_status()'s summary counts are persisted (status,
last_updated, adoms_cached, error) — the full per-ADOM device lists
stay in-memory-only to avoid re-creating the multi-MB-payload problem
from scale-review-1000-devices.md section C2.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 6: `infra_health_cache` — per-host SQLite write-through/read-through

**Files:**
- Modify: `app/infra_health_cache.py`
- Test: `tests/test_infra_health_cache.py`

**Interfaces:** `get_cached(host: str) -> dict | None` keeps its exact current signature/shape.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_infra_health_cache.py`:

```python
def test_get_cached_reads_sqlite_when_host_never_polled_locally(monkeypatch, tmp_path):
    from app import collector_store, infra_health_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    collector_store.write_snapshot(
        "infra_health:10.0.0.5",
        {"cpu": 12.0, "mem": 30.0, "snmp_status": "ok", "last_updated": "t1"},
    )

    assert infra_health_cache.get_cached("10.0.0.5") is None  # nothing local yet

    result = infra_health_cache.get_cached("10.0.0.5")

    assert result == {"cpu": 12.0, "mem": 30.0, "snmp_status": "ok", "last_updated": "t1"}
```

Note: the first `assert ... is None` line is deliberately checking pre-implementation behavior and will need to be removed once the read-through is implemented (since after Step 3, `get_cached` will find the SQLite snapshot on the very first call). Replace it before finalizing with just the second assertion, or drop the first line — the point is that a host with **no** local `_cache` entry still returns data because of the SQLite fallback.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_infra_health_cache.py -v -k sqlite`
Expected: FAIL (`AssertionError: None != {...}`).

- [ ] **Step 3: Implement**

Change `get_cached`:

```python
def get_cached(host: str) -> dict | None:
    """Return a shallow copy of the cached entry for host, or None if not cached."""
    with _lock:
        entry = _cache.get(host)
        return dict(entry) if entry is not None else None
```

to:

```python
def get_cached(host: str) -> dict | None:
    """Return a shallow copy of the cached entry for host, or None if not
    cached locally or in the collector's shared SQLite snapshot store."""
    with _lock:
        entry = _cache.get(host)
        if entry is not None:
            return dict(entry)

    from app import collector_store

    return collector_store.read_snapshot(f"infra_health:{host}")
```

Change `poll_all_targets`:

```python
def poll_all_targets() -> None:
    """Poll every SNMP-supported target in Config.INFRA_TARGETS and update the cache."""
    if not Config.SNMP_ENABLED:
        return
    for target in Config.INFRA_TARGETS:
        if target.get("type", "").lower() not in _SUPPORTED_TYPES:
            continue
        host = target.get("host")
        if not host:
            continue
        result = _poll_target(target)
        if result is None:
            continue
        with _lock:
            _cache[host] = result
```

to:

```python
def poll_all_targets() -> None:
    """Poll every SNMP-supported target in Config.INFRA_TARGETS and update the cache."""
    if not Config.SNMP_ENABLED:
        return
    from app import collector_store

    for target in Config.INFRA_TARGETS:
        if target.get("type", "").lower() not in _SUPPORTED_TYPES:
            continue
        host = target.get("host")
        if not host:
            continue
        result = _poll_target(target)
        if result is None:
            continue
        with _lock:
            _cache[host] = result
        collector_store.write_snapshot(
            f"infra_health:{host}", result, collected_at=result.get("last_updated")
        )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_infra_health_cache.py -v --tb=short`
Expected: PASS

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest tests/ -v --tb=short`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/infra_health_cache.py tests/test_infra_health_cache.py
git commit -m "$(cat <<'EOF'
feat: write-through/read-through infra_health_cache per host via SQLite

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 7: `schema_version: 3`, `freshness` map, and docs

`psirt` (via `app.psirt_store`, which already reads `psirt.db` directly on every call — no in-memory cache exists for it at all) and `lifecycle` (derived entirely from the device-sweep group already covered by Task 3) need no code change for the SQLite requirement — only documentation confirming they already satisfy it.

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Modify: `docs/api-reference.md`
- Modify: `docs/features.md`
- Test: `tests/test_external_api_executive.py`

**Interfaces:** payload gains `"schema_version": 3` (was `2`) and a new top-level `"freshness": dict[str, str | None]` key. No existing key is removed or changes shape (except the unrelated `psirt.top_advisory.devices` change from the sibling drill-down-lists plan, if merged).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_external_api_executive.py`:

```python
def test_executive_summary_schema_version_is_3(client, app_ctx):
    resp = client.get(
        "/external/api/executive/summary",
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.get_json()["schema_version"] == 3


def test_executive_summary_freshness_map_covers_every_group(client, app_ctx):
    resp = client.get(
        "/external/api/executive/summary",
        headers={"Authorization": "Bearer test-token"},
    )
    body = resp.get_json()
    freshness = body["freshness"]
    for group in (
        "device_review",
        "rule_hygiene",
        "version_breakdown",
        "psirt",
        "change_control",
        "lifecycle",
        "infra",
        "pending_status",
    ):
        assert group in freshness, f"missing freshness entry for {group!r}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_external_api_executive.py -v -k "schema_version_is_3 or freshness_map"`
Expected: FAIL (`schema_version == 2`, `KeyError: 'freshness'`).

- [ ] **Step 3: Implement**

In `app/routes/external_api_routes.py`'s `ext_executive_summary()`, change `"schema_version": 2,` to `"schema_version": 3,`.

Add a new helper near the other payload helpers:

```python
def _freshness(payload: dict, summary: dict) -> dict:
    """When each rollup's underlying data was actually collected — the
    preferred way to check staleness as of schema_version 3. Every v1/v2
    per-object "collected_at" (or "ran_at"-derived "collected_at") field
    is kept for backward compatibility; this map is just a single place
    to check all of them without knowing which nested object each one
    lives in.
    """
    from app.pending_status_cache import get_cache_status

    device_review = payload.get("device_review") or {}
    rule_hygiene = payload.get("rule_hygiene") or {}
    psirt = payload.get("psirt") or {}
    change_control = payload.get("change_control") or {}
    lifecycle = payload.get("lifecycle") or {}

    return {
        "device_review": device_review.get("collected_at"),
        "rule_hygiene": rule_hygiene.get("collected_at"),
        "version_breakdown": summary.get("device_sweep_collected_at"),
        "silent_devices": summary.get("device_sweep_collected_at"),
        "psirt": psirt.get("collected_at"),
        "change_control": change_control.get("collected_at"),
        "lifecycle": lifecycle.get("collected_at"),
        "infra": summary.get("device_sweep_collected_at"),
        "pending_status": get_cache_status().get("last_updated"),
    }
```

(If `silent_devices` isn't part of the payload yet in this branch — i.e. the drill-down-lists plan's Task 4 hasn't merged — drop that one key; check with `grep -n '"silent_devices"' app/routes/external_api_routes.py` first.)

Then in `ext_executive_summary()`, after the `payload = {...}` dict literal is fully assembled (after its closing `}`, before the `ai_enabled = ...` line), add:

```python
    payload["freshness"] = _freshness(payload, summary)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_external_api_executive.py -v --tb=short`
Expected: PASS

- [ ] **Step 5: Run the full suite (guard against any test asserting `schema_version == 2` elsewhere)**

Run: `grep -rn "schema_version" tests/ docs/`

Update any test or doc example still hardcoding `2` as the expected/example value for this endpoint (leave alone any reference to `psirt`'s own internal PSIRT-store versioning if that's a separate, unrelated `schema_version` concept — check context before changing).

Run: `uv run pytest tests/ -v --tb=short`
Expected: PASS

- [ ] **Step 6: Update `docs/api-reference.md`**

Update the `/external/api/executive/summary` row/section to note `schema_version: 3` and add:

```markdown
### Freshness map (schema_version 3+)

`freshness` is a flat map of `{field_group: collected_at}` covering every
rollup in the payload — the preferred way to check staleness, instead of
digging into each nested object's own `collected_at`/`ran_at` field.
Every v1/v2 per-object timestamp field listed below is kept for this
release as a **deprecated alias** — do not remove them yet, but new
integrations should read `freshness` instead:

| `freshness` key | Deprecated v1/v2 alias |
|---|---|
| `device_review` | `device_review.collected_at` |
| `rule_hygiene` | `rule_hygiene.collected_at` |
| `version_breakdown` | `device_sweep_collected_at` (top-level) |
| `silent_devices` | `silent_devices.collected_at` |
| `psirt` | `psirt.collected_at` |
| `change_control` | `change_control.collected_at` |
| `lifecycle` | `lifecycle.collected_at` |
| `infra` | `device_sweep_collected_at` (top-level) |
| `pending_status` | *(no prior alias — new in schema_version 3)* |
```

- [ ] **Step 7: Update `docs/features.md`**

Add a short paragraph under the Executive Summary Endpoint section describing the collector/web process split (pointing to `container.md` for deployment detail) and the `freshness` map, and bump the documented `schema_version` example from `2` to `3` in every JSON example in that section.

- [ ] **Step 8: Commit**

```bash
git add app/routes/external_api_routes.py docs/api-reference.md docs/features.md tests/test_external_api_executive.py
git commit -m "$(cat <<'EOF'
feat: bump executive summary to schema_version 3, add freshness map

freshness is a flat {field_group: collected_at} map covering every
rollup. Every v1/v2 field is kept as a documented deprecated alias.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 8: `docker-compose.yml`, `Dockerfile`, `container.md`, `docs/deployment.md`/`docs/operations.md`

**Files:**
- Modify: `docker-compose.yml`
- Modify: `Dockerfile` (comment only — see below; the CMD itself doesn't need to change)
- Modify: `container.md`
- Modify: `docs/deployment.md`
- Modify: `docs/operations.md`

- [ ] **Step 1: Split `docker-compose.yml` into `web` and `collector` services**

Replace the single `app:` service with `web:` and `collector:`, both building the same image, sharing every data-file volume mount (so both processes see the same JSON/SQLite files), and only `web` publishing a port / running a healthcheck:

```yaml
services:
  test-smtp:
    image: mailhog/mailhog
    container_name: test-smtp
    restart: unless-stopped
    ports:
      - "1025:1025"
      - "8025:8025"

  web:
    build: .
    image: 4thealth-plus:latest
    container_name: 4thealth-plus-web
    restart: unless-stopped
    # Two workers is safe again now that the executive summary and every
    # other cache it reads read through to collector_state.db (SQLite,
    # WAL mode) instead of relying on this process's own in-memory copy
    # — see app/collector_store.py and
    # ~/Documents/4thealth-notes/scale-review-1000-devices.md section
    # C1. This service starts NO schedulers (RUN_SCHEDULERS defaults to
    # "off" — see the `collector` service below).
    command: >
      gunicorn --workers 2 --threads 4 --worker-class gthread
      --bind 0.0.0.0:8100 --timeout 120 --worker-tmp-dir /dev/shm
      --certfile certs/cert.pem --keyfile certs/key.pem
      --access-logfile - --error-logfile - wsgi:app
    ports:
      - "8100:8100"
    env_file:
      - .env
    volumes:
      - ./users.json:/app/users.json:rw
      - ./groups.json:/app/groups.json:rw
      - ./infra_targets.json:/app/infra_targets.json:ro
      - ./policy_db.json:/app/policy_db.json:rw
      - ./naming.yaml:/app/naming.yaml:ro
      - ./review_requirements.yaml:/app/review_requirements.yaml:ro
      - ./ai_usage.db:/app/ai_usage.db:rw
      - ./host_metrics.db:/app/host_metrics.db:rw
      - ./psirt.db:/app/psirt.db:rw
      - ./collector_state.db:/app/collector_state.db:rw
      - ./app_settings.json:/app/app_settings.json:rw
      - ./api_tokens.json:/app/api_tokens.json:rw
      - ./smtp_config.json:/app/smtp_config.json:rw
      - ./config_diff_jobs.json:/app/config_diff_jobs.json:rw
      - ./device_review_jobs.json:/app/device_review_jobs.json:rw
      - ./rule_hygiene_jobs.json:/app/rule_hygiene_jobs.json:rw
      - ./summary_history.json:/app/summary_history.json:rw
      - ./certs:/app/certs:ro
    healthcheck:
      test:
        - CMD
        - python3
        - -c
        - "import urllib.request, ssl; urllib.request.urlopen('https://localhost:8100/login', context=ssl._create_unverified_context(), timeout=5)"
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s

  collector:
    build: .
    image: 4thealth-plus:latest
    container_name: 4thealth-plus-collector
    restart: unless-stopped
    command: ["python", "-m", "app.collector"]
    env_file:
      - .env
    volumes:
      - ./users.json:/app/users.json:rw
      - ./groups.json:/app/groups.json:rw
      - ./infra_targets.json:/app/infra_targets.json:ro
      - ./policy_db.json:/app/policy_db.json:rw
      - ./naming.yaml:/app/naming.yaml:ro
      - ./review_requirements.yaml:/app/review_requirements.yaml:ro
      - ./ai_usage.db:/app/ai_usage.db:rw
      - ./host_metrics.db:/app/host_metrics.db:rw
      - ./psirt.db:/app/psirt.db:rw
      - ./collector_state.db:/app/collector_state.db:rw
      - ./app_settings.json:/app/app_settings.json:rw
      - ./api_tokens.json:/app/api_tokens.json:rw
      - ./smtp_config.json:/app/smtp_config.json:rw
      - ./config_diff_jobs.json:/app/config_diff_jobs.json:rw
      - ./device_review_jobs.json:/app/device_review_jobs.json:rw
      - ./rule_hygiene_jobs.json:/app/rule_hygiene_jobs.json:rw
      - ./summary_history.json:/app/summary_history.json:rw
      - ./certs:/app/certs:ro
```

Note `device_review_rollup.json`/`hygiene_rollup.json`/`change_control.json` are removed from both volume lists — Task 4 moved that persistence into `collector_state.db`, which is already mounted. Confirm no other code path in the repo still reads those three JSON files directly (`grep -rn "device_review_rollup.json\|hygiene_rollup.json\|change_control.json" app/`) before removing the mounts; if anything else still reads them directly, keep the mounts and flag it in the commit message as a follow-up.

Also confirm whether `.env`/`.env.example` needs `RUN_SCHEDULERS=off` made explicit for `web` — since Task 2 made `"off"` the default when the env var is entirely unset, it's fine to leave both services' `env_file: .env` as-is and let `collector`'s own hardcoded `os.environ["RUN_SCHEDULERS"] = "inline"` (set inside `app/collector.py` itself, Task 2 Step 7) override whatever `.env` says for that one process — no compose-level `environment:` override is needed for either service.

- [ ] **Step 2: Add a one-line comment to the `Dockerfile`**

Above the `CMD [...]` line, add:

```dockerfile
# Default CMD serves the web process. The collector process overrides
# this at the docker-compose/run level with:
#   command: ["python", "-m", "app.collector"]
# See docker-compose.yml and container.md.
```

- [ ] **Step 3: Update `container.md`**

Under `## Option A — Single Container (current architecture, recommended now)`, add a new subsection right after `### Step 3 — Create docker-compose.yml` (or replace/annotate that step) explaining the two-service split: `web` (Gunicorn, no schedulers) and `collector` (`python -m app.collector`, owns every scheduled job), both built from the same image and sharing the same data-file volumes so they see each other's writes (JSON files and the three SQLite databases). Note that `Option A` is no longer strictly "single container" after this change — retitle it if the doc's heading now reads oddly (e.g. to "Option A — Docker Compose (recommended now)"), and cross-reference `~/Documents/4thealth-notes/scale-review-1000-devices.md` section C1 for why the split exists. Also update the `### Step 6 — Build and start` instructions to mention both services (`docker compose up -d` still starts both; `docker compose logs -f collector` for scheduler activity, `docker compose logs -f web` for request traffic).

- [ ] **Step 4: Update `docs/deployment.md`**

Under `## Phase 2 — Application Deployment`, `### 2.6` (the systemd service section), add a parallel `python -m app.collector` systemd unit example (same `WorkingDirectory`/`User`/`EnvironmentFile` pattern as the existing web unit, different `ExecStart`), and a note that `RUN_SCHEDULERS` must be `inline` for a single-process bare-metal deployment that doesn't want to run a separate collector unit — pointing back to `container.md` for the two-service pattern this doc's systemd approach mirrors.

- [ ] **Step 5: Update `docs/operations.md`**

Under `## Monitoring the Background Summary Job`, add a note that in the split deployment, the collector process (not the web workers) runs every scheduled sweep, and its logs (systemd `journalctl -u <collector-unit>` or `docker compose logs collector`) are now the place to look for scheduler activity, not the web process's logs.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml Dockerfile container.md docs/deployment.md docs/operations.md
git commit -m "$(cat <<'EOF'
docs+compose: split web/collector services sharing the data volume

web runs Gunicorn with RUN_SCHEDULERS unset (off) and no schedulers;
collector runs `python -m app.collector` and owns every scheduled job.
Both share the same JSON/SQLite data files.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 9: Cross-cutting integration tests and final verification

**Files:**
- Test: `tests/test_collector_split_integration.py` (new)

- [ ] **Step 1: Write an integration test proving "two app instances see the same value after one collector write"**

Create `tests/test_collector_split_integration.py`:

```python
"""Integration coverage for the collector/web split: a web worker that
has never run its own sweep must serve whatever the collector last
wrote to SQLite, and two independent readers must agree."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    from app import collector_store

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "shared.db")
    yield


def test_route_reads_from_sqlite_when_in_memory_cache_is_empty(client, app_ctx):
    """Simulates a freshly started web worker under the split deployment:
    executive_summary_cache._store is still at its pending defaults, but
    the collector already wrote a device-sweep snapshot."""
    from app import collector_store, executive_summary_cache

    with executive_summary_cache._lock:
        assert executive_summary_cache._store["device_sweep_status"] == "pending"

    collector_store.write_snapshot(
        "executive_summary_device",
        {
            "firewall_online_count": 7,
            "firewalls_total": 10,
            "adom_count": 2,
            "device_sweep_status": "ok",
            "device_sweep_collected_at": "2026-09-12T00:00:00+00:00",
        },
    )

    resp = client.get(
        "/external/api/executive/summary",
        headers={"Authorization": "Bearer test-token"},
    )
    body = resp.get_json()

    assert body["firewall_online_count"] == 7
    assert body["firewalls_total"] == 10
    assert body["adom_count"] == 2


def test_two_independent_readers_agree_after_one_collector_write(monkeypatch, tmp_path):
    """Simulates two separate app instances/processes (e.g. two Gunicorn
    workers) both reading get_summary() after one write — since neither
    has run its own sweep, both must read the same SQLite snapshot."""
    from app import collector_store, executive_summary_cache

    collector_store.write_snapshot(
        "executive_summary_device",
        {"firewall_online_count": 3, "device_sweep_status": "ok"},
    )

    with executive_summary_cache._lock:
        executive_summary_cache._store["device_sweep_status"] = "pending"

    reader_one = executive_summary_cache.get_summary()

    with executive_summary_cache._lock:
        executive_summary_cache._store["device_sweep_status"] = "pending"

    reader_two = executive_summary_cache.get_summary()

    assert reader_one["firewall_online_count"] == 3
    assert reader_two["firewall_online_count"] == 3
```

Match this file's `client`/`app_ctx` fixtures to whatever `tests/test_external_api_executive.py` already defines/imports (reuse via a shared conftest fixture if one exists after Task 1-8's work added any, otherwise duplicate the minimal client-setup boilerplate from that file).

- [ ] **Step 2: Run test to verify it fails before this plan's earlier tasks, passes after**

Run: `uv run pytest tests/test_collector_split_integration.py -v --tb=short`
Expected: PASS (this test should already pass at this point in the plan, since Task 3 implemented the underlying behavior — this task exists to give the two specific spec-mandated scenarios their own named, obviously-spec-traceable test, not to introduce new implementation).

- [ ] **Step 3: Commit**

```bash
git add tests/test_collector_split_integration.py
git commit -m "$(cat <<'EOF'
test: add collector/web split integration coverage

Explicit tests for the two spec-mandated scenarios: the route reads
from SQLite when the in-memory cache is empty, and two independent
readers see the same value after one collector write.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

- [ ] **Step 4: Final verification**

Run the full suite and linter:

```bash
uv run pytest tests/ -v --tb=short
uv run ruff check app/ wsgi.py manage_users.py
uv run ruff format --check app/ wsgi.py manage_users.py
```

All must pass clean. Then manually sanity-check the split works end to end (optional but recommended if Docker is available locally):

```bash
docker compose build
docker compose up -d web collector
docker compose logs collector --tail 50   # confirm "schedulers started" / individual scheduler start-up log lines
curl -sk https://localhost:8100/external/api/executive/summary -H "Authorization: Bearer <a real token>" | python3 -m json.tool
docker compose down
```

If Docker isn't available in this environment, skip the manual check and note it in the final report as unverified (not a blocker — the unit/integration test suite covers the behavior that matters).
