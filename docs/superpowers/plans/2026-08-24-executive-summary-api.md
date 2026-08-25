# Executive Summary API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `GET /external/api/executive/summary` to 4thealth-plus so 4tExecutive can poll fleet-wide metrics (hygiene score, version compliance, pending config diffs, firewall online count) over the existing bearer-token external API.

**Architecture:** A new background-refreshed cache module (`app/executive_summary_cache.py`), following the same pattern as `summary_job.py`/`versions_cache.py`/`pending_status_cache.py`, computes the four metrics on an APScheduler interval and stores them in memory. The new route reads that store instantly — no live FortiManager call happens inside the request. Aggregation math is split into small pure functions so it's unit-testable without mocking FortiManager at all.

**Tech Stack:** Flask, APScheduler (already a dependency), pytest, existing `FMGClient` (`app/fmg_client.py`).

**Spec:** [docs/superpowers/specs/2026-08-24-executive-summary-api-design.md](../specs/2026-08-24-executive-summary-api-design.md)

## Global Constraints

- No live FortiManager calls inside the request handler — the route only reads an in-memory store (spec decision 1).
- `hygiene_score` sweep uses only these checks: `unnamed`, `unlogged`, `disabled`, `expired`, `unhit` — `shadow` is explicitly excluded (spec decision 5).
- `version_compliance_pct` is `null` when no `executive_compliant_versions` are configured — never a fabricated heuristic (spec decision 3).
- `last_backup_status` is not part of the response payload at all (spec decision, Context section).
- New scheduler env var: `EXEC_SUMMARY_REFRESH_MINUTES`, default `15` (spec decision 6).
- All new/modified files follow the existing lock-guarded-snapshot pattern already used by `versions_cache.py` / `pending_status_cache.py` (copy-on-read, never leak internal references).

---

### Task 1: `pending_status_cache.py` — add cross-ADOM accessor

**Files:**
- Modify: `app/pending_status_cache.py` (add a function near `get_cached_devices`, ~line 41)
- Test: `tests/test_pending_status_cache.py` (append)

**Interfaces:**
- Produces: `get_all_cached_devices() -> dict[str, list[dict]]` — snapshot of every cached ADOM's device list, keyed by ADOM name. Used by Task 4.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_pending_status_cache.py`:

```python
def test_get_all_cached_devices_returns_empty_dict_when_empty():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)
    assert mod.get_all_cached_devices() == {}


def test_get_all_cached_devices_returns_snapshot_across_adoms():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)

    with mod._lock:
        mod._cache["ADOM1"] = {
            "devices": [{"name": "FW1", "conf_status": "outofsync"}],
            "last_updated": "2026-07-17T01:00:00",
        }
        mod._cache["ADOM2"] = {
            "devices": [{"name": "FW2", "conf_status": "insync"}],
            "last_updated": "2026-07-17T01:00:00",
        }

    result = mod.get_all_cached_devices()
    assert result == {
        "ADOM1": [{"name": "FW1", "conf_status": "outofsync"}],
        "ADOM2": [{"name": "FW2", "conf_status": "insync"}],
    }


def test_get_all_cached_devices_returns_copies_not_references():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)

    with mod._lock:
        mod._cache["ADOM1"] = {
            "devices": [{"name": "FW1"}],
            "last_updated": "2026-07-17T01:00:00",
        }

    result = mod.get_all_cached_devices()
    result["ADOM1"].append({"name": "INJECTED"})
    assert len(mod._cache["ADOM1"]["devices"]) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_pending_status_cache.py -v -k get_all_cached_devices`
Expected: FAIL with `AttributeError: module 'app.pending_status_cache' has no attribute 'get_all_cached_devices'`

- [ ] **Step 3: Implement**

In `app/pending_status_cache.py`, add directly below `get_cached_devices`:

```python
def get_all_cached_devices() -> dict[str, list[dict]]:
    """Return a snapshot of every cached ADOM's device list, keyed by ADOM name."""
    with _lock:
        return {adom: list(entry["devices"]) for adom, entry in _cache.items()}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_pending_status_cache.py -v`
Expected: PASS (all tests, including the pre-existing ones)

- [ ] **Step 5: Commit**

```bash
cd /Users/alanw/code/github/ai/4thealth-plus
git add app/pending_status_cache.py tests/test_pending_status_cache.py
git commit -m "feat: add get_all_cached_devices() to pending_status_cache"
```

---

### Task 2: `app_settings.py` — add `executive_compliant_versions` default

**Files:**
- Modify: `app/app_settings.py:13` (`_DEFAULTS` dict)
- Test: `tests/test_app_settings.py` — check if it exists first; if not, add assertions inline in Task 6's test file instead (see note in Task 6)

**Interfaces:**
- Produces: `get_setting("executive_compliant_versions", [])` returns `[]` by default; `list[str]` after being set. Used by Task 4 and Task 6.

- [ ] **Step 1: Check for an existing settings test file**

Run: `ls /Users/alanw/code/github/ai/4thealth-plus/tests/test_app_settings.py 2>/dev/null || echo "no dedicated file"`

If it exists, add the test from Step 2 there. If not, skip straight to Step 3 (implementation) — the default will be exercised by Task 6's admin-route tests instead, so no dedicated test file is needed for a one-line dict addition.

- [ ] **Step 2 (only if `tests/test_app_settings.py` exists): Write the failing test**

```python
def test_executive_compliant_versions_defaults_to_empty_list():
    import importlib
    import app.app_settings as mod
    importlib.reload(mod)
    assert mod.get_setting("executive_compliant_versions") == []
```

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_app_settings.py -v -k executive_compliant`
Expected: FAIL — default returns `None`, not `[]`

- [ ] **Step 3: Implement**

In `app/app_settings.py`, change:

```python
_DEFAULTS: dict = {
    "external_api_enabled": False,
    "ai_assist_enabled": False,
}
```

to:

```python
_DEFAULTS: dict = {
    "external_api_enabled": False,
    "ai_assist_enabled": False,
    "executive_compliant_versions": [],
}
```

- [ ] **Step 4: Run test(s) to verify**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_app_settings.py -v` (if the file exists), otherwise skip — verified in Task 6.

- [ ] **Step 5: Commit**

```bash
cd /Users/alanw/code/github/ai/4thealth-plus
git add app/app_settings.py
git commit -m "feat: add executive_compliant_versions setting default"
```

---

### Task 3: `app/executive_summary_cache.py` — pure aggregation functions

**Files:**
- Create: `app/executive_summary_cache.py`
- Test: `tests/test_executive_summary_cache.py`

**Interfaces:**
- Consumes: nothing (pure functions, no imports from other new code)
- Produces (used by Task 4):
  - `_classify_online(devices: list[dict]) -> tuple[int, int]` — `(online_count, total_count)`; a device counts as online when `d.get("conn_status") == 1`.
  - `_version_compliance_pct(devices: list[dict], compliant_versions: list[str]) -> float | None` — `None` if `compliant_versions` is empty or `devices` is empty; else `round(100 * compliant / total, 1)`.
  - `_pending_diff_count(devices_by_adom: dict[str, list[dict]]) -> int` — counts devices where `conf_status == "outofsync"` or `db_status == "modified"` or `pkg_status == "modified"`.
  - `_hygiene_score(total_findings: int, total_policies: int) -> float | None` — `None` if `total_policies == 0`; else `round(clamp(100 * (1 - total_findings/total_policies), 0, 100), 1)`.
  - `_device_version(d: dict) -> str` — same formatting logic as the equivalent inline code in `versions_cache.py`/`pending_status_cache.py` (`vMAJOR.MR.PATCH`, falling back to `vMAJOR.MR` or `"n/a"`).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_executive_summary_cache.py`:

```python
"""Unit tests for the pure aggregation functions in app.executive_summary_cache."""
import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from app.executive_summary_cache import (
    _classify_online,
    _device_version,
    _hygiene_score,
    _pending_diff_count,
    _version_compliance_pct,
)


# ── _classify_online ────────────────────────────────────────────────────────

def test_classify_online_counts_conn_status_1_as_online():
    devices = [
        {"name": "FW1", "conn_status": 1},
        {"name": "FW2", "conn_status": 1},
        {"name": "FW3", "conn_status": 0},
    ]
    assert _classify_online(devices) == (2, 3)


def test_classify_online_empty_list():
    assert _classify_online([]) == (0, 0)


# ── _version_compliance_pct ─────────────────────────────────────────────────

def test_version_compliance_pct_none_when_no_target_versions():
    devices = [{"version": "v7.4.3"}]
    assert _version_compliance_pct(devices, []) is None


def test_version_compliance_pct_none_when_no_devices():
    assert _version_compliance_pct([], ["v7.4.3"]) is None


def test_version_compliance_pct_computes_percentage():
    devices = [
        {"version": "v7.4.3"},
        {"version": "v7.4.3"},
        {"version": "v7.2.1"},
        {"version": "v7.6.2"},
    ]
    assert _version_compliance_pct(devices, ["v7.4.3", "v7.6.2"]) == 75.0


# ── _pending_diff_count ──────────────────────────────────────────────────────

def test_pending_diff_count_zero_when_all_in_sync():
    devices_by_adom = {
        "ADOM1": [{"conf_status": "insync", "db_status": "nomod", "pkg_status": "nomod"}],
    }
    assert _pending_diff_count(devices_by_adom) == 0


def test_pending_diff_count_counts_outofsync():
    devices_by_adom = {
        "ADOM1": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}],
    }
    assert _pending_diff_count(devices_by_adom) == 1


def test_pending_diff_count_counts_modified_db_or_pkg():
    devices_by_adom = {
        "ADOM1": [
            {"conf_status": "insync", "db_status": "modified", "pkg_status": "nomod"},
            {"conf_status": "insync", "db_status": "nomod", "pkg_status": "modified"},
        ],
    }
    assert _pending_diff_count(devices_by_adom) == 2


def test_pending_diff_count_sums_across_adoms():
    devices_by_adom = {
        "ADOM1": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}],
        "ADOM2": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}],
    }
    assert _pending_diff_count(devices_by_adom) == 2


def test_pending_diff_count_does_not_double_count_one_device():
    devices_by_adom = {
        "ADOM1": [{"conf_status": "outofsync", "db_status": "modified", "pkg_status": "modified"}],
    }
    assert _pending_diff_count(devices_by_adom) == 1


# ── _hygiene_score ───────────────────────────────────────────────────────────

def test_hygiene_score_none_when_no_policies():
    assert _hygiene_score(total_findings=0, total_policies=0) is None


def test_hygiene_score_100_when_no_findings():
    assert _hygiene_score(total_findings=0, total_policies=50) == 100.0


def test_hygiene_score_computes_density():
    assert _hygiene_score(total_findings=10, total_policies=50) == 80.0


def test_hygiene_score_clamped_to_zero_when_findings_exceed_policies():
    # A policy can trigger more than one check, so findings can outnumber policies.
    assert _hygiene_score(total_findings=200, total_policies=50) == 0.0


# ── _device_version ──────────────────────────────────────────────────────────

def test_device_version_major_mr_patch():
    assert _device_version({"os_ver": 700, "mr": 4, "patch": 3}) == "v7.4.3"


def test_device_version_major_mr_only():
    assert _device_version({"os_ver": 700, "mr": 6, "patch": None}) == "v7.6"


def test_device_version_unknown():
    assert _device_version({"os_ver": 0, "mr": None, "patch": None}) == "n/a"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_executive_summary_cache.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.executive_summary_cache'`

- [ ] **Step 3: Implement the pure functions**

Create `app/executive_summary_cache.py`:

```python
"""Background cache for the executive-summary external API endpoint.

Runs a periodic sweep (default every EXEC_SUMMARY_REFRESH_MINUTES=15 minutes)
across every non-forti* ADOM, computing four fleet-wide metrics from a
single per-ADOM device list plus a per-ADOM policy sweep:

  - firewall_online_count / firewalls_total  (device conn_status)
  - version_compliance_pct                   (device version vs. an admin-
                                                configured target list)
  - pending_config_diff_count                (aggregated from the existing
                                                pending_status_cache)
  - hygiene_score                            (findings-density across a
                                                restricted, cheap check set)

Results are held in _store and served instantly by
GET /external/api/executive/summary. See docs/superpowers/specs/
2026-08-24-executive-summary-api-design.md for the full rationale.
"""

from __future__ import annotations

import logging
import os
import threading
import time as _time
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# Only checks that need no live per-device/per-object lookups — see spec
# decision 5. "shadow" is deliberately excluded (needs addr/svc resolvers).
_HYGIENE_CHECKS = ["unnamed", "unlogged", "disabled", "expired", "unhit"]

_store: dict = {
    "hygiene_score": None,
    "version_compliance_pct": None,
    "pending_config_diff_count": None,
    "firewall_online_count": None,
    "firewalls_total": None,
    "status": "pending",  # pending | running | ok | error
    "error": None,
    "last_updated": None,
}

_lock = threading.Lock()
_running = threading.Event()


def get_summary() -> dict:
    """Return a copy of the current summary store (safe to serialise as JSON)."""
    with _lock:
        return dict(_store)


# ── Pure aggregation helpers (no I/O — unit-tested directly) ──────────────────


def _classify_online(devices: list[dict]) -> tuple[int, int]:
    """Return (online_count, total_count) from a flat device list."""
    total = len(devices)
    online = sum(1 for d in devices if d.get("conn_status") == 1)
    return online, total


def _version_compliance_pct(
    devices: list[dict], compliant_versions: list[str]
) -> float | None:
    if not compliant_versions or not devices:
        return None
    total = len(devices)
    compliant = sum(1 for d in devices if d.get("version") in compliant_versions)
    return round(100 * compliant / total, 1)


def _pending_diff_count(devices_by_adom: dict[str, list[dict]]) -> int:
    count = 0
    for devices in devices_by_adom.values():
        for d in devices:
            if (
                d.get("conf_status") == "outofsync"
                or d.get("db_status") == "modified"
                or d.get("pkg_status") == "modified"
            ):
                count += 1
    return count


def _hygiene_score(total_findings: int, total_policies: int) -> float | None:
    if total_policies == 0:
        return None
    score = 100 * (1 - total_findings / total_policies)
    return round(max(0.0, min(100.0, score)), 1)


def _device_version(d: dict) -> str:
    """Format a device's firmware version — mirrors versions_cache.py's inline logic."""
    os_ver = d.get("os_ver", 0)
    mr = d.get("mr")
    patch = d.get("patch")
    major = (
        int(os_ver) // 100
        if str(os_ver).isdigit() and int(os_ver) >= 100
        else os_ver
    )
    if mr is not None and patch is not None and int(patch) >= 0:
        return f"v{major}.{mr}.{patch}"
    if mr is not None:
        return f"v{major}.{mr}"
    return "n/a"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_executive_summary_cache.py -v`
Expected: PASS (18 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/alanw/code/github/ai/4thealth-plus
git add app/executive_summary_cache.py tests/test_executive_summary_cache.py
git commit -m "feat: add executive summary aggregation functions"
```

---

### Task 4: `app/executive_summary_cache.py` — FMG sweep, scheduler, app-factory wiring

**Files:**
- Modify: `app/executive_summary_cache.py` (append `_run_job`, `refresh_now`, `init_scheduler`)
- Modify: `app/__init__.py` (register the scheduler, after the `_PENDING_STATUS_CACHE_STARTED` block, ~line 141)
- Test: `tests/test_executive_summary_cache.py` (append `_run_job` integration test with a fully mocked FMG client)

**Interfaces:**
- Consumes: `_classify_online`, `_version_compliance_pct`, `_pending_diff_count`, `_hygiene_score`, `_device_version` (Task 3); `get_all_cached_devices()` (Task 1); `app.app_settings.get_setting` (Task 2); `app.hygiene.run_checks` (existing); `app.fmg_helpers.make_client` (existing).
- Produces: `_run_job(app)`, `refresh_now(app)`, `init_scheduler(app)` — same signatures as `versions_cache.py`'s equivalents. Used by Task 5 (route reads `get_summary()`) and by `app/__init__.py`.

- [ ] **Step 1: Write the failing integration test**

Append to `tests/test_executive_summary_cache.py`:

```python
# ── _run_job (mocked FMG client) ────────────────────────────────────────────

from unittest.mock import MagicMock, patch

import app.executive_summary_cache as cache_mod


@pytest.fixture(autouse=True)
def _reset_store():
    with cache_mod._lock:
        cache_mod._store.update({
            "hygiene_score": None,
            "version_compliance_pct": None,
            "pending_config_diff_count": None,
            "firewall_online_count": None,
            "firewalls_total": None,
            "status": "pending",
            "error": None,
            "last_updated": None,
        })
    yield


def _fake_client():
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}, {"name": "FortiForticloud"}]
    client.get_devices.return_value = [
        {"name": "FW1", "conn_status": 1, "os_ver": 700, "mr": 4, "patch": 3},
        {"name": "FW2", "conn_status": 0, "os_ver": 700, "mr": 4, "patch": 3},
    ]
    client.get_policy_packages.return_value = [{"path": "default", "name": "default"}]
    client.get_policies.return_value = [
        {"policyid": 1, "name": "", "status": 1, "logtraffic": 0},  # unnamed + unlogged
        {"policyid": 2, "name": "allow-web", "status": 1, "logtraffic": 2},
    ]
    return client


def test_run_job_populates_store_from_mocked_fmg(monkeypatch, app_ctx):
    monkeypatch.setattr(
        "app.app_settings.get_setting",
        lambda key, default=None: ["v7.4.3"] if key == "executive_compliant_versions" else default,
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_all_cached_devices",
        lambda: {"Customer1": [{"conf_status": "outofsync", "db_status": "nomod", "pkg_status": "nomod"}]},
    )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_job(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["status"] == "ok"
    assert summary["firewalls_total"] == 2
    assert summary["firewall_online_count"] == 1
    assert summary["version_compliance_pct"] == 100.0  # both devices are v7.4.3
    assert summary["pending_config_diff_count"] == 1
    assert summary["hygiene_score"] is not None
    assert summary["last_updated"] is not None


def test_run_job_only_counts_non_forti_adoms(monkeypatch, app_ctx):
    monkeypatch.setattr(
        "app.app_settings.get_setting", lambda key, default=None: default
    )
    monkeypatch.setattr(
        "app.pending_status_cache.get_all_cached_devices", lambda: {}
    )

    fake_client = _fake_client()
    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        cache_mod._run_job(app_ctx)

    # get_devices/get_policy_packages must only be called for "Customer1",
    # not "FortiForticloud"
    assert fake_client.get_devices.call_count == 1
    fake_client.get_devices.assert_called_with("Customer1")


def test_run_job_sets_error_status_on_exception(monkeypatch, app_ctx):
    with patch("app.fmg_helpers.make_client", side_effect=RuntimeError("boom")):
        cache_mod._run_job(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["status"] == "error"
    assert "boom" in summary["error"]
```

Add the `app_ctx` fixture at the top of the file if not already present (it lives in `conftest.py` but is not autouse — import it explicitly is unnecessary since pytest fixtures from `conftest.py` are auto-discovered for any test file in `tests/`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_executive_summary_cache.py -v -k run_job`
Expected: FAIL — `AttributeError: module 'app.executive_summary_cache' has no attribute '_run_job'`

- [ ] **Step 3: Implement**

Append to `app/executive_summary_cache.py`:

```python
# ── FMG sweep ───────────────────────────────────────────────────────────────


def _run_job(app) -> None:
    """Sweep every non-forti* ADOM and refresh the summary store."""
    if _running.is_set():
        logger.info("executive_summary_cache: already running, skipping overlap")
        return

    _running.set()
    with _lock:
        _store["status"] = "running"
        _store["error"] = None

    logger.info("executive_summary_cache: starting refresh")
    t0 = _time.monotonic()

    try:
        from app.app_settings import get_setting
        from app.fmg_helpers import make_client
        from app.hygiene import run_checks
        from app.pending_status_cache import get_all_cached_devices

        devices_flat: list[dict] = []
        total_findings = 0
        total_policies = 0

        with make_client() as client:
            adoms_raw = client.get_adoms()
            adom_names = [
                a.get("name", "")
                for a in adoms_raw
                if isinstance(a, dict)
                and a.get("name")
                and not a.get("name", "").lower().startswith("forti")
            ]

            for adom in adom_names:
                try:
                    raw = client.get_devices(adom)
                except Exception as exc:
                    logger.warning(
                        "executive_summary_cache: get_devices(%s) failed: %s", adom, exc
                    )
                    raw = []
                for d in raw:
                    if not isinstance(d, dict):
                        continue
                    devices_flat.append(
                        {
                            "name": d.get("name", ""),
                            "version": _device_version(d),
                            "conn_status": d.get("conn_status"),
                        }
                    )

                try:
                    packages = client.get_policy_packages(adom)
                except Exception as exc:
                    logger.warning(
                        "executive_summary_cache: get_policy_packages(%s) failed: %s",
                        adom,
                        exc,
                    )
                    continue
                for pkg in packages:
                    pkg_path = pkg.get("path", pkg.get("name", ""))
                    if not pkg_path:
                        continue
                    try:
                        policies = client.get_policies(adom, pkg_path)
                    except Exception as exc:
                        logger.warning(
                            "executive_summary_cache: get_policies(%s, %s) failed: %s",
                            adom,
                            pkg_path,
                            exc,
                        )
                        continue
                    total_policies += len(policies)
                    total_findings += len(run_checks(policies, _HYGIENE_CHECKS))

        online, total = _classify_online(devices_flat)
        compliant_versions = get_setting("executive_compliant_versions", [])
        compliance_pct = _version_compliance_pct(devices_flat, compliant_versions)
        pending_count = _pending_diff_count(get_all_cached_devices())
        hygiene_score = _hygiene_score(total_findings, total_policies)

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "executive_summary_cache: done in %ss — %d/%d online, "
            "compliance=%s, pending=%d, hygiene=%s",
            elapsed,
            online,
            total,
            compliance_pct,
            pending_count,
            hygiene_score,
        )

        with _lock:
            _store.update(
                {
                    "hygiene_score": hygiene_score,
                    "version_compliance_pct": compliance_pct,
                    "pending_config_diff_count": pending_count,
                    "firewall_online_count": online,
                    "firewalls_total": total,
                    "status": "ok",
                    "error": None,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )

    except Exception as exc:
        logger.exception("executive_summary_cache: unhandled error")
        with _lock:
            _store["status"] = "error"
            _store["error"] = str(exc)
    finally:
        _running.clear()


def refresh_now(app) -> None:
    """Trigger an immediate background refresh (non-blocking)."""
    t = threading.Thread(
        target=_run_job, args=[app], name="executive_summary_cache_refresh", daemon=True
    )
    t.start()


def init_scheduler(app):
    """Start the refresh scheduler and fire an initial warm-up immediately."""
    from apscheduler.schedulers.background import BackgroundScheduler

    interval_min = int(os.environ.get("EXEC_SUMMARY_REFRESH_MINUTES", "15"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_job,
        args=[app],
        trigger="interval",
        minutes=interval_min,
        id="executive_summary_refresh",
        name="Executive summary cache refresh",
    )
    scheduler.start()
    logger.info(
        "executive_summary_cache: scheduler started — every %d minutes", interval_min
    )

    t = threading.Thread(
        target=_run_job, args=[app], name="executive_summary_cache_startup", daemon=True
    )
    t.start()

    return scheduler
```

Then in `app/__init__.py`, add this block directly after the `_PENDING_STATUS_CACHE_STARTED` block (after line ~140):

```python
    if not app.config.get("TESTING") and not app.config.get(
        "_EXEC_SUMMARY_CACHE_STARTED"
    ):
        app.config["_EXEC_SUMMARY_CACHE_STARTED"] = True
        from app.executive_summary_cache import (
            init_scheduler as init_exec_summary_scheduler,
        )

        init_exec_summary_scheduler(app)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_executive_summary_cache.py -v`
Expected: PASS (all tests from Task 3 and Task 4)

- [ ] **Step 5: Run the full test suite to check for regressions**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest -q`
Expected: PASS, no new failures

- [ ] **Step 6: Commit**

```bash
cd /Users/alanw/code/github/ai/4thealth-plus
git add app/executive_summary_cache.py app/__init__.py tests/test_executive_summary_cache.py
git commit -m "feat: wire executive summary background sweep and scheduler"
```

---

### Task 5: `GET /external/api/executive/summary` route

**Files:**
- Modify: `app/routes/external_api_routes.py` (add route + update module docstring's endpoint list)
- Test: `tests/test_external_api_executive.py` (new)

**Interfaces:**
- Consumes: `get_summary()` from Task 4; existing `_gate()` helper in the same file.
- Produces: `GET /external/api/executive/summary` — 503 if disabled, 401 if unauthorized, 200 with the summary JSON otherwise.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_external_api_executive.py`:

```python
"""Tests for GET /external/api/executive/summary."""
import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import patch

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app(test_config={"TESTING": True})
    with app.test_client() as c:
        yield c


def test_returns_503_when_feature_disabled(client):
    with patch("app.routes.external_api_routes.get_setting", return_value=False):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer whatever"},
        )
    assert resp.status_code == 503


def test_returns_401_when_no_token(client):
    with patch("app.routes.external_api_routes.get_setting", return_value=True):
        resp = client.get("/external/api/executive/summary")
    assert resp.status_code == 401


def test_returns_401_when_invalid_token(client):
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch("app.routes.external_api_routes.validate_token", return_value=None),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer bad-token"},
        )
    assert resp.status_code == 401


def test_returns_summary_payload_when_authorized(client):
    fake_summary = {
        "hygiene_score": 87.3,
        "version_compliance_pct": 91.2,
        "pending_config_diff_count": 4,
        "firewall_online_count": 212,
        "firewalls_total": 218,
        "status": "ok",
        "error": None,
        "last_updated": "2026-08-24T15:00:00+00:00",
    }
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch(
            "app.executive_summary_cache.get_summary", return_value=fake_summary
        ),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["hygiene_score"] == 87.3
    assert data["firewall_online_count"] == 212
    assert "last_backup_status" not in data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_external_api_executive.py -v`
Expected: FAIL — 404 on all requests (route doesn't exist yet)

- [ ] **Step 3: Implement**

In `app/routes/external_api_routes.py`, update the module docstring's endpoint list (near line 16-20) to add:

```
  GET  /external/api/executive/summary  Fleet-wide metrics for the 4tExecutive dashboard
```

Then add the route at the end of the file:

```python
# ── Executive summary ────────────────────────────────────────────────────────


@bp.route("/executive/summary")
def ext_executive_summary():
    err = _gate()
    if err:
        return err

    from app.executive_summary_cache import get_summary

    summary = get_summary()
    return jsonify(
        {
            "hygiene_score": summary.get("hygiene_score"),
            "version_compliance_pct": summary.get("version_compliance_pct"),
            "pending_config_diff_count": summary.get("pending_config_diff_count"),
            "firewall_online_count": summary.get("firewall_online_count"),
            "firewalls_total": summary.get("firewalls_total"),
            "status": summary.get("status"),
            "last_updated": summary.get("last_updated"),
        }
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_external_api_executive.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/alanw/code/github/ai/4thealth-plus
git add app/routes/external_api_routes.py tests/test_external_api_executive.py
git commit -m "feat: add GET /external/api/executive/summary route"
```

---

### Task 6: Admin API — `executive_compliant_versions` setting

**Files:**
- Modify: `app/routes/admin_routes.py` (`api_settings_put`, ~line 278-291)
- Test: `tests/test_admin_ai_assist_setting.py` (append — it already covers `/admin/api/settings`, no need for a new file)

**Interfaces:**
- Consumes: `set_setting`/`get_all_settings` from `app.app_settings` (already imported in `admin_routes.py`).
- Produces: `PUT /admin/api/settings` accepts `executive_compliant_versions` as either a `list[str]` or a newline/comma-separated `str`; always normalized and stored as `list[str]`. `GET /admin/api/settings` includes it via the existing `get_all_settings()` passthrough — no change needed there.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_admin_ai_assist_setting.py`:

```python
def test_settings_get_includes_executive_compliant_versions(admin_client):
    resp = admin_client.get("/admin/api/settings")
    assert resp.status_code == 200
    assert "executive_compliant_versions" in resp.get_json()


def test_settings_put_accepts_list_of_versions(admin_client):
    with patch("app.routes.admin_routes.set_setting") as mock_set:
        resp = admin_client.put(
            "/admin/api/settings",
            json={"executive_compliant_versions": ["v7.4.3", "v7.6.2"]},
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    mock_set.assert_any_call(
        "executive_compliant_versions", ["v7.4.3", "v7.6.2"]
    )


def test_settings_put_splits_comma_and_newline_separated_string(admin_client):
    with patch("app.routes.admin_routes.set_setting") as mock_set:
        resp = admin_client.put(
            "/admin/api/settings",
            json={"executive_compliant_versions": "v7.4.3,\nv7.6.2, v7.6.3"},
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    mock_set.assert_any_call(
        "executive_compliant_versions", ["v7.4.3", "v7.6.2", "v7.6.3"]
    )


def test_settings_put_empty_string_clears_versions(admin_client):
    with patch("app.routes.admin_routes.set_setting") as mock_set:
        resp = admin_client.put(
            "/admin/api/settings",
            json={"executive_compliant_versions": ""},
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    mock_set.assert_any_call("executive_compliant_versions", [])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_admin_ai_assist_setting.py -v -k executive_compliant`
Expected: FAIL — `assert False` on the `get` test (key missing) and `AssertionError` on the `put` tests (mock never called with that key)

- [ ] **Step 3: Implement**

In `app/routes/admin_routes.py`, check the top-of-file imports for `re`:

Run: `grep -n "^import re" app/routes/admin_routes.py`

If it prints nothing, add `import re` to the imports block at the top of the file.

Then in `api_settings_put` (the function containing the `external_api_enabled`/`ai_assist_enabled` blocks), add:

```python
    if "executive_compliant_versions" in data:
        versions = data["executive_compliant_versions"]
        if isinstance(versions, str):
            versions = [v.strip() for v in re.split(r"[\n,]+", versions) if v.strip()]
        elif isinstance(versions, list):
            versions = [str(v).strip() for v in versions if str(v).strip()]
        else:
            versions = []
        set_setting("executive_compliant_versions", versions)
        app_log(
            "INFO",
            "admin",
            "Executive compliant versions updated",
            by=session["user"],
            count=len(versions),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && uv run pytest tests/test_admin_ai_assist_setting.py -v`
Expected: PASS (all tests in the file, old and new)

- [ ] **Step 5: Commit**

```bash
cd /Users/alanw/code/github/ai/4thealth-plus
git add app/routes/admin_routes.py tests/test_admin_ai_assist_setting.py
git commit -m "feat: accept executive_compliant_versions in admin settings API"
```

---

### Task 7: Admin UI — compliant-versions field on the External API panel

**Files:**
- Modify: `app/templates/admin.html` (External API panel, ~line 143-150)
- Modify: `app/static/js/admin.js` (`loadExtApi`, ~line 319-331; add a new save handler near `btnSaveExtApiToggle`, ~line 356-373)

No automated test — this is a template/JS-only change with no Python logic, following the same untested pattern as the existing toggle UI. Verify manually per Step 3.

- [ ] **Step 1: Add the HTML field**

In `app/templates/admin.html`, immediately after the existing enable/disable toggle block (after the `</div>` that closes the block starting `<!-- Enable / Disable toggle -->`, ~line 150), add:

```html
  <!-- Executive summary: compliant firmware versions -->
  <div style="margin-bottom:1.5rem;padding:.75rem 1rem;background:var(--surface-alt);border:1px solid var(--border);border-radius:6px">
    <label for="execCompliantVersions" style="display:block;font-weight:500;margin-bottom:.4rem">
      Executive Summary — compliant firmware version(s)
    </label>
    <p class="text-muted" style="font-size:.82rem;margin:0 0 .5rem">
      One version per line or comma-separated (e.g. <code>v7.4.3, v7.6.2</code>).
      Used to compute <code>version_compliance_pct</code> for
      <code>/external/api/executive/summary</code>. Leave empty to report
      compliance as unavailable rather than a fabricated number.
    </p>
    <textarea id="execCompliantVersions" rows="3" style="width:100%;font-family:monospace"></textarea>
    <div style="margin-top:.5rem;display:flex;align-items:center;gap:1rem">
      <button class="btn btn-primary btn-sm" id="btnSaveExecVersions">Save</button>
      <span id="execVersionsMsg" style="font-size:.83rem"></span>
    </div>
  </div>
```

- [ ] **Step 2: Add the JS load/save logic**

In `app/static/js/admin.js`, inside `loadExtApi()` (~line 319-331), after the line `document.getElementById('extApiEnabled').checked = !!settings.external_api_enabled;`, add:

```javascript
    document.getElementById('execCompliantVersions').value =
      (settings.executive_compliant_versions || []).join('\n');
```

Then, immediately after the existing `btnSaveExtApiToggle` click handler (after its closing `});`, ~line 373), add:

```javascript
  // Save executive-summary compliant versions
  document.getElementById('btnSaveExecVersions').addEventListener('click', async () => {
    const raw = document.getElementById('execCompliantVersions').value;
    const msgEl = document.getElementById('execVersionsMsg');
    const res = await fetch('/admin/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ executive_compliant_versions: raw }),
    });
    if (res.ok) {
      msgEl.textContent = 'Saved.';
      msgEl.style.color = 'var(--success)';
    } else {
      msgEl.textContent = 'Failed to save.';
      msgEl.style.color = 'var(--danger)';
    }
    setTimeout(() => { msgEl.textContent = ''; }, 3000);
  });
```

- [ ] **Step 3: Manually verify in the browser**

Run: `cd /Users/alanw/code/github/ai/4thealth-plus && python wsgi.py` (or use the `run` skill if available), then:
1. Log in as an admin, go to Admin → External API.
2. Confirm the new "Executive Summary — compliant firmware version(s)" textarea renders below the enable/disable toggle.
3. Type `v7.4.3, v7.6.2` and click Save — confirm "Saved." appears.
4. Reload the page, confirm the textarea still shows the saved values (proves the GET round-trip works via `loadExtApi`).

- [ ] **Step 4: Commit**

```bash
cd /Users/alanw/code/github/ai/4thealth-plus
git add app/templates/admin.html app/static/js/admin.js
git commit -m "feat: add compliant-versions admin UI for executive summary"
```

---

### Task 8: Documentation

**Files:**
- Modify: `docs/api-reference.md` (External API table, ~line 129-131)
- Modify: `docs/features.md` (External API section — find via `grep -n "external-api" docs/features.md`)
- Modify: `CLAUDE.md` (External API section, ~line 542-567)

No tests — documentation only.

- [ ] **Step 1: Update `docs/api-reference.md`**

In the "External API (bearer-token, no session required)" table, add a row after the existing three:

```markdown
| GET | `/external/api/executive/summary` | Fleet-wide metrics for the 4tExecutive dashboard (hygiene score, version compliance, pending config diffs, firewall online count) |
```

- [ ] **Step 2: Update `docs/features.md`**

Run: `grep -n "external-api\|External API" docs/features.md` to find the section, then add a subsection describing:
- The new endpoint and its JSON shape (copy from the spec's decision 7).
- The new `executive_compliant_versions` admin setting and where to configure it (Admin → External API).
- That `last_backup_status` is intentionally not part of the payload (one sentence, referencing that 4thealth-plus backs up its own app config, not firewall configs).

- [ ] **Step 3: Update `CLAUDE.md`**

In the `### External API` section (~line 542-567):
- Add to the "Endpoints (all read-only)" list:
  ```
  - `GET  /external/api/executive/summary` — fleet-wide metrics for the 4tExecutive dashboard (hygiene score, version compliance %, pending config-diff count, firewall online count/total); backed by a new background sweep, `app/executive_summary_cache.py` (default every 15 min, `EXEC_SUMMARY_REFRESH_MINUTES`)
  ```
- Add to "Supporting modules":
  ```
  - `app/executive_summary_cache.py` — background sweep computing the four executive-summary metrics; same pending|running|ok|error store pattern as `summary_job.py`
  ```
- Add to "Admin endpoints added to `admin_routes.py`" bullet for `GET/PUT /admin/api/settings`, noting it now also covers `executive_compliant_versions`.

- [ ] **Step 4: Commit**

```bash
cd /Users/alanw/code/github/ai/4thealth-plus
git add docs/api-reference.md docs/features.md CLAUDE.md
git commit -m "docs: document the executive summary API endpoint"
```

---

## Self-Review Notes

**Spec coverage:**
- Decision 1 (background job pattern) → Task 4.
- Decision 2 (single device sweep for online + version data) → Task 4 (`_run_job`).
- Decision 3 (admin setting, `null` when unconfigured) → Task 2, Task 6, Task 7, Task 3 (`_version_compliance_pct`).
- Decision 4 (`pending_status_cache` accessor) → Task 1, used in Task 4.
- Decision 5 (hygiene sweep, cheap checks only, findings-density score) → Task 3 (`_hygiene_score`), Task 4 (`_HYGIENE_CHECKS`).
- Decision 6 (refresh cadence env var) → Task 4 (`init_scheduler`).
- Decision 7 (route + response shape, omit `last_backup_status`) → Task 5.
- Decision 8 (4tExecutive-side widget cleanup) → explicitly out of scope, not a task here.
- Testing section of spec → Task 3, Task 4, Task 5, Task 6 test steps.
- Documentation section of spec → Task 8.
