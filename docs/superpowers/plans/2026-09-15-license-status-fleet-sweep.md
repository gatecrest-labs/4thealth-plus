# License Status Fleet Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fleet-wide, daily-swept license status rollup to 4thealth-plus, exposed as a new `license_status` field group in `GET /external/api/executive/summary`, so 4tExecutive can display it (companion plan, separate repo).

**Architecture:** A new background sweep module (`app/license_status_cache.py`), structurally identical to the existing `app/device_backup_cache.py`, calls a new per-device `FMGClient.get_device_license_status()` proxy method (one FMG round-trip per device — there is no bulk endpoint) across every non-`forti*` ADOM, using the same `ThreadPoolExecutor(max_workers=4)` concurrency pattern already used by `bulk_device_review_adom()`. Results are persisted to `license_status.json` and exposed via a new `_license_status()` builder in `app/routes/external_api_routes.py`. The license-parsing logic already added to the firewall detail panel in PR #80 (`app/routes/api_routes.py::_assemble_health`'s inline `_parse_license` closure) is extracted into a shared module so both the live single-device path and this new fleet sweep use one implementation.

**Tech Stack:** Python 3.14, Flask, APScheduler, pytest — same stack as the rest of this repo. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-15-license-status-executive-summary-design.md`

## Global Constraints

- Sweep cadence: daily, env vars `DEVICE_LICENSE_REFRESH_HOUR` (default `3`) / `DEVICE_LICENSE_REFRESH_MINUTE` (default `0`) — staggered after `device_backup`'s 02:00 and `summary_job`'s 01:00.
- Persistence: plain JSON file (`license_status.json`, gitignored, project root) via `atomic_write_json` — no SQLite collector/web split needed (same reasoning as `device_backup_cache.py`).
- `details` list contains only non-`"licensed"` devices (expired or unknown) — never a full device roster.
- No domain-score changes on the 4tExecutive side (out of scope, see spec's Non-goals).
- This branch (`feature/license-status-executive-summary`) is based on `develop`, which does **not** yet include PR #80's lint fix (`0a2f003`, still on the unmerged `feature/firewall-license-status` branch) — `app/routes/api_routes.py` on this branch currently has the pre-fix `from datetime import datetime, timezone` / `timezone.utc`. Task 1 below replaces that whole block by extraction, so the lint issue is resolved as a side effect — don't fix it separately.

---

### Task 1: Extract shared license-parsing logic into `app/license_status.py`

**Files:**
- Create: `app/license_status.py`
- Modify: `app/routes/api_routes.py:1-6` (imports), `app/routes/api_routes.py:655-671` (remove inline `_parse_license` closure, call the shared function instead)
- Test: `tests/test_license_status.py`

**Interfaces:**
- Produces: `app.license_status.parse_license_payload(raw_payload: dict | None) -> dict` returning `{"status": "licensed" | "expired" | "unknown", "expires": str | None}` (expires is `"YYYY-MM-DD"` only when `status == "licensed"`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_license_status.py
"""Tests for app.license_status's shared FortiOS license-response parser."""

import time

from app.license_status import parse_license_payload


def test_licensed_with_future_expiry():
    future_ts = int(time.time()) + 86400 * 30
    payload = {
        "forticare": {"support": {"enhanced": {"status": "licensed", "expires": future_ts}}}
    }
    result = parse_license_payload(payload)
    assert result["status"] == "licensed"
    assert result["expires"] is not None


def test_licensed_but_expiry_in_past_is_expired():
    past_ts = int(time.time()) - 86400
    payload = {
        "forticare": {"support": {"enhanced": {"status": "licensed", "expires": past_ts}}}
    }
    result = parse_license_payload(payload)
    assert result == {"status": "expired", "expires": None}


def test_missing_forticare_block_is_unknown():
    assert parse_license_payload({}) == {"status": "unknown", "expires": None}


def test_none_payload_is_unknown():
    assert parse_license_payload(None) == {"status": "unknown", "expires": None}


def test_status_not_licensed_is_unknown():
    payload = {
        "forticare": {"support": {"enhanced": {"status": "unlicensed", "expires": 123}}}
    }
    assert parse_license_payload(payload) == {"status": "unknown", "expires": None}


def test_licensed_status_without_expires_is_unknown():
    payload = {"forticare": {"support": {"enhanced": {"status": "licensed"}}}}
    assert parse_license_payload(payload) == {"status": "unknown", "expires": None}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_license_status.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.license_status'`

- [ ] **Step 3: Write the module**

```python
# app/license_status.py
"""Shared FortiOS license-response parsing.

Used by both the live, single-device firewall detail panel
(app.routes.api_routes._assemble_health) and the fleet-wide daily sweep
(app.license_status_cache) so the "licensed / expired / unknown"
classification never has two independent implementations to drift out of
sync. Source: FortiOS's /api/v2/monitor/license/status response, proxied
through FortiManager (see app.fmg_client.PROXY_ENDPOINTS's "license_status"
entry and FMGClient.get_device_license_status()).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime


def parse_license_payload(raw_payload: dict | None) -> dict:
    """Classify a FortiOS license/status proxy payload.

    raw_payload is the already-unwrapped `results` dict FMGClient's
    _proxy() returns (i.e. `payload("license_status")` in api_routes.py,
    or the direct return of FMGClient.get_device_license_status()).

    Returns {"status": "licensed" | "expired" | "unknown", "expires":
    "YYYY-MM-DD" | None}. "unknown" covers every failure mode: missing/
    malformed forticare block, a non-"licensed" status string, or a
    "licensed" status with no expires timestamp — never fabricated.
    """
    results = raw_payload if isinstance(raw_payload, dict) else {}
    forticare = results.get("forticare", {})
    enhanced = forticare.get("support", {}).get("enhanced", {})
    status = enhanced.get("status", "")
    expires_ts = enhanced.get("expires")
    if status == "licensed" and expires_ts:
        if expires_ts > time.time():
            exp_str = datetime.fromtimestamp(expires_ts, tz=UTC).strftime("%Y-%m-%d")
            return {"status": "licensed", "expires": exp_str}
        return {"status": "expired", "expires": None}
    return {"status": "unknown", "expires": None}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_license_status.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Wire `_assemble_health()` to call the shared function**

In `app/routes/api_routes.py`, replace the current imports (lines 3-6) —

```python
import json
import re
import time
from datetime import datetime, timezone
```

— with:

```python
import json
import re
```

(both `time` and `datetime`/`timezone` were only used by the inline `_parse_license` closure being removed).

Then replace lines 655-671 (the `_parse_license` closure definition plus its call) —

```python
    def _parse_license(raw_payload) -> dict:
        # _proxy() already unwraps response.results, so raw_payload IS the results dict
        results = raw_payload if isinstance(raw_payload, dict) else {}
        forticare = results.get("forticare", {})
        enhanced = forticare.get("support", {}).get("enhanced", {})
        status = enhanced.get("status", "")
        expires_ts = enhanced.get("expires")
        if status == "licensed" and expires_ts:
            if expires_ts > time.time():
                exp_str = datetime.fromtimestamp(expires_ts, tz=timezone.utc).strftime(
                    "%Y-%m-%d"
                )
                return {"status": "licensed", "expires": exp_str}
            return {"status": "expired", "expires": None}
        return {"status": "unknown", "expires": None}

    license_info = _parse_license(payload("license_status"))
```

— with:

```python
    license_info = parse_license_payload(payload("license_status"))
```

And add the import near the top, alongside the other `app.*` imports (after `from app.decorators import ...`):

```python
from app.license_status import parse_license_payload
```

- [ ] **Step 6: Run the full test suite to confirm nothing broke**

Run: `uv run pytest -q`
Expected: PASS, same count as before this change plus the 6 new tests. No import errors from `api_routes.py`.

- [ ] **Step 7: Lint check**

Run: `uv run ruff check app/license_status.py app/routes/api_routes.py && uv run ruff format --check app/license_status.py app/routes/api_routes.py`
Expected: clean (this also resolves the pre-existing `timezone.utc` UP017 lint issue mentioned in Global Constraints, since that code is now deleted).

- [ ] **Step 8: Commit**

```bash
git add app/license_status.py app/routes/api_routes.py tests/test_license_status.py
git commit -m "refactor: extract license-response parsing into app.license_status

Shared by the firewall detail panel and the new fleet-wide license sweep
(added in a following commit) so the licensed/expired/unknown
classification has one implementation."
```

---

### Task 2: Add `FMGClient.get_device_license_status()`

**Files:**
- Modify: `app/fmg_client.py` (add method near `get_device_admins`, around line 1404)
- Test: `tests/test_fmg_client_license_status.py`

**Interfaces:**
- Consumes: `FMGClient._proxy(adom, device, resource) -> dict` (existing; returns `{"rpc_code", "http_status", "payload"}`).
- Produces: `FMGClient.get_device_license_status(adom: str, device_name: str) -> dict` — returns the raw `payload` dict from the proxy call (the same shape `_assemble_health()`'s `payload("license_status")` already reads), or `{}` on any error.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_fmg_client_license_status.py
"""Tests for FMGClient.get_device_license_status()."""

from unittest.mock import patch

from app.fmg_client import FMGClient


def _make_client():
    c = FMGClient.__new__(FMGClient)
    c.base_url = "https://fmg.test/jsonrpc"
    c.token = "tok"
    c.session = None
    c.verify_ssl = False
    c._req_id = 0
    return c


def test_get_device_license_status_returns_payload():
    client = _make_client()
    fake_payload = {"forticare": {"support": {"enhanced": {"status": "licensed", "expires": 9999999999}}}}
    with patch.object(
        client,
        "_proxy",
        return_value={"rpc_code": 0, "http_status": 200, "payload": fake_payload},
    ) as mock_proxy:
        result = client.get_device_license_status("root", "FW-1")
    assert result == fake_payload
    mock_proxy.assert_called_once_with("root", "FW-1", "/api/v2/monitor/license/status")


def test_get_device_license_status_returns_empty_dict_on_exception():
    client = _make_client()
    with patch.object(client, "_proxy", side_effect=Exception("connection refused")):
        result = client.get_device_license_status("root", "FW-1")
    assert result == {}


def test_get_device_license_status_returns_empty_dict_when_payload_not_a_dict():
    client = _make_client()
    with patch.object(
        client,
        "_proxy",
        return_value={"rpc_code": 0, "http_status": 200, "payload": []},
    ):
        result = client.get_device_license_status("root", "FW-1")
    assert result == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_fmg_client_license_status.py -v`
Expected: FAIL with `AttributeError: 'FMGClient' object has no attribute 'get_device_license_status'`

- [ ] **Step 3: Add the method**

In `app/fmg_client.py`, immediately after `get_device_admins()` (ends around line 1414, right before `get_device_system_global`), add:

```python
    def get_device_license_status(self, adom: str, device_name: str) -> dict:
        """Return the raw /api/v2/monitor/license/status proxy payload for
        one device, or {} on any error (including a non-dict payload) —
        callers pass this straight into app.license_status.parse_license_payload(),
        which already treats {} as "unknown" rather than crashing."""
        try:
            r = self._proxy(adom, device_name, "/api/v2/monitor/license/status")
            payload = r.get("payload", {})
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_fmg_client_license_status.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Lint check**

Run: `uv run ruff check app/fmg_client.py && uv run ruff format --check app/fmg_client.py`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add app/fmg_client.py tests/test_fmg_client_license_status.py
git commit -m "feat: add FMGClient.get_device_license_status()"
```

---

### Task 3: `app/license_status_cache.py` — pure aggregation logic

**Files:**
- Create: `app/license_status_cache.py`
- Test: `tests/test_license_status_cache.py`

**Interfaces:**
- Consumes: `app.license_status.parse_license_payload(raw_payload) -> dict` (Task 1).
- Produces: `_classify_devices(devices_by_adom_with_license: dict[str, list[dict]]) -> dict` — the pure aggregation function, unit-tested directly (no I/O). Input shape: `{adom: [{"name": str, "license": {"status": ..., "expires": ...}}, ...]}` — see Step 1 for the exact contract. Output: `{"devices_licensed": int, "devices_expired": int, "devices_unknown": int, "details": list[dict]}`.

This task only builds and tests the pure classification function — no FMG calls, no scheduler, no persistence yet (those are Task 4).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_license_status_cache.py
"""Tests for app.license_status_cache's pure aggregation logic."""

from app.license_status_cache import _classify_devices


def test_classify_devices_counts_and_details():
    devices_by_adom = {
        "Corp": [
            {"name": "fw-licensed", "license": {"status": "licensed", "expires": "2027-01-01"}},
            {"name": "fw-expired", "license": {"status": "expired", "expires": None}},
            {"name": "fw-unknown", "license": {"status": "unknown", "expires": None}},
        ]
    }

    result = _classify_devices(devices_by_adom)

    assert result["devices_licensed"] == 1
    assert result["devices_expired"] == 1
    assert result["devices_unknown"] == 1
    assert result["details"] == [
        {"device": "fw-expired", "adom": "Corp", "status": "expired", "expires": None},
        {"device": "fw-unknown", "adom": "Corp", "status": "unknown", "expires": None},
    ]


def test_classify_devices_details_excludes_licensed():
    devices_by_adom = {
        "Corp": [{"name": "fw-a", "license": {"status": "licensed", "expires": "2027-01-01"}}]
    }

    result = _classify_devices(devices_by_adom)

    assert result["devices_licensed"] == 1
    assert result["details"] == []


def test_classify_devices_multiple_adoms():
    devices_by_adom = {
        "Corp": [{"name": "fw-a", "license": {"status": "licensed", "expires": "2027-01-01"}}],
        "Branch": [{"name": "fw-b", "license": {"status": "expired", "expires": None}}],
    }

    result = _classify_devices(devices_by_adom)

    assert result["devices_licensed"] == 1
    assert result["devices_expired"] == 1
    assert result["details"] == [
        {"device": "fw-b", "adom": "Branch", "status": "expired", "expires": None}
    ]


def test_classify_devices_empty_input():
    result = _classify_devices({})
    assert result == {
        "devices_licensed": 0,
        "devices_expired": 0,
        "devices_unknown": 0,
        "details": [],
    }


def test_classify_devices_skips_entries_missing_name():
    devices_by_adom = {"Corp": [{"license": {"status": "expired", "expires": None}}]}
    result = _classify_devices(devices_by_adom)
    assert result == {
        "devices_licensed": 0,
        "devices_expired": 0,
        "devices_unknown": 0,
        "details": [],
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_license_status_cache.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.license_status_cache'`

- [ ] **Step 3: Write the module (aggregation portion only)**

```python
# app/license_status_cache.py
"""Fleet-wide FortiGate license status: daily sweep.

Unlike the cheap per-ADOM bulk device sweep (app.executive_summary_cache,
app.device_backup_cache), license status has no bulk/fleet-wide FMG
endpoint -- FortiOS only exposes it via /api/v2/monitor/license/status,
fetched one FMG proxy call per device (FMGClient.get_device_license_status()).
This is the same cost class as app.device_backup_cache's sweep, hence its
own daily cadence (DEVICE_LICENSE_REFRESH_HOUR/_MINUTE, default 03:00 local
-- staggered after device_backup's 02:00 and summary_job's 01:00) rather
than riding the 15-minute device sweep.

For each non-forti* ADOM, devices are fetched via client.get_devices(adom)
(device roster), then a ThreadPoolExecutor(max_workers=4) -- same
concurrency pattern as app.routes.audit_review_routes.bulk_device_review_adom()
-- calls get_device_license_status() per device and classifies the result
via app.license_status.parse_license_payload().

Persisted to license_status.json (gitignored, project root) via
atomic_write_json after every successful sweep -- same single-latest-record,
"a failed sweep leaves the prior result in place" convention as
app.device_backup_cache. Because this is a plain JSON file on shared disk
rather than an in-memory store, it needs no SQLite collector/web split
treatment.
"""

from __future__ import annotations

import json
import logging
import threading
import time as _time
from datetime import UTC, datetime
from pathlib import Path

from app.atomic_io import atomic_write_json
from app.license_status import parse_license_payload

logger = logging.getLogger(__name__)

_STORE_PATH = Path(__file__).parent.parent / "license_status.json"

_lock = threading.Lock()
_running = threading.Event()


# ── Pure aggregation (no I/O — unit-tested directly) ────────────────────────


def _classify_devices(devices_by_adom_with_license: dict[str, list[dict]]) -> dict:
    """Bucket every device across all ADOMs into licensed/expired/unknown.

    devices_by_adom_with_license: {adom: [{"name": str, "license": {"status",
    "expires"}}, ...]} — each device dict must already carry its parsed
    "license" sub-dict (see _run_sweep(), which attaches it before calling
    this function).
    """
    licensed = 0
    expired = 0
    unknown = 0
    details: list[dict] = []

    for adom, devices in devices_by_adom_with_license.items():
        for device in devices:
            if not isinstance(device, dict):
                continue
            name = device.get("name", "")
            if not name:
                continue
            license_info = device.get("license") or {}
            status = license_info.get("status", "unknown")
            if status == "licensed":
                licensed += 1
            elif status == "expired":
                expired += 1
                details.append(
                    {
                        "device": name,
                        "adom": adom,
                        "status": "expired",
                        "expires": license_info.get("expires"),
                    }
                )
            else:
                unknown += 1
                details.append(
                    {
                        "device": name,
                        "adom": adom,
                        "status": "unknown",
                        "expires": license_info.get("expires"),
                    }
                )

    return {
        "devices_licensed": licensed,
        "devices_expired": expired,
        "devices_unknown": unknown,
        "details": details,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_license_status_cache.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Lint check**

Run: `uv run ruff check app/license_status_cache.py && uv run ruff format --check app/license_status_cache.py`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add app/license_status_cache.py tests/test_license_status_cache.py
git commit -m "feat: add license_status_cache aggregation logic (no I/O yet)"
```

---

### Task 4: `app/license_status_cache.py` — sweep, persistence, and scheduler

**Files:**
- Modify: `app/license_status_cache.py` (append persistence + sweep + scheduler functions)
- Modify: `app/__init__.py` (register the scheduler, mirroring the `_DEVICE_BACKUP_SCHEDULER_STARTED` block)
- Test: `tests/test_license_status_cache.py` (append)

**Interfaces:**
- Consumes: `_classify_devices()` (Task 3), `app.license_status.parse_license_payload()` (Task 1), `FMGClient.get_devices(adom)` (existing), `FMGClient.get_device_license_status(adom, device)` (Task 2), `app.fmg_helpers.make_client()` (existing context manager), `app.atomic_io.atomic_write_json(path, data)` (existing).
- Produces: `get_latest() -> dict | None`, `refresh_now(app) -> None`, `init_scheduler(app) -> BackgroundScheduler`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_license_status_cache.py`:

```python
import json
from unittest.mock import MagicMock, patch

from app.license_status_cache import get_latest, _run_sweep, _STORE_PATH


def test_get_latest_returns_none_when_no_file(tmp_path, monkeypatch):
    fake_path = tmp_path / "license_status.json"
    monkeypatch.setattr("app.license_status_cache._STORE_PATH", fake_path)
    assert get_latest() is None


def test_get_latest_reads_persisted_record(tmp_path, monkeypatch):
    fake_path = tmp_path / "license_status.json"
    fake_path.write_text(json.dumps({"devices_licensed": 5, "collected_at": "2026-09-16T03:00:00Z"}))
    monkeypatch.setattr("app.license_status_cache._STORE_PATH", fake_path)
    result = get_latest()
    assert result["devices_licensed"] == 5


def test_run_sweep_persists_classified_result(tmp_path, monkeypatch):
    fake_path = tmp_path / "license_status.json"
    monkeypatch.setattr("app.license_status_cache._STORE_PATH", fake_path)

    fake_client = MagicMock()
    fake_client.get_adoms.return_value = [{"name": "Corp"}]
    fake_client.get_devices.return_value = [{"name": "fw-a"}]
    fake_client.get_device_license_status.return_value = {
        "forticare": {"support": {"enhanced": {"status": "licensed", "expires": 9999999999}}}
    }
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)

    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        result = _run_sweep(app=None)

    assert result is True
    persisted = json.loads(fake_path.read_text())
    assert persisted["devices_licensed"] == 1
    assert persisted["devices_expired"] == 0
    assert "collected_at" in persisted


def test_run_sweep_skips_forti_prefixed_adoms(tmp_path, monkeypatch):
    fake_path = tmp_path / "license_status.json"
    monkeypatch.setattr("app.license_status_cache._STORE_PATH", fake_path)

    fake_client = MagicMock()
    fake_client.get_adoms.return_value = [{"name": "FortiManager_Managed_Devices"}, {"name": "Corp"}]
    fake_client.get_devices.return_value = []
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)

    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        _run_sweep(app=None)

    # get_devices should only be called for the non-forti* ADOM
    fake_client.get_devices.assert_called_once_with("Corp")


def test_run_sweep_overlap_returns_false():
    from app.license_status_cache import _running

    _running.set()
    try:
        assert _run_sweep(app=None) is False
    finally:
        _running.clear()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_license_status_cache.py -v`
Expected: FAIL — `get_latest`, `_run_sweep`, `_STORE_PATH` import errors (only `_classify_devices` exists so far).

- [ ] **Step 3: Append the persistence, sweep, and scheduler code**

Append to `app/license_status_cache.py`:

```python


def _list_target_adoms(client) -> list[str]:
    """Return non-forti* ADOM names — same convention as every other
    ADOM-enumerating sweep in this codebase (see CLAUDE.md)."""
    adoms_raw = client.get_adoms()
    return [
        a.get("name", "")
        for a in adoms_raw
        if isinstance(a, dict)
        and a.get("name")
        and not a.get("name", "").lower().startswith("forti")
    ]


# ── Persistence ──────────────────────────────────────────────────────────────


def get_latest() -> dict | None:
    """The last successfully persisted {devices_licensed, devices_expired,
    devices_unknown, details, collected_at}, or None if no sweep has ever
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


# ── Sweep ────────────────────────────────────────────────────────────────────


def _run_sweep(app) -> bool:
    """Fetch device rosters + per-device license status once per non-forti*
    ADOM, classify, and persist. Returns True on success, False on error or
    overlap — on either failure mode the previously persisted result is
    left in place."""
    if _running.is_set():
        logger.info("license_status_cache: already running, skipping overlap")
        return False

    _running.set()
    t0 = _time.monotonic()
    try:
        import concurrent.futures

        from app.fmg_helpers import make_client

        devices_by_adom_with_license: dict[str, list[dict]] = {}

        with make_client() as client:
            adom_names = _list_target_adoms(client)
            for adom in adom_names:
                try:
                    devices = client.get_devices(adom) or []
                except Exception as exc:
                    logger.warning(
                        "license_status_cache: get_devices(%s) failed: %s", adom, exc
                    )
                    devices = []

                valid_devices = [
                    d for d in devices if isinstance(d, dict) and d.get("name")
                ]

                def _fetch_one(dev: dict, adom=adom) -> dict:
                    name = dev["name"]
                    try:
                        raw = client.get_device_license_status(adom, name)
                    except Exception as exc:
                        logger.warning(
                            "license_status_cache: get_device_license_status(%s, %s) failed: %s",
                            adom,
                            name,
                            exc,
                        )
                        raw = {}
                    return {"name": name, "license": parse_license_payload(raw)}

                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    devices_by_adom_with_license[adom] = list(
                        pool.map(_fetch_one, valid_devices)
                    )

        counts = _classify_devices(devices_by_adom_with_license)
        record = {**counts, "collected_at": datetime.now(UTC).isoformat()}

        with _lock:
            _save(record)

        elapsed = round(_time.monotonic() - t0, 1)
        logger.info(
            "license_status_cache: sweep done in %ss — licensed=%d expired=%d unknown=%d",
            elapsed,
            counts["devices_licensed"],
            counts["devices_expired"],
            counts["devices_unknown"],
        )
        return True
    except Exception:
        logger.exception(
            "license_status_cache: sweep failed — keeping last persisted result"
        )
        return False
    finally:
        _running.clear()


def refresh_now(app) -> None:
    """Trigger an immediate background sweep (non-blocking)."""
    threading.Thread(
        target=_run_sweep,
        args=[app],
        name="license_status_cache_refresh",
        daemon=True,
    ).start()


def init_scheduler(app):
    """Register the daily sweep with APScheduler and fire it once immediately."""
    import os

    from apscheduler.schedulers.background import BackgroundScheduler

    refresh_hour = int(os.environ.get("DEVICE_LICENSE_REFRESH_HOUR", "3"))
    refresh_minute = int(os.environ.get("DEVICE_LICENSE_REFRESH_MINUTE", "0"))

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_sweep,
        args=[app],
        trigger="cron",
        hour=refresh_hour,
        minute=refresh_minute,
        id="license_status_refresh",
        name="Daily license status sweep",
    )
    scheduler.start()
    logger.info(
        "license_status_cache: scheduler started — daily at %02d:%02d local time",
        refresh_hour,
        refresh_minute,
    )

    threading.Thread(
        target=_run_sweep,
        args=[app],
        name="license_status_cache_startup",
        daemon=True,
    ).start()

    return scheduler
```

Note: `_fetch_one`'s `adom=adom` default-argument trick avoids the classic
late-binding closure bug inside the `for adom in adom_names` loop — each
`_fetch_one` submitted to the pool captures its own `adom` value at
definition time rather than reading the loop variable's final value.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_license_status_cache.py -v`
Expected: PASS (10 tests total: 5 from Task 3 + 5 new)

- [ ] **Step 5: Register the scheduler in `app/__init__.py`**

In `app/__init__.py`, immediately after the existing `_DEVICE_BACKUP_SCHEDULER_STARTED` block (ends around line 203, right before `def create_app`), add:

```python

    if not app.config.get("_LICENSE_STATUS_SCHEDULER_STARTED"):
        app.config["_LICENSE_STATUS_SCHEDULER_STARTED"] = True
        try:
            from app.license_status_cache import (
                init_scheduler as init_license_status_scheduler,
            )

            with app.app_context():
                init_license_status_scheduler(app)
        except Exception as exc:
            app.logger.warning("License status scheduler failed to start: %s", exc)
```

- [ ] **Step 6: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS, no regressions.

- [ ] **Step 7: Lint check**

Run: `uv run ruff check app/license_status_cache.py app/__init__.py && uv run ruff format --check app/license_status_cache.py app/__init__.py`
Expected: clean

- [ ] **Step 8: Add `license_status.json` to `.gitignore`**

Check `.gitignore` already has `device_backup.json` / `change_control.json` listed; add `license_status.json` alongside them in the same block.

- [ ] **Step 9: Commit**

```bash
git add app/license_status_cache.py app/__init__.py tests/test_license_status_cache.py .gitignore
git commit -m "feat: add daily license status sweep with scheduler wiring"
```

---

### Task 5: Expose `license_status` in the executive summary payload

**Files:**
- Modify: `app/routes/external_api_routes.py` (add `_license_status()` builder, wire into `/executive/summary` payload and `_freshness()`)
- Test: `tests/test_external_api_executive.py` (append)

**Interfaces:**
- Consumes: `app.license_status_cache.get_latest() -> dict | None` (Task 4).
- Produces: new top-level `license_status` key in the `/external/api/executive/summary` JSON response: `{"devices_licensed": int | None, "devices_expired": int | None, "devices_unknown": int | None, "details": list, "collected_at": str | None}`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_external_api_executive.py` (mirroring the existing `test_payload_includes_device_backup` / `test_payload_device_backup_defaults_when_no_sweep_yet` pair immediately above/below them):

```python
def test_payload_includes_license_status(client):
    fake_record = {
        "devices_licensed": 40,
        "devices_expired": 2,
        "devices_unknown": 1,
        "details": [{"device": "fw-a", "adom": "Corp", "status": "expired", "expires": None}],
        "collected_at": "2026-09-16T03:00:00+00:00",
    }
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value={"status": "ok"}),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
        patch("app.psirt_store.compute_psirt_rollup", return_value={}),
        patch("app.change_control_cache.get_latest", return_value=None),
        patch("app.device_backup_cache.get_latest", return_value=None),
        patch("app.license_status_cache.get_latest", return_value=fake_record),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["license_status"] == fake_record
    assert data["freshness"]["license_status"] == "2026-09-16T03:00:00+00:00"


def test_payload_license_status_defaults_when_no_sweep_yet(client):
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value={"status": "pending"}),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
        patch("app.psirt_store.compute_psirt_rollup", return_value={}),
        patch("app.change_control_cache.get_latest", return_value=None),
        patch("app.device_backup_cache.get_latest", return_value=None),
        patch("app.license_status_cache.get_latest", return_value=None),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["license_status"] == {
        "devices_licensed": None,
        "devices_expired": None,
        "devices_unknown": None,
        "details": [],
        "collected_at": None,
    }
```

Note: `app.license_status_cache.get_latest()` (like `device_backup_cache.get_latest()`)
degrades to `None` when `license_status.json` doesn't exist on disk — which
it never does in the test environment (it's gitignored, runtime-only) — so
none of the *other*, pre-existing tests in this file need any change; they
already exercise the "no sweep yet" default path for free, unmocked, exactly
as they do today for `device_backup`. Only the two new tests above need an
explicit mock, because they assert an exact non-default record.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_executive.py -v`
Expected: FAIL — `KeyError: 'license_status'` on the two new tests only; every pre-existing test in the file still passes.

- [ ] **Step 3: Add `_license_status()` and wire it in**

In `app/routes/external_api_routes.py`, immediately after `_device_backup()` (ends right before `_psirt_rollup()`), add:

```python
def _license_status() -> dict:
    """Fleet-wide FortiGate license status, from the daily
    app.license_status_cache sweep — see that module and
    app.license_status.parse_license_payload() for how devices are
    classified. None counts (never swept yet) rather than 0, same
    "unknown never renders as a false negative" convention as
    app.model_eos and app.device_backup_cache."""
    from app.license_status_cache import get_latest

    latest = get_latest()
    if latest is None:
        return {
            "devices_licensed": None,
            "devices_expired": None,
            "devices_unknown": None,
            "details": [],
            "collected_at": None,
        }
    return {
        "devices_licensed": latest.get("devices_licensed"),
        "devices_expired": latest.get("devices_expired"),
        "devices_unknown": latest.get("devices_unknown"),
        "details": latest.get("details") or [],
        "collected_at": latest.get("collected_at"),
    }
```

Then in `ext_executive_summary()`, add `"license_status": _license_status(),` to the payload dict right after the existing `"device_backup": _device_backup(),` line, and add `"license_status": license_status.get("collected_at"),` to `_freshness()`'s return dict — but `_freshness()` takes `payload` and `summary`, not individual field-group dicts, so instead extract it the same way the function already does for `psirt`/`change_control`/`lifecycle`:

In `_freshness(payload, summary)`, add this line alongside the existing `psirt = payload.get("psirt") or {}` / `change_control = ...` / `lifecycle = ...` extraction lines:

```python
    license_status = payload.get("license_status") or {}
```

and add this key to the returned dict, alongside the existing `"lifecycle": lifecycle.get("collected_at"),` line:

```python
        "license_status": license_status.get("collected_at"),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_executive.py -v`
Expected: PASS, all tests in the file (including the pre-existing ones).

- [ ] **Step 5: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS, no regressions.

- [ ] **Step 6: Lint check**

Run: `uv run ruff check app/routes/external_api_routes.py && uv run ruff format --check app/routes/external_api_routes.py`
Expected: clean

- [ ] **Step 7: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_executive.py
git commit -m "feat: expose license_status in the executive summary payload"
```

---

### Task 6: Documentation

**Files:**
- Modify: `CLAUDE.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Update the External API section**

In `CLAUDE.md`, find this sentence (in the `GET /external/api/executive/summary` bullet, in the External API section):

```
The payload also includes `lifecycle` (hardware EOS, from the device sweep), `change_control` (admin audit-log aggregation, hourly), `psirt` (persisted advisory exposure), and `device_backup` (see below) — each sourced from its own independent module/cadence, not the device sweep's 15-min loop.
```

Replace it with:

```
The payload also includes `lifecycle` (hardware EOS, from the device sweep), `change_control` (admin audit-log aggregation, hourly), `psirt` (persisted advisory exposure), `device_backup`, and `license_status` (see below) — each sourced from its own independent module/cadence, not the device sweep's 15-min loop.
```

Then find the `app/device_backup_cache.py` bullet under "Supporting modules" and add a new bullet immediately after it:

```
- `app/license_status_cache.py` — daily sweep (`DEVICE_LICENSE_REFRESH_HOUR`/`_MINUTE`, default 03:00 local — staggered after `device_backup`'s 02:00) computing fleet-wide FortiGate license status, feeding the `license_status` executive-summary key: `{devices_licensed, devices_expired, devices_unknown, details, collected_at}`. Unlike `device_backup_cache`'s one-call-per-ADOM bulk revision fetch, license status has no bulk FMG endpoint — one `FMGClient.get_device_license_status(adom, device)` proxy call per device, fetched with a 4-worker thread pool per ADOM (same concurrency pattern as `bulk_device_review_adom()`). `details` lists only non-`"licensed"` devices (expired or unknown), same "surface problems, not clean state" convention as `models_unknown`. Shares `app/license_status.py::parse_license_payload()` with the firewall detail panel's live license badge (see the Firewalls tab section) so both paths classify licenses identically. Persisted to `license_status.json` (gitignored, project root) after every successful sweep, same atomic-write/single-latest-record pattern as `app/device_backup_cache.py`; a failed sweep leaves the prior result in place.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document the license_status executive-summary field group"
```

---

### Task 7: Full verification pass

**Files:** none (verification only).

- [ ] **Step 1: Run the entire test suite**

Run: `uv run pytest -q`
Expected: PASS, all tests green.

- [ ] **Step 2: Run lint across the whole repo**

Run: `uv run ruff check app/ wsgi.py manage_users.py && uv run ruff format --check app/ wsgi.py manage_users.py`
Expected: clean

- [ ] **Step 3: Manual smoke test**

Start the app locally (`python wsgi.py`), confirm the app starts without errors in the log (watch for "License status scheduler failed to start" — if seen, investigate before proceeding), then check `GET /external/api/executive/summary` (with a valid bearer token, `external_api_enabled` on) includes a `license_status` key with either real counts (if a sweep has already run once at startup — `init_scheduler()` fires one immediately) or the all-`None`/`[]` defaults.

- [ ] **Step 4: Push the branch**

```bash
git push -u origin feature/license-status-executive-summary
```

Do not open a PR yet — hold until the companion 4tExecutive-side plan is also implemented, or open now and note in the PR description that it's usable independently (the new field is purely additive and doesn't require the 4tExecutive-side changes to be safe to merge).
