# Exec Recommendations Tier 2 (4thealth+) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the 4thealth+ half of Tier 2 exec-recommendations — device review and rule
hygiene fleet rollups, a fresher `rule_count_total`, version EOL flagging, per-field-group
freshness/status, AI usage attribution, and a `schema_version` field — on the external
executive-summary API (`/external/api/executive/summary`).

**Architecture:** Reuses existing scheduled sweeps (`executive_summary_cache`'s device/hygiene
sweeps, `device_review_scheduler`'s per-ADOM cron jobs) rather than adding new schedulers.
Two new small JSON-file rollup stores follow the existing `atomic_write_json` /
`device_review_jobs.json` pattern. `ai_usage.db` gains two nullable columns via a
guarded idempotent migration. All payload changes are additive — existing consumers reading
only today's flat fields are unaffected.

**Tech Stack:** Flask, Python 3.11+ (repo pinned to 3.14 in CI), pytest, ruff, SQLite
(`sqlite3` stdlib), APScheduler (existing schedulers only — no new ones).

**Spec:** `docs/Exec-recommendations.md` (4tExecutive repo, section 2 "Tier 2") and
`docs/superpowers/specs/2026-08-28-exec-recommendations-tier2-design.md` (4tExecutive repo) —
this plan implements design-doc sections 2–7, 9.

## Global Constraints

- No new APScheduler jobs/collectors — every new rollup piggybacks on an existing scheduled
  sweep (design doc section 1: Tier 2 premise is "no new collectors").
- All payload changes are additive/backward-compatible — missing/old fields must not break
  existing consumers (design doc section 2).
- `rec 2.3 (PSIRT)` is explicitly out of scope for this plan (design doc section 1/10).
- `app/summary_job.py` is NOT deleted or modified — it's the sole writer of
  `summary_history.json`, which backs the internal `api_routes.py::summary_history()` route
  (a 30-day trend graph unrelated to the executive API). Only the external payload's source
  for `rule_count_total` changes (design doc section 5).
- Every new/changed field follows the "missing key ⇒ null/absent, no crash" convention already
  established on this endpoint.
- Lint (`ruff check app/` + `ruff format --check app/`) and the full test suite
  (`uv run pytest tests/ -v`) must pass before each commit that touches `app/`.

---

## File Structure

- `app/executive_summary_cache.py` (modify) — `_store` gains `rule_count_total`,
  `rule_hygiene` (findings-by-type + total), `device_sweep_status`/`hygiene_sweep_status`
  (replacing shared `status`), per-group `collected_at` fields; `_run_hygiene_sweep()` extended
  to compute rule count + hygiene rollup.
- `app/hygiene_rollup.py` (new) — persistence for the rule-hygiene fleet rollup history
  (`hygiene_rollup.json`), mirroring `device_review_scheduler.py`'s `_load`/`_save`/`_append_run`
  pattern.
- `app/device_review_severity.py` (new) — static `SEVERITY: dict[str, str]` mapping each of the
  26 `device_review.CHECKS` keys to `critical|high|medium|low`.
- `app/device_review_rollup.py` (new) — aggregation (`build_rollup(results)`) + persistence
  (`hygiene_rollup.py`'s twin) for `device_review_rollup.json`.
- `app/device_review_scheduler.py` (modify) — `_execute_job()` calls
  `device_review_rollup.build_rollup()` + `.append_run()` before `results`/`all_rows` go out of
  scope.
- `app/version_eol.py` (new) — static `EOL_VERSIONS: set[str]` (or prefix-matcher) + `is_eol()`.
- `app/routes/external_api_routes.py` (modify) — `_version_breakdown()` annotates `eol`;
  `ext_executive_summary()` assembles `schema_version`, `device_review`, `rule_hygiene`,
  `ai_usage_by_feature`, split status/freshness fields, reads `rule_count_total` from
  `executive_summary_cache` instead of `summary_job`.
- `app/ai_usage.py` (modify) — schema migration (`feature`/`user` nullable columns),
  `record_usage()` gains `feature`/`user` kwargs, `usage_summary()` gains `by_feature: bool`,
  new `prune_old_data()`.
- `app/llm/base.py`, `app/llm/codex_provider.py`, `app/llm/claude_provider.py`,
  `app/llm/ollama_provider.py` (modify) — `narrate()` gains a `feature: str` parameter, threaded
  into every `record_usage()` call.
- Six caller sites (modify): `app/pending_changes_ai.py`, `app/config_diff_scheduler.py`,
  `app/device_review_ai.py`, `app/device_review_scheduler.py` (narrative call, distinct from the
  rollup change above), `app/host_metrics_ai.py`, `app/hygiene_ai.py`,
  `app/routes/rule_review_routes.py` (two call sites), `app/routes/psirt_routes.py` — each passes
  a static `feature` string and `user` (from `session` where available, `None` in schedulers).
- New tests: `tests/test_hygiene_rollup.py`, `tests/test_device_review_rollup.py`,
  `tests/test_device_review_severity.py`, `tests/test_version_eol.py`. Modified tests:
  `tests/test_executive_summary_cache.py`, `tests/test_device_review_scheduler.py`,
  `tests/test_external_api_executive.py`, `tests/test_ai_usage.py`,
  `tests/test_admin_ai_assist_setting.py` (or wherever the AI-usage rollup route is tested).

---

### Task 1: Fresher `rule_count_total` sourced from the hygiene sweep

**Files:**
- Modify: `app/executive_summary_cache.py`
- Modify: `app/routes/external_api_routes.py`
- Modify: `tests/test_executive_summary_cache.py`
- Modify: `tests/test_external_api_executive.py`

**Interfaces:**
- Produces: `executive_summary_cache.get_summary()`'s returned dict gains a
  `"rule_count_total": int | None` key.
- `app/summary_job.py` is untouched (still runs daily, still feeds `summary_history.json`).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_executive_summary_cache.py` (near the existing hygiene-sweep tests):

```python
def test_run_hygiene_sweep_stores_rule_count_total(app_ctx):
    import app.executive_summary_cache as cache_mod

    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}]
    client.get_devices.return_value = [{"name": "fw1"}]
    client.get_policy_packages.return_value = [{"name": "default", "path": "default"}]
    client.get_policies.return_value = [{"policyid": 1}, {"policyid": 2}, {"policyid": 3}]

    with patch("app.fmg_helpers.make_client", return_value=client):
        cache_mod._run_hygiene_sweep(app_ctx)

    assert cache_mod.get_summary()["rule_count_total"] == 3
```

(Use the same `from unittest.mock import MagicMock, patch` import already present at the top of
this test file, and the same `_list_target_adoms`-compatible ADOM-name shape used by the
existing hygiene-sweep tests in this file — if `_list_target_adoms` filters by a different
signal than `get_adoms`, match whatever the neighboring existing hygiene-sweep test in this file
already sets up for `client.get_adoms`/`get_devices`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_executive_summary_cache.py::test_run_hygiene_sweep_stores_rule_count_total -v`
Expected: FAIL — `KeyError: 'rule_count_total'` (key doesn't exist in `_store` yet).

- [ ] **Step 3: Write the implementation**

In `app/executive_summary_cache.py`, add `"rule_count_total": None,` to the `_store` dict
literal (next to `"adom_count"`).

In `_run_hygiene_sweep()`, the loop already accumulates `total_policies` (confirmed at the
`total_policies += len(policies)` line, inside the per-package loop). Add `"rule_count_total":
total_policies,` to the `_store.update({...})` call at the end of the try block (same dict that
sets `"hygiene_score"`, `"status"`, `"error"`, `"last_updated"`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_executive_summary_cache.py::test_run_hygiene_sweep_stores_rule_count_total -v`
Expected: PASS

- [ ] **Step 5: Write the failing route test**

Add to `tests/test_external_api_executive.py`:

```python
def test_rule_count_total_sourced_from_executive_summary_cache_not_summary_job(client):
    fake_summary = {"status": "ok", "last_updated": None, "rule_count_total": 14203}
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    assert resp.status_code == 200
    assert resp.get_json()["rule_count_total"] == 14203
```

(Note this test deliberately does NOT patch `app.summary_job.get_summary` — if the route still
reads from there, this test will fail with a `KeyError`/mock artifact rather than `14203`,
proving the source switched.)

- [ ] **Step 6: Run test to verify it fails**

Run: `uv run pytest tests/test_external_api_executive.py::test_rule_count_total_sourced_from_executive_summary_cache_not_summary_job -v`
Expected: FAIL (route still calls `summary_job.get_summary()`, which isn't mocked, so it hits
real `_store` defaults — `rules_total` is `None`, not `14203`).

- [ ] **Step 7: Write the implementation**

In `app/routes/external_api_routes.py`'s `ext_executive_summary()`, remove the
`from app.summary_job import get_summary as get_rule_summary` import line and change:

```python
"rule_count_total": get_rule_summary().get("rules_total"),
```

to:

```python
"rule_count_total": summary.get("rule_count_total"),
```

(`summary` is already `executive_summary_cache.get_summary()`, assigned earlier in the
function — no new import needed.)

- [ ] **Step 8: Run tests to verify they pass**

Run: `uv run pytest tests/test_executive_summary_cache.py tests/test_external_api_executive.py -v`
Expected: PASS

- [ ] **Step 9: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS. (Confirms no other test hardcodes the old `summary_job`-sourced value.)

- [ ] **Step 10: Commit**

```bash
git add app/executive_summary_cache.py app/routes/external_api_routes.py tests/test_executive_summary_cache.py tests/test_external_api_executive.py
git commit -m "Source external rule_count_total from the hourly hygiene sweep instead of the daily summary job"
```

---

### Task 2: Rule Hygiene fleet rollup

**Files:**
- Create: `app/hygiene_rollup.py`
- Create: `tests/test_hygiene_rollup.py`
- Modify: `app/executive_summary_cache.py`
- Modify: `tests/test_executive_summary_cache.py`

**Interfaces:**
- Consumes: `hygiene.CHECKS` (dict, keys: `unnamed, unlogged, shadow, disabled, expired, unhit`),
  `hygiene.run_checks(policies, checks, ...)`, `hygiene.find_unused_objects(policies, addresses,
  addr_groups, services, svc_groups)` — existing, from Task 1's neighboring code.
- Produces: `hygiene_rollup.append_run(record: dict) -> None`,
  `hygiene_rollup.get_latest() -> dict | None` — used by Task 6.
- Produces: `executive_summary_cache._store` gains `"rule_hygiene": {"rule_findings_total": int,
  "rule_findings_by_type": dict, "collected_at": str} | None`.

- [ ] **Step 1: Write the failing persistence test**

Create `tests/test_hygiene_rollup.py`:

```python
"""Tests for the rule-hygiene fleet rollup persistence."""

from __future__ import annotations

import app.hygiene_rollup as hygiene_rollup


def test_append_run_and_get_latest(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene_rollup, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json")

    record = {
        "ran_at": "2026-08-28T09:00:00Z",
        "rule_findings_total": 118,
        "rule_findings_by_type": {
            "shadow": 4, "unhit": 60, "unlogged": 12, "expired": 8,
            "disabled": 20, "unnamed": 6, "unused_objects": 8,
        },
    }
    hygiene_rollup.append_run(record)

    assert hygiene_rollup.get_latest() == record


def test_get_latest_returns_none_when_no_history(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene_rollup, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json")

    assert hygiene_rollup.get_latest() is None


def test_append_run_keeps_at_most_30_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene_rollup, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json")

    for i in range(35):
        hygiene_rollup.append_run({"ran_at": f"run-{i}", "rule_findings_total": i, "rule_findings_by_type": {}})

    history = hygiene_rollup.get_history()
    assert len(history) == 30
    assert history[0]["ran_at"] == "run-34"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_hygiene_rollup.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.hygiene_rollup'`.

- [ ] **Step 3: Write the implementation**

Create `app/hygiene_rollup.py`:

```python
"""Fleet-wide rule-hygiene rollup history — persisted so trends survive restarts.

Follows the same JSON-file-at-project-root pattern as device_review_jobs.json
(app/device_review_scheduler.py) and api_tokens.json (app/api_tokens.py).
"""

from __future__ import annotations

from pathlib import Path

from app.atomic_io import atomic_write_json

_ROLLUP_PATH = Path(__file__).parent.parent / "hygiene_rollup.json"
_MAX_RUNS = 30


def get_history() -> list[dict]:
    """Return the rollup history, newest first, or [] if none exists yet."""
    if not _ROLLUP_PATH.exists():
        return []
    try:
        import json

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

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_hygiene_rollup.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add app/hygiene_rollup.py tests/test_hygiene_rollup.py
git commit -m "Add hygiene_rollup persistence module for the fleet-wide rule-hygiene rollup"
```

- [ ] **Step 6: Write the failing sweep-integration test**

Add to `tests/test_executive_summary_cache.py`:

```python
def test_run_hygiene_sweep_computes_and_persists_rule_hygiene_rollup(app_ctx, tmp_path, monkeypatch):
    import app.executive_summary_cache as cache_mod
    import app.hygiene_rollup as hygiene_rollup

    monkeypatch.setattr(hygiene_rollup, "_ROLLUP_PATH", tmp_path / "hygiene_rollup.json")

    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}]
    client.get_devices.return_value = [{"name": "fw1"}]
    client.get_policy_packages.return_value = [{"name": "default", "path": "default"}]
    client.get_policies.return_value = [
        {"policyid": 1, "name": "", "logtraffic": "disable"},
        {"policyid": 2, "name": "rule2"},
    ]
    client.get_addresses.return_value = []
    client.get_address_groups.return_value = []
    client.get_services.return_value = []
    client.get_service_groups.return_value = []

    with patch("app.fmg_helpers.make_client", return_value=client):
        cache_mod._run_hygiene_sweep(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["rule_hygiene"]["rule_findings_total"] >= 0
    assert set(summary["rule_hygiene"]["rule_findings_by_type"]) == {
        "shadow", "unhit", "unlogged", "expired", "disabled", "unnamed", "unused_objects",
    }
    assert summary["rule_hygiene"]["collected_at"] is not None
    assert hygiene_rollup.get_latest()["rule_findings_total"] == summary["rule_hygiene"]["rule_findings_total"]
```

(If the fake FMG client needs different method names for addresses/services than
`get_addresses`/`get_address_groups`/`get_services`/`get_service_groups`, check
`app/fmg_client.py` for the actual method names used elsewhere to fetch those object types for
`find_unused_objects()`'s real callers, and use those exact names — this test's mock must match
whatever `_run_hygiene_sweep` actually calls.)

- [ ] **Step 7: Run test to verify it fails**

Run: `uv run pytest tests/test_executive_summary_cache.py::test_run_hygiene_sweep_computes_and_persists_rule_hygiene_rollup -v`
Expected: FAIL — `KeyError: 'rule_hygiene'`.

- [ ] **Step 8: Write the implementation**

In `app/executive_summary_cache.py`, add `"rule_hygiene": None,` to the `_store` dict literal.

Add the import at the top (alongside the existing `from app.hygiene import run_checks` inside
`_run_hygiene_sweep`): change that line to also import `CHECKS as HYGIENE_CHECK_TYPES,
find_unused_objects`.

Inside `_run_hygiene_sweep()`'s per-package loop, after the existing
`total_policies += len(policies)` / `total_findings += len(run_checks(policies,
_HYGIENE_CHECKS))` lines, add full-check-set accumulation and unused-objects detection:

```python
                    addresses = client.get_addresses(adom)
                    addr_groups = client.get_address_groups(adom)
                    services = client.get_services(adom)
                    svc_groups = client.get_service_groups(adom)

                    all_findings = run_checks(policies, list(HYGIENE_CHECK_TYPES))
                    for f in all_findings:
                        by_type[f["check"]] = by_type.get(f["check"], 0) + 1

                    unused = find_unused_objects(policies, addresses, addr_groups, services, svc_groups)
                    by_type["unused_objects"] = by_type.get("unused_objects", 0) + (
                        len(unused["unused_addresses"]) + len(unused["unused_services"])
                    )
```

(Use whichever exact `client.get_addresses`/`get_address_groups`/`get_services`/
`get_service_groups` method names `app/fmg_client.py` actually defines — confirm during
implementation by grepping `app/fmg_client.py` for the methods `find_unused_objects`'s existing
callers use, e.g. in `app/routes/hygiene_routes.py`.)

Initialize `by_type: dict[str, int] = {}` before the `for adom in adom_names:` loop (same scope
as `total_findings`/`total_policies`).

After the loop, before computing `hygiene_score`, add:

```python
        rule_hygiene_record = {
            "ran_at": datetime.now(UTC).isoformat(),
            "rule_findings_total": sum(by_type.values()),
            "rule_findings_by_type": by_type,
        }
        from app.hygiene_rollup import append_run as _append_hygiene_rollup

        _append_hygiene_rollup(rule_hygiene_record)
```

Add `"rule_hygiene": {**rule_hygiene_record, "collected_at": rule_hygiene_record.pop("ran_at")
and datetime.now(UTC).isoformat()},` — **simpler**, avoid the confusing pop/reuse: instead build
it explicitly:

```python
        with _lock:
            _store.update(
                {
                    "hygiene_score": hygiene_score,
                    "rule_count_total": total_policies,
                    "rule_hygiene": {
                        "rule_findings_total": rule_hygiene_record["rule_findings_total"],
                        "rule_findings_by_type": by_type,
                        "collected_at": datetime.now(UTC).isoformat(),
                    },
                    "status": "ok",
                    "error": None,
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            )
```

(This replaces the existing `_store.update({...})` call at the end of the try block — merge
with Task 1's `rule_count_total` addition into this one dict, since both tasks touch the same
`_store.update` call. If Task 1 was already committed, this step's diff is additive to that same
dict literal.)

- [ ] **Step 9: Run test to verify it passes**

Run: `uv run pytest tests/test_executive_summary_cache.py -v`
Expected: PASS (including Task 1's tests, still)

- [ ] **Step 10: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS

- [ ] **Step 11: Commit**

```bash
git add app/executive_summary_cache.py tests/test_executive_summary_cache.py
git commit -m "Compute fleet-wide rule-hygiene rollup (all 6 checks + unused objects) in the hygiene sweep"
```

---

### Task 3: Device Review severity table and rollup

**Files:**
- Create: `app/device_review_severity.py`
- Create: `tests/test_device_review_severity.py`
- Create: `app/device_review_rollup.py`
- Create: `tests/test_device_review_rollup.py`
- Modify: `app/device_review_scheduler.py`
- Modify: `tests/test_device_review_scheduler.py`

**Interfaces:**
- Produces: `device_review_severity.SEVERITY: dict[str, str]` (26 keys, values one of
  `critical|high|medium|low`) — used by Task 3's rollup aggregation.
- Produces: `device_review_rollup.build_rollup(results: list[dict]) -> dict`,
  `device_review_rollup.append_run(record: dict) -> None`,
  `device_review_rollup.get_latest() -> dict | None` — `get_latest` used by Task 6.
- Consumes: `device_review.CHECKS_META` (list of `{key, name, description, ...}`, no `run` key)
  for check-key/display-name lookup, same as `_build_check_summary`'s `name_to_key` pattern.

- [ ] **Step 1: Write the failing severity-table test**

Create `tests/test_device_review_severity.py`:

```python
"""Tests for the static device-review check severity table."""

from app.device_review import CHECKS
from app.device_review_severity import SEVERITY


def test_every_check_key_has_a_severity():
    check_keys = {c["key"] for c in CHECKS}
    assert set(SEVERITY) == check_keys


def test_severity_values_are_valid():
    valid = {"critical", "high", "medium", "low"}
    assert all(v in valid for v in SEVERITY.values())


def test_default_admin_is_critical():
    assert SEVERITY["default_admin"] == "critical"


def test_ha_sync_is_critical():
    assert SEVERITY["ha_sync"] == "critical"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_device_review_severity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.device_review_severity'`.

- [ ] **Step 3: Write the implementation**

Create `app/device_review_severity.py`:

```python
"""Static severity classification for app.device_review's 26 CIS-derived checks.

The check registry (app/device_review.py CHECKS) has no explicit severity
field -- CIS L1/L2 tiering lives only in free-text descriptions. This table
is a one-time hand classification, reviewed alongside the checks themselves;
update it when a check is added, removed, or reclassified.
"""

from __future__ import annotations

SEVERITY: dict[str, str] = {
    "interface_protocols": "high",
    "ntp_config": "medium",
    "syslog_config": "medium",
    "trusted_hosts": "high",
    "default_admin": "critical",
    "admin_mfa": "critical",
    "idle_timeout": "medium",
    "lockout_threshold": "medium",
    "password_length": "high",
    "log_disk": "medium",
    "log_severity": "low",
    "log_faz": "medium",
    "dns_servers": "low",
    "snmp_version": "high",
    "snmp_readonly": "medium",
    "tls_version": "high",
    "ssh_ciphers": "high",
    "firmware_version": "high",
    "ha_sync": "critical",
    "hostname_changed": "low",
    "admin_port_nondefault": "low",
    "prelogin_banner": "low",
    "timezone_set": "low",
    "vpn_weak_crypto": "critical",
    "vpn_pfs": "high",
    "vpn_ike_version": "high",
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_device_review_severity.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/device_review_severity.py tests/test_device_review_severity.py
git commit -m "Add static severity classification for device review checks"
```

- [ ] **Step 6: Write the failing rollup-aggregation test**

Create `tests/test_device_review_rollup.py`:

```python
"""Tests for device-review fleet rollup aggregation and persistence."""

from __future__ import annotations

import app.device_review_rollup as dr_rollup


def _row(device, check, result):
    return {
        "device": device, "interface": "", "vdom": "root", "ip": "10.0.0.1",
        "type": "system", "status": "", "check": check, "result": result,
        "detail": "", "protocols": [], "has_insecure": False, "has_secure": False,
    }


def test_build_rollup_counts_devices_and_severities(monkeypatch):
    monkeypatch.setattr(
        dr_rollup,
        "_name_to_key",
        {"Default 'admin' Account (CIS)": "default_admin", "DNS Servers (CIS)": "dns_servers"},
    )
    monkeypatch.setattr(dr_rollup, "_severity_for_key", lambda k: {"default_admin": "critical", "dns_servers": "low"}[k])

    results = [
        {
            "device": "fw-01", "ip": "10.0.0.1", "error": None,
            "rows": [_row("fw-01", "Default 'admin' Account (CIS)", "FAIL"), _row("fw-01", "DNS Servers (CIS)", "PASS")],
        },
        {
            "device": "fw-02", "ip": "10.0.0.2", "error": None,
            "rows": [_row("fw-02", "DNS Servers (CIS)", "PASS")],
        },
    ]

    rollup = dr_rollup.build_rollup(results)

    assert rollup["devices_reviewed"] == 2
    assert rollup["devices_with_failures"] == 1
    assert rollup["findings_by_severity"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert rollup["top_failing_checks"] == [{"check": "default_admin", "count": 1}]


def test_build_rollup_excludes_devices_with_errors_from_reviewed_count():
    results = [{"device": "fw-01", "ip": "10.0.0.1", "error": "timeout", "rows": []}]

    rollup = dr_rollup.build_rollup(results)

    assert rollup["devices_reviewed"] == 0
    assert rollup["devices_with_failures"] == 0


def test_append_run_and_get_latest(tmp_path, monkeypatch):
    monkeypatch.setattr(dr_rollup, "_ROLLUP_PATH", tmp_path / "device_review_rollup.json")

    record = {
        "ran_at": "2026-08-28T06:00:00Z", "devices_reviewed": 5, "devices_with_failures": 1,
        "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        "top_failing_checks": [{"check": "dns_servers", "count": 1}],
    }
    dr_rollup.append_run(record)

    assert dr_rollup.get_latest() == record
```

- [ ] **Step 7: Run test to verify it fails**

Run: `uv run pytest tests/test_device_review_rollup.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.device_review_rollup'`.

- [ ] **Step 8: Write the implementation**

Create `app/device_review_rollup.py`:

```python
"""Fleet-wide device-review rollup: aggregation + persisted history.

Aggregation mirrors app.device_review_scheduler._build_check_summary's
name-to-key lookup pattern (row["check"] holds the check's display NAME,
not its key -- unlike app.hygiene's findings, which key by check key
directly). Persistence follows the same JSON-file-at-project-root pattern
as app.hygiene_rollup / app.device_review_scheduler's device_review_jobs.json.
"""

from __future__ import annotations

from pathlib import Path

from app.atomic_io import atomic_write_json
from app.device_review import CHECKS_META
from app.device_review_severity import SEVERITY

_ROLLUP_PATH = Path(__file__).parent.parent / "device_review_rollup.json"
_MAX_RUNS = 30

_name_to_key: dict[str, str] = {c["name"]: c["key"] for c in CHECKS_META}


def _severity_for_key(key: str) -> str:
    return SEVERITY.get(key, "low")


_NON_FAILURE_RESULTS = {"PASS", "INFO"}


def build_rollup(results: list[dict]) -> dict:
    """Aggregate a bulk_device_review_adom()-shaped result list into fleet counts.

    results: list of {device, ip, rows, error} as returned by
    app.routes.device_review_routes.bulk_device_review_adom(). Devices with
    a non-None "error" contribute no rows and are excluded from
    devices_reviewed/devices_with_failures (they weren't actually reviewed).
    """
    reviewed = [d for d in results if not d.get("error")]
    devices_with_failures = 0
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    failing_check_counts: dict[str, int] = {}

    for dev in reviewed:
        device_failed = False
        for row in dev.get("rows", []):
            if row.get("result") in _NON_FAILURE_RESULTS:
                continue
            device_failed = True
            key = _name_to_key.get(row.get("check", ""))
            if key is None:
                continue
            findings_by_severity[_severity_for_key(key)] += 1
            failing_check_counts[key] = failing_check_counts.get(key, 0) + 1
        if device_failed:
            devices_with_failures += 1

    top_failing_checks = [
        {"check": key, "count": count}
        for key, count in sorted(failing_check_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
    ]

    return {
        "devices_reviewed": len(reviewed),
        "devices_with_failures": devices_with_failures,
        "findings_by_severity": findings_by_severity,
        "top_failing_checks": top_failing_checks,
    }


def get_history() -> list[dict]:
    """Return the rollup history, newest first, or [] if none exists yet."""
    if not _ROLLUP_PATH.exists():
        return []
    try:
        import json

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

- [ ] **Step 9: Run test to verify it passes**

Run: `uv run pytest tests/test_device_review_rollup.py -v`
Expected: PASS (4 tests)

- [ ] **Step 10: Commit**

```bash
git add app/device_review_rollup.py tests/test_device_review_rollup.py
git commit -m "Add device_review_rollup aggregation and persistence"
```

- [ ] **Step 11: Write the failing scheduler-integration test**

Add to `tests/test_device_review_scheduler.py`, following the existing
`test_execute_job_sends_email` fixture/monkeypatch pattern:

```python
def test_execute_job_persists_device_review_rollup(jobs_path, monkeypatch, tmp_path):
    from app import device_review_scheduler as sched
    import app.device_review_rollup as dr_rollup

    monkeypatch.setattr(dr_rollup, "_ROLLUP_PATH", tmp_path / "device_review_rollup.json")
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)

    job = sched.create_job({
        "adom": "Customer1", "format": "pdf", "email": "test@corp.com",
        "checks": [], "check_params": {},
    })
    fake_results = [
        {"device": "fw-01", "ip": "10.0.0.1", "error": None, "rows": [
            {"device": "fw-01", "interface": "", "vdom": "root", "ip": "10.0.0.1",
             "type": "system", "status": "", "check": "Default 'admin' Account (CIS)",
             "result": "FAIL", "detail": "", "protocols": [], "has_insecure": False, "has_secure": False},
        ]},
    ]
    monkeypatch.setattr(
        "app.device_review_scheduler._bulk_device_review_adom",
        lambda adom, checks, check_params, max_workers=4: fake_results,
    )
    monkeypatch.setattr(
        "app.device_review_scheduler._send_email",
        lambda to, subject, body_html, attachments: None,
    )

    sched._execute_job(job["id"])

    latest = dr_rollup.get_latest()
    assert latest is not None
    assert latest["devices_reviewed"] == 1
    assert latest["devices_with_failures"] == 1
```

(Reuse whatever `fake_meta` fixture/constant the existing `test_execute_job_sends_email` test
in this file already defines for `_CHECKS_META` — do not redefine it if it already exists at
module scope in this test file.)

- [ ] **Step 12: Run test to verify it fails**

Run: `uv run pytest tests/test_device_review_scheduler.py::test_execute_job_persists_device_review_rollup -v`
Expected: FAIL — `dr_rollup.get_latest()` returns `None` (nothing persists the rollup yet).

- [ ] **Step 13: Write the implementation**

In `app/device_review_scheduler.py`'s `_execute_job()`, after the line
`all_rows = [r for dev in results for r in dev.get("rows", [])]` and before
`fail_count = sum(...)`, add:

```python
        from app.device_review_rollup import append_run as _append_dr_rollup, build_rollup as _build_dr_rollup

        dr_rollup_record = {
            "ran_at": datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z",
            **_build_dr_rollup(results),
        }
        _append_dr_rollup(dr_rollup_record)
```

- [ ] **Step 14: Run test to verify it passes**

Run: `uv run pytest tests/test_device_review_scheduler.py -v`
Expected: PASS (all tests, including the existing `test_execute_job_sends_email`)

- [ ] **Step 15: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS

- [ ] **Step 16: Commit**

```bash
git add app/device_review_scheduler.py tests/test_device_review_scheduler.py
git commit -m "Persist a fleet-wide device-review rollup on every scheduled review run"
```

---

### Task 4: Version EOL flagging

**Files:**
- Create: `app/version_eol.py`
- Create: `tests/test_version_eol.py`
- Modify: `app/routes/external_api_routes.py`
- Modify: `tests/test_external_api_executive.py`

**Interfaces:**
- Produces: `version_eol.is_eol(version: str) -> bool`.
- Changes: `_version_breakdown()`'s return shape from `{version: count}` to
  `{version: {"count": count, "eol": bool}}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_version_eol.py`:

```python
"""Tests for the static FortiOS version end-of-support table."""

from app.version_eol import is_eol


def test_known_eol_version_returns_true():
    assert is_eol("v6.4.2") is True


def test_current_version_returns_false():
    assert is_eol("v7.4.5") is False


def test_unknown_version_defaults_to_not_eol():
    assert is_eol("v99.9.9") is False


def test_handles_version_without_v_prefix():
    assert is_eol("6.4.2") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_version_eol.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.version_eol'`.

- [ ] **Step 3: Write the implementation**

Create `app/version_eol.py`:

```python
"""Static FortiOS end-of-support table. Update when Fortinet publishes new EOL dates.

Source: Fortinet's published FortiOS Support Lifecycle
(https://support.fortinet.com/Information/Support-Lifecycle.aspx as of authoring).
Versions are matched by exact string after stripping a leading "v"/"V".
"""

from __future__ import annotations

_EOL_VERSIONS: set[str] = {
    "6.0.0", "6.0.1", "6.0.2", "6.0.3", "6.0.4", "6.0.5",
    "6.2.0", "6.2.1", "6.2.2", "6.2.3",
    "6.4.0", "6.4.1", "6.4.2", "6.4.3", "6.4.4", "6.4.5",
    "6.4.6", "6.4.7", "6.4.8", "6.4.9", "6.4.10", "6.4.11",
    "6.4.12", "6.4.13", "6.4.14",
    "7.0.0", "7.0.1", "7.0.2",
}


def is_eol(version: str) -> bool:
    """Return True if version is a known end-of-support FortiOS release.

    Unrecognized versions (including newer releases not yet in the table)
    return False -- absence of data must never render as a false EOL flag.
    """
    normalized = version.lstrip("vV")
    return normalized in _EOL_VERSIONS
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_version_eol.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/version_eol.py tests/test_version_eol.py
git commit -m "Add static FortiOS version end-of-support table"
```

- [ ] **Step 6: Write the failing route test**

Add to `tests/test_external_api_executive.py`:

```python
def test_version_breakdown_annotates_eol_versions(client):
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value={"status": "ok"}),
        patch(
            "app.versions_cache.get_cached",
            return_value={"devices": [
                {"name": "fw1", "version": "v7.4.5"},
                {"name": "fw2", "version": "v6.4.2"},
            ]},
        ),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["version_breakdown"] == {
        "v7.4.5": {"count": 1, "eol": False},
        "v6.4.2": {"count": 1, "eol": True},
    }
```

- [ ] **Step 7: Run test to verify it fails**

Run: `uv run pytest tests/test_external_api_executive.py::test_version_breakdown_annotates_eol_versions -v`
Expected: FAIL — `data["version_breakdown"] == {"v7.4.5": 1, "v6.4.2": 1}` (old flat shape).

- [ ] **Step 8: Write the implementation**

In `app/routes/external_api_routes.py`, update `_version_breakdown()`:

```python
def _version_breakdown() -> dict:
    """Firmware version -> {count, eol}, from the all-ADOM versions cache."""
    from collections import Counter

    from app import versions_cache
    from app.version_eol import is_eol

    devices = versions_cache.get_cached().get("devices") or []
    counts = Counter(d.get("version", "n/a") for d in devices)
    return {version: {"count": count, "eol": is_eol(version)} for version, count in counts.items()}
```

- [ ] **Step 9: Run test to verify it passes**

Run: `uv run pytest tests/test_external_api_executive.py -v`
Expected: PASS. **Check the existing test
`test_returns_summary_payload_when_authorized`** (which currently asserts
`data["version_breakdown"] == {"v7.4.5": 2, "v7.2.9": 1}`, the old flat shape) — update it in
place to `{"v7.4.5": {"count": 2, "eol": False}, "v7.2.9": {"count": 1, "eol": False}}`.

- [ ] **Step 10: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS

- [ ] **Step 11: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_executive.py
git commit -m "Annotate version_breakdown entries with an EOL flag"
```

---

### Task 5: Per-field-group freshness and split sweep status

**Files:**
- Modify: `app/executive_summary_cache.py`
- Modify: `app/routes/external_api_routes.py`
- Modify: `tests/test_executive_summary_cache.py`
- Modify: `tests/test_external_api_executive.py`

**Interfaces:**
- Changes: `_store` gains `device_sweep_status`, `hygiene_sweep_status`,
  `device_sweep_collected_at`, `hygiene_sweep_collected_at` (all string/None); the single shared
  `"status"`/`"last_updated"` keys are computed, not sweep-written (see below).
- Changes: external payload gains `schema_version`, `device_sweep_status`,
  `hygiene_sweep_status`, `device_sweep_collected_at`, `hygiene_sweep_collected_at`,
  `rule_count_collected_at`; keeps `status`/`last_updated` as deprecated aliases for one release.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_executive_summary_cache.py`:

```python
def test_device_sweep_error_does_not_affect_hygiene_sweep_status(app_ctx):
    import app.executive_summary_cache as cache_mod

    # A prior successful hygiene sweep already set hygiene_sweep_status ok.
    with cache_mod._lock:
        cache_mod._store["hygiene_sweep_status"] = "ok"
        cache_mod._store["hygiene_sweep_collected_at"] = "2026-08-28T09:00:00Z"

    with patch("app.fmg_helpers.make_client", side_effect=RuntimeError("FMG down")):
        cache_mod._run_device_sweep(app_ctx)

    summary = cache_mod.get_summary()
    assert summary["device_sweep_status"] == "error"
    assert summary["hygiene_sweep_status"] == "ok"


def test_run_device_sweep_sets_device_sweep_collected_at(app_ctx):
    import app.executive_summary_cache as cache_mod

    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_adoms.return_value = [{"name": "Customer1"}]
    client.get_devices.return_value = [{"name": "fw1", "conn_status": "up"}]

    with patch("app.fmg_helpers.make_client", return_value=client):
        cache_mod._run_device_sweep(app_ctx)

    assert cache_mod.get_summary()["device_sweep_collected_at"] is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_executive_summary_cache.py -k "device_sweep_status or device_sweep_collected_at" -v`
Expected: FAIL — `KeyError`.

- [ ] **Step 3: Write the implementation**

In `app/executive_summary_cache.py`'s `_store` dict literal, add:

```python
    "device_sweep_status": "pending",
    "hygiene_sweep_status": "pending",
    "device_sweep_collected_at": None,
    "hygiene_sweep_collected_at": None,
```

In `_run_device_sweep()`, replace every `_store["status"] = "running"` /
`_store["status"] = "error"` / the `"status": "ok"` key inside the final `_store.update({...})`
with `device_sweep_status` equivalents, and add `"device_sweep_collected_at":
datetime.now(UTC).isoformat()` alongside the existing `"last_updated"` key in that same update.
Concretely: the `with _lock: _store["status"] = "running"; _store["error"] = None` block near
the top becomes `_store["device_sweep_status"] = "running"`; the `except` block's `_store["status"]
= "error"` becomes `_store["device_sweep_status"] = "error"`; the success `_store.update({...})`
dict's `"status": "ok"` becomes `"device_sweep_status": "ok", "device_sweep_collected_at":
datetime.now(UTC).isoformat()`.

Apply the identical mechanical change in `_run_hygiene_sweep()`, using
`hygiene_sweep_status`/`hygiene_sweep_collected_at` instead.

Also keep `_store["status"]`/`_store["last_updated"]` being written in both sweeps (don't remove
them) — they're read by `get_summary()`'s consumers as the deprecated aliases assembled in Task
6's route change; simplest is to leave the pre-existing lines untouched and additively write the
new split keys alongside them.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_executive_summary_cache.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest tests/ -v`
Expected: PASS (device_review_scheduler/hygiene_rollup tests from Tasks 1-4 unaffected — they
don't assert on `"status"`).

- [ ] **Step 6: Commit**

```bash
git add app/executive_summary_cache.py tests/test_executive_summary_cache.py
git commit -m "Split device/hygiene sweep status and add per-sweep collected_at timestamps"
```

- [ ] **Step 7: Write the failing route test**

Add to `tests/test_external_api_executive.py`:

```python
def test_payload_includes_schema_version_and_split_freshness(client):
    fake_summary = {
        "status": "ok", "last_updated": "2026-08-28T09:45:00Z",
        "device_sweep_status": "ok", "hygiene_sweep_status": "ok",
        "device_sweep_collected_at": "2026-08-28T09:45:00Z",
        "hygiene_sweep_collected_at": "2026-08-28T09:00:00Z",
        "rule_count_total": 14203,
    }
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["schema_version"] == 1
    assert data["device_sweep_status"] == "ok"
    assert data["hygiene_sweep_status"] == "ok"
    assert data["device_sweep_collected_at"] == "2026-08-28T09:45:00Z"
    assert data["hygiene_sweep_collected_at"] == "2026-08-28T09:00:00Z"
    assert data["rule_count_collected_at"] == "2026-08-28T09:00:00Z"
    assert data["status"] == "ok"  # deprecated alias, still present
```

- [ ] **Step 8: Run test to verify it fails**

Run: `uv run pytest tests/test_external_api_executive.py::test_payload_includes_schema_version_and_split_freshness -v`
Expected: FAIL — `KeyError: 'schema_version'`.

- [ ] **Step 9: Write the implementation**

In `app/routes/external_api_routes.py`'s `ext_executive_summary()`, add to the `payload` dict
literal:

```python
        "schema_version": 1,
        "device_sweep_status": summary.get("device_sweep_status"),
        "hygiene_sweep_status": summary.get("hygiene_sweep_status"),
        "device_sweep_collected_at": summary.get("device_sweep_collected_at"),
        "hygiene_sweep_collected_at": summary.get("hygiene_sweep_collected_at"),
        "rule_count_collected_at": summary.get("hygiene_sweep_collected_at"),
```

(`rule_count_total` is computed inside the hygiene sweep per Task 1/2, so it shares that sweep's
`collected_at`.) `"status"` and `"last_updated"` stay exactly as they already are in the dict —
no change needed there, they're the deprecated aliases by construction.

- [ ] **Step 10: Run test to verify it passes**

Run: `uv run pytest tests/test_external_api_executive.py -v`
Expected: PASS

- [ ] **Step 11: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS

- [ ] **Step 12: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_executive.py
git commit -m "Add schema_version and per-field-group freshness to the executive payload"
```

---

### Task 6: Assemble `device_review` and `rule_hygiene` into the payload

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Modify: `tests/test_external_api_executive.py`

**Interfaces:**
- Consumes: `device_review_rollup.get_latest()` (Task 3), `hygiene_rollup.get_latest()` (or
  `executive_summary_cache.get_summary()["rule_hygiene"]` — Task 2 already stores the latest
  hygiene rollup in `_store`, so this task reads from there rather than re-reading the JSON
  file, avoiding a redundant disk read on every request).
- Produces: payload gains `"device_review"` and `"rule_hygiene"` keys (`None` when no rollup has
  run yet).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_external_api_executive.py`:

```python
def test_payload_includes_device_review_and_rule_hygiene_rollups(client):
    fake_summary = {
        "status": "ok",
        "rule_hygiene": {
            "rule_findings_total": 118,
            "rule_findings_by_type": {"shadow": 4, "unhit": 60},
            "collected_at": "2026-08-28T09:00:00Z",
        },
    }
    fake_dr_rollup = {
        "ran_at": "2026-08-28T06:00:00Z",
        "devices_reviewed": 42,
        "devices_with_failures": 7,
        "findings_by_severity": {"critical": 1, "high": 3, "medium": 9, "low": 4},
        "top_failing_checks": [{"check": "default_admin", "count": 5}],
    }
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
        patch("app.device_review_rollup.get_latest", return_value=fake_dr_rollup),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["rule_hygiene"]["rule_findings_total"] == 118
    assert data["device_review"]["devices_reviewed"] == 42
    assert data["device_review"]["collected_at"] == "2026-08-28T06:00:00Z"


def test_payload_device_review_none_when_no_rollup_yet(client):
    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value={"status": "ok"}),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
        patch("app.device_review_rollup.get_latest", return_value=None),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["device_review"] is None
    assert data["rule_hygiene"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_external_api_executive.py -k "device_review_and_rule_hygiene or device_review_none" -v`
Expected: FAIL — `KeyError: 'device_review'`.

- [ ] **Step 3: Write the implementation**

In `app/routes/external_api_routes.py`, add a helper near `_version_breakdown()`:

```python
def _device_review_rollup() -> dict | None:
    from app.device_review_rollup import get_latest

    latest = get_latest()
    if latest is None:
        return None
    return {
        "devices_reviewed": latest["devices_reviewed"],
        "devices_with_failures": latest["devices_with_failures"],
        "findings_by_severity": latest["findings_by_severity"],
        "top_failing_checks": latest["top_failing_checks"],
        "collected_at": latest["ran_at"],
    }
```

In `ext_executive_summary()`, add to the `payload` dict:

```python
        "device_review": _device_review_rollup(),
        "rule_hygiene": summary.get("rule_hygiene"),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_external_api_executive.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_executive.py
git commit -m "Assemble device_review and rule_hygiene rollups into the executive payload"
```

---

### Task 7: AI usage attribution — schema, providers, retention, payload

**Files:**
- Modify: `app/ai_usage.py`
- Modify: `app/llm/base.py`
- Modify: `app/llm/codex_provider.py`
- Modify: `app/llm/claude_provider.py`
- Modify: `app/llm/ollama_provider.py`
- Modify: `app/pending_changes_ai.py`, `app/config_diff_scheduler.py`,
  `app/device_review_ai.py`, `app/device_review_scheduler.py`, `app/host_metrics_ai.py`,
  `app/hygiene_ai.py`, `app/routes/rule_review_routes.py`, `app/routes/psirt_routes.py`
- Modify: `app/routes/admin_routes.py`
- Modify: `app/routes/external_api_routes.py`
- Modify: `tests/test_ai_usage.py`
- Modify: whichever test file covers `/admin/api/ai-usage` (confirmed as
  `tests/test_admin_ai_assist_setting.py` in this repo)
- Modify: `tests/test_external_api_executive.py`

**Interfaces:**
- Changes: `record_usage()` gains `feature: str, user: str | None = None` keyword params.
- Changes: `LLMProvider.narrate(self, system_prompt, user_prompt, *, feature)` — `feature`
  becomes a required keyword-only param on the abstract method and all three implementations.
- Produces: `ai_usage.usage_summary(start, end, num_buckets=24, by_feature=False)` — when
  `by_feature=True`, adds a `"by_feature"` key: `{feature: {calls, cost_usd, failures}}`.
- Produces: `ai_usage.prune_old_data() -> None` (mirrors `host_metrics.prune_old_data()`).

- [ ] **Step 1: Write the failing migration test**

Add to `tests/test_ai_usage.py`:

```python
def test_init_db_adds_feature_and_user_columns_to_existing_table(tmp_path, monkeypatch):
    import sqlite3

    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE ai_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
        "provider TEXT NOT NULL, model TEXT NOT NULL, input_tokens INTEGER NOT NULL, "
        "output_tokens INTEGER NOT NULL, cost_usd REAL NOT NULL, success INTEGER NOT NULL, error TEXT)"
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(ai_usage, "_DB_PATH", db_path)
    ai_usage._init_db()

    conn = sqlite3.connect(db_path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(ai_usage)")}
    conn.close()
    assert "feature" in columns
    assert "user" in columns


def test_record_usage_stores_feature_and_user(usage_db):
    ai_usage.record_usage(
        provider="claude", model="claude-sonnet-4-5", input_tokens=100, output_tokens=50,
        cost_usd=0.01, success=True, feature="device_review_summary", user="alice",
    )
    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert rows[0]["feature"] == "device_review_summary"
    assert rows[0]["user"] == "alice"


def test_record_usage_feature_and_user_default_to_none(usage_db):
    ai_usage.record_usage(
        provider="claude", model="claude-sonnet-4-5", input_tokens=100, output_tokens=50,
        cost_usd=0.01, success=True, feature="device_review_summary",
    )
    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert rows[0]["user"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_ai_usage.py -k "feature_and_user or adds_feature" -v`
Expected: FAIL — `sqlite3.OperationalError: table ai_usage has no column named feature`.

- [ ] **Step 3: Write the implementation**

In `app/ai_usage.py`, update `_SCHEMA` and `_init_db()`:

```python
_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cost_usd REAL NOT NULL,
    success INTEGER NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_usage_timestamp ON ai_usage (timestamp);
"""


def _init_db() -> None:
    conn = sqlite3.connect(_DB_PATH)
    try:
        conn.executescript(_SCHEMA)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(ai_usage)")}
        if "feature" not in columns:
            conn.execute("ALTER TABLE ai_usage ADD COLUMN feature TEXT")
        if "user" not in columns:
            conn.execute("ALTER TABLE ai_usage ADD COLUMN user TEXT")
        conn.commit()
    finally:
        conn.close()
```

Update `record_usage()`'s signature and INSERT:

```python
def record_usage(
    *,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
    success: bool,
    feature: str,
    user: str | None = None,
    error: str | None = None,
) -> None:
    """Record one AI Assist LLM call. Never raises -- a tracking failure
    must never break the actual AI Assist request that triggered it."""
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        try:
            conn.execute(
                "INSERT INTO ai_usage (timestamp, provider, model, input_tokens, "
                "output_tokens, cost_usd, success, error, feature, user) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    dt.datetime.now(dt.UTC).isoformat(),
                    provider,
                    model,
                    input_tokens,
                    output_tokens,
                    cost_usd,
                    1 if success else 0,
                    error,
                    feature,
                    user,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
```

(`query_usage()`'s `SELECT *` already returns `sqlite3.Row` objects supporting `row["feature"]`/
`row["user"]` once the columns exist — no change needed there, per the existing full-file read
showing it doesn't enumerate columns explicitly. If it does enumerate columns explicitly,
extend that column list the same way as the INSERT above.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_ai_usage.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/ai_usage.py tests/test_ai_usage.py
git commit -m "Add feature/user columns to ai_usage.db via idempotent migration"
```

- [ ] **Step 6: Write the failing provider-signature test**

Add to `tests/test_ai_usage.py` (or a new small test near the provider modules if one already
tests them — check for `tests/test_llm_providers.py` first; if none exists, add these to
`tests/test_ai_usage.py`):

```python
def test_claude_provider_narrate_requires_feature_and_records_it(usage_db, monkeypatch):
    from app.llm.claude_provider import ClaudeProvider

    class _FakeResponse:
        class _Content:
            text = "narrated"
        content = [_Content()]
        class _Usage:
            input_tokens = 10
            output_tokens = 5
        usage = _Usage()

    fake_client = MagicMock()
    fake_client.messages.create.return_value = _FakeResponse()
    monkeypatch.setattr(
        "anthropic.Anthropic", lambda **kwargs: fake_client, raising=False
    )

    provider = ClaudeProvider(model="claude-sonnet-4-5")
    provider.narrate("system", "user", feature="device_review_summary")

    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert rows[-1]["feature"] == "device_review_summary"
```

(Adjust the `anthropic.Anthropic` mock target/response shape to match exactly what
`app/llm/claude_provider.py`'s real `narrate()` body calls — read that file's exact SDK call
before writing this mock, since the earlier research pass captured the `record_usage` call sites
but not the full Anthropic SDK response object shape.)

- [ ] **Step 7: Run test to verify it fails**

Run: `uv run pytest tests/test_ai_usage.py -k claude_provider_narrate -v`
Expected: FAIL — `TypeError: narrate() got an unexpected keyword argument 'feature'`.

- [ ] **Step 8: Write the implementation**

In `app/llm/base.py`, update the abstract method signature to
`def narrate(self, system_prompt: str, user_prompt: str, *, feature: str, user: str | None = None) -> str:`.

In each of `app/llm/codex_provider.py`, `app/llm/claude_provider.py`,
`app/llm/ollama_provider.py`: change `def narrate(self, system_prompt: str, user_prompt: str) ->
str:` to `def narrate(self, system_prompt: str, user_prompt: str, *, feature: str, user: str |
None = None) -> str:`, and add `feature=feature, user=user` to every `record_usage(...)` call
in that file (there are 3 call sites per provider file, as catalogued in research: two failure
branches and one success branch — add the two new kwargs to all three).

- [ ] **Step 9: Run test to verify it passes**

Run: `uv run pytest tests/test_ai_usage.py -v`
Expected: PASS

- [ ] **Step 10: Run the full suite to find every now-broken `.narrate(...)` call site**

Run: `uv run pytest tests/ -v`
Expected: FAIL at multiple call sites — every one of the eight caller locations from the
research pass now raises `TypeError: narrate() missing 1 required keyword-only argument:
'feature'`. This step's purpose is to get the exact list of failing tests to fix next.

- [ ] **Step 11: Update every caller with its feature string and user**

For each call site, add `feature="<name>"` (and `user=session.get("user")` where a Flask session
is available, omit `user` — defaults to `None` — in the two scheduler call sites):

- `app/pending_changes_ai.py::build_diff_narrative()` → its `.narrate(...)` call gets
  `feature="pending_changes_diff_summary"`. If this function itself is called from both a route
  (`pending_changes_routes.py`) and a scheduler (`config_diff_scheduler.py`), thread a `user:
  str | None = None` parameter through `build_diff_narrative()` itself so each caller can supply
  its own value: the route passes `user=session.get("user")`, the scheduler passes nothing
  (defaults to `None`).
- `app/device_review_ai.py::build_narrative()` → `feature="device_review_summary"`, same
  dual-caller threading as above for `app/routes/device_review_routes.py` (route,
  `user=session.get("user")`) vs. `app/device_review_scheduler.py` (scheduler, `user=None`).
- `app/host_metrics_ai.py::build_trend_narrative()` → `feature="host_metrics_ai_summary"`,
  `user=session.get("user")` (route-only caller).
- `app/hygiene_ai.py::explain_finding()` → `feature="hygiene_explain_finding"`,
  `user=session.get("user")` (route-only caller).
- `app/routes/rule_review_routes.py`'s two direct `get_provider().narrate(...)` call sites
  (`rr_ai_assist()`, `rr_ai_assist_fqdn()`) → `feature="rule_review_ai_assist"` and
  `feature="rule_review_ai_assist_fqdn"` respectively, `user=session.get("user")`.
- `app/routes/psirt_routes.py`'s `psirt_extract()` (via whatever `extract_advisory()` calls
  internally) → `feature="psirt_extract"`, `user=session.get("user")`. If `extract_advisory()`
  is a separate module function taking a `provider` object, thread `user` through it the same
  way as `build_diff_narrative()`/`build_narrative()` above.

For each file: import `session` from `flask` if not already imported (check first — most route
files already have it), make the edit, then run that file's existing test(s) to confirm no
regression before moving to the next file.

- [ ] **Step 12: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS — every caller now supplies `feature`, no remaining `TypeError`s.

- [ ] **Step 13: Commit**

```bash
git add app/llm/ app/pending_changes_ai.py app/config_diff_scheduler.py app/device_review_ai.py app/device_review_scheduler.py app/host_metrics_ai.py app/hygiene_ai.py app/routes/rule_review_routes.py app/routes/psirt_routes.py tests/test_ai_usage.py
git commit -m "Thread a required feature label (and best-effort user) through every AI Assist call site"
```

- [ ] **Step 14: Write the failing by-feature summary test**

Add to `tests/test_ai_usage.py`:

```python
def test_usage_summary_by_feature(usage_db):
    ai_usage.record_usage(
        provider="claude", model="m", input_tokens=10, output_tokens=5, cost_usd=0.01,
        success=True, feature="device_review_summary",
    )
    ai_usage.record_usage(
        provider="claude", model="m", input_tokens=20, output_tokens=10, cost_usd=0.02,
        success=False, feature="psirt_extract",
    )

    result = ai_usage.usage_summary(_dt(1), _dt(-1), by_feature=True)

    assert result["by_feature"]["device_review_summary"] == {"calls": 1, "cost_usd": pytest.approx(0.01), "failures": 0}
    assert result["by_feature"]["psirt_extract"] == {"calls": 1, "cost_usd": pytest.approx(0.02), "failures": 1}


def test_usage_summary_omits_by_feature_key_by_default(usage_db):
    result = ai_usage.usage_summary(_dt(1), _dt(-1))
    assert "by_feature" not in result
```

- [ ] **Step 15: Run test to verify it fails**

Run: `uv run pytest tests/test_ai_usage.py -k by_feature -v`
Expected: FAIL — `TypeError: usage_summary() got an unexpected keyword argument 'by_feature'`.

- [ ] **Step 16: Write the implementation**

In `app/ai_usage.py`, update `usage_summary()`'s signature to
`def usage_summary(start: dt.datetime, end: dt.datetime, num_buckets: int = 24, *, by_feature: bool = False) -> dict:`,
and before the final `return {...}`, add:

```python
    result = {
        "buckets": buckets,
        "total_calls": total_calls,
        "total_cost_usd": total_cost,
        "total_failures": total_failures,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
    }
    if by_feature:
        by_feature_totals: dict[str, dict] = {}
        for row in rows:
            key = row["feature"] or "unknown"
            entry = by_feature_totals.setdefault(key, {"calls": 0, "cost_usd": 0.0, "failures": 0})
            entry["calls"] += 1
            entry["cost_usd"] += row["cost_usd"]
            if not row["success"]:
                entry["failures"] += 1
        result["by_feature"] = by_feature_totals
    return result
```

(Replace the existing bare `return {...}` at the end of the function with this — `rows` is
already in scope from `query_usage(start, end)` at the top of the function.)

- [ ] **Step 17: Run test to verify it passes**

Run: `uv run pytest tests/test_ai_usage.py -v`
Expected: PASS

- [ ] **Step 18: Commit**

```bash
git add app/ai_usage.py tests/test_ai_usage.py
git commit -m "Add optional by_feature breakdown to usage_summary()"
```

- [ ] **Step 19: Write the failing retention test**

Add to `tests/test_ai_usage.py`:

```python
def test_prune_old_data_deletes_rows_older_than_90_days(usage_db):
    import sqlite3

    conn = sqlite3.connect(usage_db)
    old_ts = (_dt(90 * 24 + 1)).isoformat()
    conn.execute(
        "INSERT INTO ai_usage (timestamp, provider, model, input_tokens, output_tokens, "
        "cost_usd, success, error, feature, user) VALUES (?, 'claude', 'm', 1, 1, 0.0, 1, NULL, 'x', NULL)",
        (old_ts,),
    )
    conn.commit()
    conn.close()

    ai_usage.record_usage(
        provider="claude", model="m", input_tokens=1, output_tokens=1, cost_usd=0.0,
        success=True, feature="x",
    )

    ai_usage.prune_old_data()

    rows = ai_usage.query_usage(_dt(200 * 24), _dt(-1))
    assert len(rows) == 1
```

- [ ] **Step 20: Run test to verify it fails**

Run: `uv run pytest tests/test_ai_usage.py::test_prune_old_data_deletes_rows_older_than_90_days -v`
Expected: FAIL — `AttributeError: module 'app.ai_usage' has no attribute 'prune_old_data'`.

- [ ] **Step 21: Write the implementation**

In `app/ai_usage.py`, add (mirroring `app/host_metrics.py::prune_old_data()`'s structure, but
this table uses an ISO-string `timestamp` column, not an integer `ts`, so the cutoff comparison
is a string comparison against an ISO cutoff):

```python
_RETENTION_DAYS = 90


def prune_old_data() -> None:
    """Delete rows older than _RETENTION_DAYS. Never raises."""
    try:
        cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=_RETENTION_DAYS)).isoformat()
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        try:
            conn.execute("DELETE FROM ai_usage WHERE timestamp < ?", (cutoff,))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
```

Register it in `app/__init__.py`'s `create_app()`, alongside `host_metrics.init_scheduler`'s
existing `prune_old_data` cron registration — check that function's exact `scheduler.add_job(...)`
call for `host_metrics_prune` and add an analogous job for `ai_usage.prune_old_data` (e.g. `id="ai_usage_prune"`, same `hour=3` daily cadence, guarded by a new `_AI_USAGE_PRUNE_STARTED`
config flag following the same guard pattern as every other scheduler registration in that file).
If `host_metrics.init_scheduler` already owns a single `BackgroundScheduler` instance that other
modules register jobs onto (rather than each module creating its own scheduler), reuse that
same scheduler object instead of creating a new one — confirm which pattern `app/__init__.py`
uses (single shared scheduler vs. one per module) before writing this registration, since the
research pass captured `summary_job`'s and `executive_summary_cache`'s own separate
`BackgroundScheduler()` instances, suggesting each module owns its own — in that case, add a
small `init_scheduler(app)` function to `app/ai_usage.py` itself, following that same
one-scheduler-per-module convention, and call it from `app/__init__.py` with its own guard flag.

- [ ] **Step 22: Run test to verify it passes**

Run: `uv run pytest tests/test_ai_usage.py -v`
Expected: PASS

- [ ] **Step 23: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS

- [ ] **Step 24: Commit**

```bash
git add app/ai_usage.py app/__init__.py tests/test_ai_usage.py
git commit -m "Add 90-day retention pruning for ai_usage.db"
```

- [ ] **Step 25: Write the failing payload test**

Add to `tests/test_external_api_executive.py`:

```python
def test_payload_includes_ai_usage_by_feature_when_ai_enabled(client):
    fake_summary = {"status": "ok"}
    fake_usage = {
        "buckets": [], "total_calls": 2, "total_cost_usd": 0.03, "total_failures": 0,
        "total_input_tokens": 0, "total_output_tokens": 0,
        "by_feature": {"device_review_summary": {"calls": 1, "cost_usd": 0.01, "failures": 0}},
    }
    with (
        patch("app.routes.external_api_routes.get_setting", side_effect=lambda k, default=None: {
            "external_api_enabled": True, "ai_assist_enabled": True,
        }.get(k, default)),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
        patch("app.executive_summary_cache.get_summary", return_value=fake_summary),
        patch("app.versions_cache.get_cached", return_value={"devices": []}),
        patch("app.backup_scheduler.get_all_jobs", return_value=[]),
        patch("app.device_review_rollup.get_latest", return_value=None),
        patch("app.ai_usage.usage_summary", return_value=fake_usage),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer good-token"},
        )
    data = resp.get_json()
    assert data["ai_usage_by_feature"] == fake_usage["by_feature"]
```

(Check `_ai_usage_24h()`'s existing implementation in `external_api_routes.py` for exactly how
it calls `usage_summary` today — likely `usage_summary(start, end)` without `by_feature` — so
you know whether to add a second call with `by_feature=True` or extend the existing one.)

- [ ] **Step 26: Run test to verify it fails**

Run: `uv run pytest tests/test_external_api_executive.py::test_payload_includes_ai_usage_by_feature_when_ai_enabled -v`
Expected: FAIL — `KeyError: 'ai_usage_by_feature'`.

- [ ] **Step 27: Write the implementation**

In `app/routes/external_api_routes.py`, inside `ext_executive_summary()`'s
`if ai_enabled:` block, add:

```python
        payload["ai_usage_by_feature"] = _ai_usage_by_feature()
```

Add the helper near `_ai_usage_24h()`:

```python
def _ai_usage_by_feature() -> dict:
    from datetime import UTC, datetime, timedelta

    from app.ai_usage import usage_summary

    end = datetime.now(UTC)
    start = end - timedelta(hours=24)
    return usage_summary(start, end, by_feature=True).get("by_feature", {})
```

- [ ] **Step 28: Run test to verify it passes**

Run: `uv run pytest tests/test_external_api_executive.py -v`
Expected: PASS

- [ ] **Step 29: Run the full suite and lint**

Run: `uv run pytest tests/ -v && uv run ruff check app/ && uv run ruff format --check app/`
Expected: PASS

- [ ] **Step 30: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_executive.py
git commit -m "Add ai_usage_by_feature to the executive payload when AI Assist is enabled"
```

---

### Task 8: Full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest tests/ -v`
Expected: PASS, zero failures.

- [ ] **Step 2: Run lint and format check**

Run: `uv run ruff check app/ wsgi.py manage_users.py && uv run ruff format --check app/ wsgi.py manage_users.py`
Expected: no errors. Fix any and re-run.

- [ ] **Step 3: Manual smoke check**

Start the app locally (check `README.md` for the run command), obtain a bearer token via the
admin API-tokens UI, and confirm with `curl`:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:5000/external/api/executive/summary | python3 -m json.tool
```

1. `schema_version` is `1`.
2. `rule_count_total` is populated and, after waiting for one hygiene-sweep cycle, its value
   matches what the hygiene sweep's log line reports (`executive_summary_cache: hygiene sweep
   done in ...`).
3. `version_breakdown` entries are `{count, eol}` objects.
4. `device_review`/`rule_hygiene` are `null` until at least one scheduled device-review job and
   one hygiene sweep have run, then populate.
5. `device_sweep_status`/`hygiene_sweep_status` update independently — stop the FMG connection
   briefly and confirm one flips to `"error"` without affecting the other.
6. With AI Assist enabled and at least one AI Assist feature used (e.g. a device-review
   narrative), `ai_usage_by_feature` shows that feature's call.
7. Confirm the internal `/api/summary/history` (or whatever route
   `api_routes.py::summary_history()` is registered at) still returns data — `summary_job.py`
   was not touched, so this should be unaffected, but verify directly.

- [ ] **Step 4: Report results**

No commit for this task — verification only.

---

## Self-Review Notes

- **Spec coverage:** design doc section 3 (device review rollup) → Task 3; section 4 (hygiene
  rollup) → Task 2; section 5 (rule count cadence) → Task 1, with the `summary_job.py`-preserving
  correction folded in; section 6 (version EOL) → Task 4; section 7 (AI usage) → Task 7; section
  9 (schema_version + freshness) → Tasks 5–6.
- **Back-compat:** `status`/`last_updated` remain in the payload unchanged; `version_breakdown`'s
  shape change (flat int → `{count, eol}`) is the one payload change that is NOT
  backward-compatible for a consumer doing raw arithmetic on values — flagged explicitly here
  since the design doc's "additive/backward-compatible" framing doesn't perfectly cover this one
  field. 4tExecutive's own plan (separate document) must special-case this field regardless
  (it already does, via `get_widget_series`'s existing nested-field pattern), so this is an
  acceptable, anticipated exception — not a defect.
- **Type consistency:** `device_review_rollup.build_rollup()`'s return dict keys
  (`devices_reviewed`, `devices_with_failures`, `findings_by_severity`, `top_failing_checks`)
  match exactly what `_device_review_rollup()` in Task 6 reads.
