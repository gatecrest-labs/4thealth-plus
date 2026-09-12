# Drill-down Details Lists Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, capped, ordered `details` drill-down list inside five executive-summary rollup objects so a future consumer (4tExecutive's per-device drill-down table, P6/W4-2) can show which specific devices/packages/versions drove each fleet-wide number, without any live FMG calls of its own.

**Architecture:** Each details list is derived from data a scheduled sweep *already computes in memory* — no new FMG calls, no new schedule. Each list is capped at 50 entries and sorted most-severe-or-most-relevant first, with the exact ordering documented per list (see Global Constraints). Lists are added as new, purely additive keys/fields on the existing payload; every existing v1/v2 field keeps its current shape except one explicit, documented exception (`psirt.top_advisory.devices`, see Task 5).

**Tech Stack:** Python 3.14, Flask, pytest, ruff. No new dependencies.

**Spec:** `~/Downloads/4texecutive2.md` section "Wave 4", prompt W4-2 (P6) — 4thealth-plus third only. Also see `~/code/github/ai/4thealth-plus/docs/superpowers/specs/2026-08-24-executive-summary-api-design.md` for the existing payload's design rationale.

## Global Constraints

- Every details list is capped at **50 items**.
- Every details list documents its own exact ordering (see per-task "Ordering" note) — there is no single global rule, because each rollup has different data available to rank by.
- No task may add a new FMG call, background thread, or scheduler. All five lists are built from data an existing sweep already holds in memory at the point the aggregate is computed.
- Every new/changed field is additive except the one documented exception in Task 5 (`psirt.top_advisory.devices` changes from `int` to a list — the old int is preserved under a new name, `device_count`, so no information is destroyed).
- Follow this repo's existing style: pure aggregation functions (no I/O) are unit-tested directly with plain dict/list fixtures; route-level tests hit `/external/api/executive/summary` through the Flask test client with the relevant module's cache monkeypatched. See `tests/test_executive_summary_cache.py` and `tests/test_external_api_executive.py` for the existing pattern.
- Run `uv run pytest tests/ -v --tb=short` and `uv run ruff check app/ wsgi.py manage_users.py && uv run ruff format --check app/ wsgi.py manage_users.py` before each commit (matches `.github/workflows/ci.yml`).
- Every commit message ends with:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
  ```

---

## Task 1: `device_review.details`

**Files:**
- Modify: `app/device_review_rollup.py`
- Modify: `app/device_review_scheduler.py:249-266` (wires `details` into the persisted record — no functional change to what's already being called, just capture one more value)
- Modify: `app/routes/external_api_routes.py:121-134` (`_device_review_rollup()`)
- Test: `tests/test_device_review_rollup.py`
- Test: `tests/test_external_api_executive.py`

**Interfaces:**
- Consumes: `bulk_device_review_adom()`'s existing return shape `list[{"device": str, "ip": str, "rows": list[dict], "error": str|None}]` (each `row` has `"check"` = a CHECKS_META display name, and `"result"` = one of `"PASS"|"FAIL"|"INSECURE"|"WARN"|"INFO"|"CONFIG_MISSING"`), and the module-level `_name_to_key: dict[str,str]` and `_severity_for_key(key) -> str` already in `app/device_review_rollup.py`.
- Produces: `build_details(results: list[dict], adom: str) -> list[dict]` in `app/device_review_rollup.py`, each entry `{"device": str, "adom": str, "failed_checks": list[str], "worst_severity": str}`. Route payload gains `device_review.details` (same shape, `None` when there is no rollup history yet, `[]` when the latest run reviewed devices but found no failures).

**Ordering:** capped at 50; sorted by `worst_severity` ascending in the order `critical, high, medium, low` (most severe first), tie-broken by `len(failed_checks)` descending, tie-broken by `device` name ascending.

- [ ] **Step 1: Write the failing unit test for `build_details`**

Add to `tests/test_device_review_rollup.py`:

```python
def test_build_details_orders_by_severity_then_failed_count_then_name():
    from app.device_review_rollup import build_details

    results = [
        {
            "device": "fw-b",
            "ip": "10.0.0.2",
            "rows": [
                {"check": "Default admin account", "result": "FAIL"},
                {"check": "DNS servers", "result": "FAIL"},
            ],
            "error": None,
        },
        {
            "device": "fw-a",
            "ip": "10.0.0.1",
            "rows": [{"check": "Default admin account", "result": "FAIL"}],
            "error": None,
        },
        {
            "device": "fw-c",
            "ip": "10.0.0.3",
            "rows": [{"check": "DNS servers", "result": "PASS"}],
            "error": None,
        },
        {"device": "fw-d", "ip": "10.0.0.4", "rows": [], "error": "timeout"},
    ]

    details = build_details(results, adom="root")

    assert details == [
        {
            "device": "fw-b",
            "adom": "root",
            "failed_checks": ["default_admin", "dns_servers"],
            "worst_severity": "critical",
        },
        {
            "device": "fw-a",
            "adom": "root",
            "failed_checks": ["default_admin"],
            "worst_severity": "critical",
        },
    ]


def test_build_details_caps_at_50_most_severe_first():
    from app.device_review_rollup import build_details

    results = [
        {
            "device": f"fw-{i:03d}",
            "ip": "10.0.0.1",
            "rows": [{"check": "DNS servers", "result": "FAIL"}],
            "error": None,
        }
        for i in range(60)
    ]
    # Make one device critical so it must sort first despite name order.
    results[59]["rows"] = [{"check": "Default admin account", "result": "FAIL"}]

    details = build_details(results, adom="root")

    assert len(details) == 50
    assert details[0]["device"] == "fw-059"
    assert details[0]["worst_severity"] == "critical"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_device_review_rollup.py -v -k build_details`
Expected: FAIL with `ImportError` / `AttributeError: module 'app.device_review_rollup' has no attribute 'build_details'`.

- [ ] **Step 3: Implement `build_details`**

Add to `app/device_review_rollup.py`, after `build_rollup()` (after the existing `return {"devices_reviewed": ..., ...}` block, before `def get_history()`):

```python
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_MAX_DETAILS = 50


def build_details(results: list[dict], adom: str) -> list[dict]:
    """Per-device drill-down for the fleet rollup's "details" field.

    Devices with an "error" (never actually reviewed) are excluded, same as
    build_rollup(). A device with no failing rows is also excluded — this
    list is "what's wrong", not a full device roster.

    Capped at _MAX_DETAILS, most severe first: sorted by worst_severity
    (critical, high, medium, low), then by number of failed checks
    (descending), then by device name (ascending) for a stable order among
    equally-severe devices.
    """
    entries = []
    for dev in results:
        if dev.get("error"):
            continue
        failed_checks: list[str] = []
        for row in dev.get("rows", []):
            if row.get("result") in _NON_FAILURE_RESULTS:
                continue
            key = _name_to_key.get(row.get("check", ""))
            if key is None:
                continue
            failed_checks.append(key)
        if not failed_checks:
            continue
        worst = min(
            (_severity_for_key(k) for k in failed_checks),
            key=lambda s: _SEVERITY_RANK.get(s, 99),
        )
        entries.append(
            {
                "device": dev.get("device", ""),
                "adom": adom,
                "failed_checks": failed_checks,
                "worst_severity": worst,
            }
        )

    entries.sort(
        key=lambda e: (
            _SEVERITY_RANK.get(e["worst_severity"], 99),
            -len(e["failed_checks"]),
            e["device"],
        )
    )
    return entries[:_MAX_DETAILS]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_device_review_rollup.py -v -k build_details`
Expected: PASS

- [ ] **Step 5: Wire `details` into the persisted rollup record**

In `app/device_review_scheduler.py`, change the import block and record construction at lines 251-265 from:

```python
        from app.device_review_rollup import (
            append_run as _append_dr_rollup,
        )
        from app.device_review_rollup import (
            build_rollup as _build_dr_rollup,
        )

        dr_rollup_record = {
            "ran_at": datetime.datetime.now(datetime.UTC)
            .replace(tzinfo=None)
            .isoformat()
            + "Z",
            "adom": adom,
            **_build_dr_rollup(results),
        }
        _append_dr_rollup(dr_rollup_record)
```

to:

```python
        from app.device_review_rollup import (
            append_run as _append_dr_rollup,
        )
        from app.device_review_rollup import (
            build_details as _build_dr_details,
        )
        from app.device_review_rollup import (
            build_rollup as _build_dr_rollup,
        )

        dr_rollup_record = {
            "ran_at": datetime.datetime.now(datetime.UTC)
            .replace(tzinfo=None)
            .isoformat()
            + "Z",
            "adom": adom,
            **_build_dr_rollup(results),
            "details": _build_dr_details(results, adom),
        }
        _append_dr_rollup(dr_rollup_record)
```

- [ ] **Step 6: Expose `details` in the route payload**

In `app/routes/external_api_routes.py`, change `_device_review_rollup()` (lines 121-134) from:

```python
def _device_review_rollup() -> dict | None:
    """Latest device review rollup, or None if no rollup has run yet."""
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

to:

```python
def _device_review_rollup() -> dict | None:
    """Latest device review rollup, or None if no rollup has run yet.

    "details" is a capped, most-severe-first per-device drill-down — see
    app.device_review_rollup.build_details() for the exact cap/ordering.
    Older persisted records (written before this field existed) fall back
    to [] rather than a missing key, so old history entries still validate
    against the current schema.
    """
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
        "details": latest.get("details", []),
    }
```

- [ ] **Step 7: Add a route-level test**

Add to `tests/test_external_api_executive.py` (find the existing test that monkeypatches `app.device_review_rollup.get_latest` for `_device_review_rollup` coverage, and add a sibling test near it):

```python
def test_executive_summary_includes_device_review_details(client, app_ctx):
    from app import device_review_rollup

    record = {
        "ran_at": "2026-09-12T00:00:00Z",
        "adom": "root",
        "devices_reviewed": 2,
        "devices_with_failures": 1,
        "findings_by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0},
        "top_failing_checks": [{"check": "default_admin", "count": 1}],
        "details": [
            {
                "device": "fw-a",
                "adom": "root",
                "failed_checks": ["default_admin"],
                "worst_severity": "critical",
            }
        ],
    }
    with patch.object(device_review_rollup, "get_latest", return_value=record):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer test-token"},
        )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["device_review"]["details"] == record["details"]
```

Check the top of `tests/test_external_api_executive.py` for how `client`/`app_ctx` fixtures and the bearer token are already set up in that file (there is no shared `client` fixture in `conftest.py` — this file builds its own Flask test client and `api_tokens.json` fixture inline; match whatever pattern the existing tests in that file already use for auth and client setup rather than introducing a new one). Import `from unittest.mock import patch` at the top of the file if not already imported.

- [ ] **Step 8: Run the full test file and verify it passes**

Run: `uv run pytest tests/test_device_review_rollup.py tests/test_external_api_executive.py -v --tb=short`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add app/device_review_rollup.py app/device_review_scheduler.py app/routes/external_api_routes.py tests/test_device_review_rollup.py tests/test_external_api_executive.py
git commit -m "$(cat <<'EOF'
feat: add device_review.details drill-down list to executive summary

Per-device failing-check breakdown, capped at 50, most severe first
(critical > high > medium > low, then most failed checks, then name).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 2: `rule_hygiene.details`

**Files:**
- Modify: `app/hygiene_rollup.py`
- Modify: `app/executive_summary_cache.py:536-670` (`_run_hygiene_sweep`)
- Modify: `app/routes/external_api_routes.py:211-228` (`_hygiene_rollup()`), and the route body at line 356 (the live in-memory `rule_hygiene` value already carries whatever `_run_hygiene_sweep` put in `_store["rule_hygiene"]`, so it needs the new field added there too, not just in the cold-start fallback)
- Test: `tests/test_executive_summary_cache.py`
- Test: `tests/test_external_api_executive.py`

**Interfaces:**
- Consumes: `app.hygiene.run_checks(policies, check_types) -> list[dict]`, each finding `{"policy_id": str, "policy_name": str, "seq": int, "check": str, "detail": str}` (plus an extra `"severity"` key only for `"over_permissive"` findings — do not assume it's present for others).
- Produces: `build_details(package_findings: list[dict]) -> list[dict]` in `app/hygiene_rollup.py`, taking a list of `{"package": str, "adom": str, "findings": list[dict]}` entries (one per policy package swept) and returning the capped/sorted list. `rule_hygiene.details` appears both in the live sweep's `_store["rule_hygiene"]` and in the persisted `hygiene_rollup.json` / `_hygiene_rollup()` cold-start fallback, same shape either way: `[{"package": str, "adom": str, "findings": list[dict]}]`.

**Ordering:** capped at 50; each per-package entry's `findings` list is the *full* list of that package's findings (from `run_checks(policies, list(HYGIENE_CHECK_TYPES))`, i.e. all check types, not just the cheap `_HYGIENE_CHECKS` subset used for `hygiene_score`). Packages are sorted by `len(findings)` descending (most findings first), tie-broken by `adom` ascending, then `package` ascending.

- [ ] **Step 1: Write the failing unit test for `build_details`**

Add to a new test file `tests/test_hygiene_rollup.py` (this module currently has no dedicated test file — check with `ls tests/test_hygiene_rollup.py` first; if it already exists, append to it instead of overwriting):

```python
from app.hygiene_rollup import build_details


def test_build_details_orders_by_finding_count_then_adom_then_package():
    package_findings = [
        {
            "package": "pkg-b",
            "adom": "root",
            "findings": [{"check": "unnamed", "policy_id": "1"}],
        },
        {
            "package": "pkg-a",
            "adom": "root",
            "findings": [
                {"check": "unnamed", "policy_id": "1"},
                {"check": "unlogged", "policy_id": "2"},
            ],
        },
        {"package": "pkg-c", "adom": "root", "findings": []},
    ]

    details = build_details(package_findings)

    assert details == [
        {
            "package": "pkg-a",
            "adom": "root",
            "findings": [
                {"check": "unnamed", "policy_id": "1"},
                {"check": "unlogged", "policy_id": "2"},
            ],
        },
        {
            "package": "pkg-b",
            "adom": "root",
            "findings": [{"check": "unnamed", "policy_id": "1"}],
        },
    ]


def test_build_details_caps_at_50():
    package_findings = [
        {
            "package": f"pkg-{i:03d}",
            "adom": "root",
            "findings": [{"check": "unnamed", "policy_id": str(i)}],
        }
        for i in range(60)
    ]

    details = build_details(package_findings)

    assert len(details) == 50
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_hygiene_rollup.py -v`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement `build_details` in `app/hygiene_rollup.py`**

Add after the module-level constants (`_MAX_RUNS = 30`):

```python
_MAX_DETAILS = 50


def build_details(package_findings: list[dict]) -> list[dict]:
    """Per-package drill-down for the fleet rollup's "details" field.

    package_findings: [{"package": str, "adom": str, "findings": list[dict]}],
    one entry per policy package swept this cycle. Packages with no
    findings are excluded. Capped at _MAX_DETAILS, most relevant first:
    sorted by number of findings (descending), then adom (ascending), then
    package (ascending) for a stable order among equally-sized packages.
    """
    entries = [p for p in package_findings if p.get("findings")]
    entries.sort(key=lambda p: (-len(p["findings"]), p["adom"], p["package"]))
    return entries[:_MAX_DETAILS]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_hygiene_rollup.py -v`
Expected: PASS

- [ ] **Step 5: Collect per-package findings during the hygiene sweep and wire in `details`**

In `app/executive_summary_cache.py`, inside `_run_hygiene_sweep`, the per-package loop (around lines 569-610) already computes `all_findings = run_checks(policies, list(HYGIENE_CHECK_TYPES))` per package. Change the function to also accumulate a `package_findings` list. Edit as follows:

Before the `with make_client() as client:` block (around line 569), add:

```python
        package_findings: list[dict] = []
```

Inside the package loop, immediately after the existing line:

```python
                    all_findings = run_checks(policies, list(HYGIENE_CHECK_TYPES))
                    for f in all_findings:
                        by_type[f["check"]] = by_type.get(f["check"], 0) + 1
```

add:

```python
                    package_findings.append(
                        {"package": pkg_path, "adom": adom, "findings": all_findings}
                    )
```

Then, in the `rule_hygiene_record` construction (around line 635-639), change:

```python
        rule_hygiene_record = {
            "ran_at": datetime.now(UTC).isoformat(),
            "rule_findings_total": sum(by_type.values()),
            "rule_findings_by_type": by_type,
        }
        from app.hygiene_rollup import append_run as _append_hygiene_rollup

        _append_hygiene_rollup(rule_hygiene_record)
```

to:

```python
        from app.hygiene_rollup import build_details as _build_hygiene_details

        hygiene_details = _build_hygiene_details(package_findings)
        rule_hygiene_record = {
            "ran_at": datetime.now(UTC).isoformat(),
            "rule_findings_total": sum(by_type.values()),
            "rule_findings_by_type": by_type,
            "details": hygiene_details,
        }
        from app.hygiene_rollup import append_run as _append_hygiene_rollup

        _append_hygiene_rollup(rule_hygiene_record)
```

Then find where `_store["rule_hygiene"]` is set later in the same function (search for `"rule_hygiene": rule_hygiene_record` or similar inside the `with _lock: _store.update({...})` block that follows) and confirm it stores the whole `rule_hygiene_record` dict (so `details` rides along automatically). If instead only a subset of fields is copied into `_store`, add `"details": hygiene_details` to that dict literal explicitly.

- [ ] **Step 6: Add `details` to the cold-start fallback and route payload**

In `app/routes/external_api_routes.py`, change `_hygiene_rollup()` (lines 211-228) from:

```python
    return {
        "rule_findings_total": latest["rule_findings_total"],
        "rule_findings_by_type": latest["rule_findings_by_type"],
        "collected_at": latest["ran_at"],
    }
```

to:

```python
    return {
        "rule_findings_total": latest["rule_findings_total"],
        "rule_findings_by_type": latest["rule_findings_by_type"],
        "collected_at": latest["ran_at"],
        "details": latest.get("details", []),
    }
```

The live-sweep path (`summary.get("rule_hygiene") or _hygiene_rollup()` at the route body, line 356) already carries whatever `_store["rule_hygiene"]` holds from Step 5, so no further change is needed there — but re-read the route function after Step 5 to confirm `details` is actually present in both branches before moving on.

- [ ] **Step 7: Add tests for the sweep and the route**

In `tests/test_executive_summary_cache.py`, find the existing test(s) for `_run_hygiene_sweep` (search for `_run_hygiene_sweep` or `rule_findings_by_type`) and add a case asserting the mocked `run_checks`/`get_policies`/`get_policy_packages` fixture data produces a `details` list in the resulting `_store["rule_hygiene"]` with the expected package/adom/findings shape. Mirror whatever mocking pattern (likely `unittest.mock.patch` on `app.fmg_helpers.make_client`) the existing hygiene-sweep tests already use in that file.

In `tests/test_external_api_executive.py`, add a route-level test analogous to Task 1 Step 7, monkeypatching `app.hygiene_rollup.get_latest` to return a record with a `details` list and asserting `body["rule_hygiene"]["details"]` matches.

- [ ] **Step 8: Run tests**

Run: `uv run pytest tests/test_hygiene_rollup.py tests/test_executive_summary_cache.py tests/test_external_api_executive.py -v --tb=short`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add app/hygiene_rollup.py app/executive_summary_cache.py app/routes/external_api_routes.py tests/test_hygiene_rollup.py tests/test_executive_summary_cache.py tests/test_external_api_executive.py
git commit -m "$(cat <<'EOF'
feat: add rule_hygiene.details drill-down list to executive summary

Per-package findings breakdown, capped at 50, most-findings-first.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 3: `version_breakdown.eol_devices`

**Files:**
- Modify: `app/routes/external_api_routes.py:68-80` (`_version_breakdown()`)
- Test: `tests/test_external_api_executive.py`

**Interfaces:**
- Consumes: `app.versions_cache.get_cached()["devices"] -> list[{"name": str, "version": str, "adom": str, "status": str}]`, `app.version_eol.is_eol(version: str) -> bool`.
- Produces: `_version_breakdown()` gains one more key inside its returned dict, `"eol_devices"`, a capped/sorted list `[{"device": str, "adom": str, "version": str}]`. This key lives alongside the existing per-version-string keys (e.g. `"v7.4.2"`) in the same dict — document clearly (in both the docstring and `docs/api-reference.md`, Task 6) that `"eol_devices"` is a reserved key name, not a firmware version string.

**Ordering:** capped at 50; sorted by parsed version ascending (oldest/most out-of-date first — i.e. worst first), tie-broken by device name ascending. Version strings are parsed as `(major, mr, patch)` int tuples via a small helper; a version equal to `"n/a"` or otherwise unparseable sorts last (least useful information, not "most severe").

- [ ] **Step 1: Write the failing test**

Add to `tests/test_external_api_executive.py`:

```python
def test_version_breakdown_includes_eol_devices_oldest_first(client, app_ctx):
    from app import versions_cache

    devices = [
        {"name": "fw-new", "version": "v7.6.1", "adom": "root", "status": "green"},
        {"name": "fw-old-b", "version": "v6.2.5", "adom": "root", "status": "green"},
        {"name": "fw-old-a", "version": "v6.0.11", "adom": "branch", "status": "green"},
        {"name": "fw-noversion", "version": "n/a", "adom": "root", "status": "offline"},
    ]
    with patch.object(
        versions_cache, "get_cached", return_value={"devices": devices}
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer test-token"},
        )
    assert resp.status_code == 200
    body = resp.get_json()
    eol = body["version_breakdown"]["eol_devices"]
    assert eol == [
        {"device": "fw-old-a", "adom": "branch", "version": "v6.0.11"},
        {"device": "fw-old-b", "adom": "root", "version": "v6.2.5"},
    ]
```

Check `app/version_eol.py`'s `_EOL_VERSIONS` set to confirm `"v6.0.11"` and `"v6.2.5"` (or two other genuinely-EOL version strings already in that set) are present — use whichever two EOL version strings actually exist in `_EOL_VERSIONS` at the time of writing the test, adjusting the fixture above to match, so the test doesn't depend on `is_eol()` being monkeypatched.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_external_api_executive.py -v -k eol_devices`
Expected: FAIL with `KeyError: 'eol_devices'`.

- [ ] **Step 3: Implement**

Change `_version_breakdown()` in `app/routes/external_api_routes.py` from:

```python
def _version_breakdown() -> dict:
    """Firmware version -> {count, eol}, from the all-ADOM versions cache."""
    from collections import Counter

    from app import versions_cache
    from app.version_eol import is_eol

    devices = versions_cache.get_cached().get("devices") or []
    counts = Counter(d.get("version", "n/a") for d in devices)
    return {
        version: {"count": count, "eol": is_eol(version)}
        for version, count in counts.items()
    }
```

to:

```python
_MAX_EOL_DEVICES = 50


def _version_sort_key(version: str) -> tuple[int, int, int, int]:
    """Parse "vMAJOR.MR.PATCH" for ascending (oldest-first) sort.

    Returns (1, 0, 0, 0) for anything unparseable (e.g. "n/a") so it always
    sorts after every real version — being unable to determine a device's
    version is not the same as it being the oldest one.
    """
    import re

    m = re.match(r"^v(\d+)\.(\d+)(?:\.(\d+))?$", version or "")
    if not m:
        return (1, 0, 0, 0)
    major, mr, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    return (0, major, mr, patch)


def _version_breakdown() -> dict:
    """Firmware version -> {count, eol}, from the all-ADOM versions cache.

    "eol_devices" is a reserved key in this dict (not a version string): a
    capped, oldest-first list of every device running an EOL version, for
    the drill-down details view. See docs/api-reference.md for the cap and
    ordering.
    """
    from collections import Counter

    from app import versions_cache
    from app.version_eol import is_eol

    devices = versions_cache.get_cached().get("devices") or []
    counts = Counter(d.get("version", "n/a") for d in devices)
    breakdown = {
        version: {"count": count, "eol": is_eol(version)}
        for version, count in counts.items()
    }

    eol_devices = [
        {
            "device": d.get("name", ""),
            "adom": d.get("adom", ""),
            "version": d.get("version", "n/a"),
        }
        for d in devices
        if is_eol(d.get("version", "n/a"))
    ]
    eol_devices.sort(
        key=lambda d: (_version_sort_key(d["version"]), d["device"])
    )
    breakdown["eol_devices"] = eol_devices[:_MAX_EOL_DEVICES]
    return breakdown
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_external_api_executive.py -v -k eol_devices`
Expected: PASS

- [ ] **Step 5: Run the full test file (guard against breaking existing `version_breakdown` consumers/tests)**

Run: `uv run pytest tests/test_external_api_executive.py -v --tb=short`
Expected: PASS. If any existing test asserts `_version_breakdown()`'s return value with an exact-dict-equality check (rather than checking specific keys), update that assertion to account for the new `eol_devices` key.

- [ ] **Step 6: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_executive.py
git commit -m "$(cat <<'EOF'
feat: add version_breakdown.eol_devices drill-down list

Capped at 50, oldest firmware first. eol_devices is a reserved key
inside version_breakdown, not a version string.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 4: Silent devices rollup (new)

There is no existing "silent devices" / log-forwarding-freshness concept anywhere in this codebase (confirmed by grep for `silent`, `last_log`, `not_forwarding`, `log_forwarding`, `checkin`). This task builds a minimal version from the one connectivity signal already available in the device sweep — FMG's `conn_status` field (1 = connected to FMG) — and documents the gap for `last_log_at` (which would require FortiAnalyzer log-freshness data this codebase does not currently query) as a spike, following this repo's existing convention (see `docs/superpowers/specs/2026-09-10-device-backup-age-spike.md` for the precedent).

**Files:**
- Modify: `app/executive_summary_cache.py` (`_run_device_sweep`, and the pure-aggregation-helpers section)
- Modify: `app/routes/external_api_routes.py` (new `_silent_devices()` helper + route payload)
- Create: `docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md`
- Test: `tests/test_executive_summary_cache.py`
- Test: `tests/test_external_api_executive.py`

**Interfaces:**
- Consumes: the device sweep's existing `devices_flat_by_adom: dict[str, list[dict]]` (already built in `_run_device_sweep`, each device dict currently `{"name": str, "version": str, "conn_status": int|None}`).
- Produces: `_build_silent_devices(devices_flat_by_adom: dict[str, list[dict]]) -> tuple[int, list[dict]]` in `app/executive_summary_cache.py`, returning `(devices_silent_count, details)` where `details` is `[{"devid": str, "devname": str, "last_log_at": None}]`, capped at 50. New top-level route payload key `"silent_devices": {"devices_silent": int, "details": list[dict], "collected_at": iso_str|None}`.

**Ordering:** capped at 50; sorted by `adom` ascending (need to track it per device — see Step 3), then `devname` ascending. There is no severity gradient available (a device is either reporting or it isn't), so ordering falls back to a stable alphabetical key rather than a fabricated severity.

`last_log_at` is always `None` in this release — no FortiAnalyzer log-freshness field is read anywhere in this codebase yet (confirmed by the grep above), so there's nothing honest to put there. This mirrors the existing `change_control.oldest_pending_change_days` omission pattern (see `app/executive_summary_cache.py`'s module docstring) and is documented in the spike doc created in Step 5. `devid` uses the device's FMG serial number (`sn`) when available, falling back to its name when not — see Step 3 for why `sn` needs to be added to the sweep's per-device flat dict.

- [ ] **Step 1: Write the failing unit test**

Add to `tests/test_executive_summary_cache.py`:

```python
def test_build_silent_devices_counts_and_details_offline_devices():
    from app.executive_summary_cache import _build_silent_devices

    devices_flat_by_adom = {
        "root": [
            {"name": "fw-a", "sn": "SN-A", "version": "v7.4.2", "conn_status": 1},
            {"name": "fw-b", "sn": "SN-B", "version": "v7.4.2", "conn_status": 0},
        ],
        "branch": [
            {"name": "fw-c", "sn": "", "version": "v7.4.2", "conn_status": 0},
        ],
    }

    count, details = _build_silent_devices(devices_flat_by_adom)

    assert count == 2
    assert details == [
        {"devid": "SN-B", "devname": "fw-b", "last_log_at": None},
        {"devid": "fw-c", "devname": "fw-c", "last_log_at": None},
    ]


def test_build_silent_devices_caps_at_50():
    from app.executive_summary_cache import _build_silent_devices

    devices_flat_by_adom = {
        "root": [
            {
                "name": f"fw-{i:03d}",
                "sn": f"SN-{i:03d}",
                "version": "v7.4.2",
                "conn_status": 0,
            }
            for i in range(60)
        ]
    }

    count, details = _build_silent_devices(devices_flat_by_adom)

    assert count == 60
    assert len(details) == 50
```

Note the sort test above relies on `adom` ordering ("branch" > "root" alphabetically would put branch's fw-c *after* root's devices — re-check: "branch" < "root" alphabetically, so fw-c from "branch" actually sorts *before* fw-b from "root". Fix the expected order in the test to `[{"devid": "fw-c", ...}, {"devid": "SN-B", ...}]` to match alphabetical adom ordering — write the assertion to match whatever your implementation actually produces once Step 3 is done, using this note to catch the mistake before it's committed.**

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_executive_summary_cache.py -v -k silent_devices`
Expected: FAIL (`ImportError`/`AttributeError`).

- [ ] **Step 3: Implement `_build_silent_devices` and thread `adom`/`sn` through the sweep**

In `app/executive_summary_cache.py`, add near the other pure-aggregation helpers (after `_count_out_of_sync`, before `_pending_diff_count`):

```python
_MAX_SILENT_DEVICES = 50


def _build_silent_devices(
    devices_flat_by_adom: dict[str, list[dict]],
) -> tuple[int, list[dict]]:
    """Devices FortiManager reports as not connected (conn_status != 1).

    This is a connectivity proxy, not a log-freshness check: FortiManager
    connectivity and FortiAnalyzer log forwarding are different signals,
    and this codebase does not currently query the latter (see
    docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md).
    last_log_at is therefore always None here — never fabricated.

    Capped at _MAX_SILENT_DEVICES, sorted by adom then device name
    (there's no severity gradient for a binary online/offline signal).
    """
    entries = []
    for adom, devices in devices_flat_by_adom.items():
        for d in devices:
            if d.get("conn_status") == 1:
                continue
            name = d.get("name", "")
            entries.append(
                {
                    "adom": adom,
                    "devid": d.get("sn") or name,
                    "devname": name,
                    "last_log_at": None,
                }
            )

    entries.sort(key=lambda e: (e["adom"], e["devname"]))
    count = len(entries)
    details = [
        {"devid": e["devid"], "devname": e["devname"], "last_log_at": e["last_log_at"]}
        for e in entries[:_MAX_SILENT_DEVICES]
    ]
    return count, details
```

Now thread `sn` through the sweep's flat device dict. In `_run_device_sweep`, find the `flat = {...}` construction (in the per-ADOM `for d in raw:` loop):

```python
                    flat = {
                        "name": d.get("name", ""),
                        "version": _device_version(d),
                        "conn_status": d.get("conn_status"),
                    }
```

Change to:

```python
                    flat = {
                        "name": d.get("name", ""),
                        "version": _device_version(d),
                        "conn_status": d.get("conn_status"),
                        "sn": d.get("sn", ""),
                    }
```

Then, later in the same function where `_store.update({...})` is called, add the silent-devices computation. Find:

```python
        online, total = _classify_online(devices_flat)
```

and add right after it:

```python
        devices_silent, silent_details = _build_silent_devices(devices_flat_by_adom)
```

Then in the `_store.update({...})` dict literal, add two new keys:

```python
                    "devices_silent": devices_silent,
                    "silent_devices_details": silent_details,
```

Also add both keys to the initial `_store: dict = {...}` module-level literal near the top of the file (alongside `"by_adom": {}` etc.):

```python
    "devices_silent": None,
    "silent_devices_details": [],
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_executive_summary_cache.py -v -k silent_devices`
Expected: PASS

- [ ] **Step 5: Write the spike doc**

Create `docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md`:

```markdown
# Spike: silent-devices `last_log_at` field

**Date:** 2026-09-12
**Status:** resolved (partial) — connectivity proxy shipped, log-freshness deferred

## Question

The Wave 4 drill-down spec (`~/Downloads/4texecutive2.md`, prompt W4-2)
asks for a "silent devices" rollup shaped
`[{devid, devname, last_log_at}]` — devices that have stopped sending
logs. No such concept existed anywhere in this codebase before this
change (confirmed by grep for `silent`, `last_log`, `not_forwarding`,
`log_forwarding`, `checkin` across `app/` and `docs/` — zero hits).

## What shipped

`app.executive_summary_cache._build_silent_devices()` uses the one
connectivity signal already read by the existing device sweep — FMG's
`conn_status` field on `/dvmdb/adom/{adom}/device` (1 = connected to
FortiManager). A device with `conn_status != 1` is counted as "silent"
and appears in `silent_devices.details`, capped at 50, sorted by ADOM
then device name.

This is a **connectivity** proxy (is the device reachable from
FortiManager?), not a **log-freshness** check (is the device still
forwarding logs to FortiAnalyzer?). The two can disagree in both
directions: a device can be connected to FMG but have stopped logging
(e.g. a misconfigured `log_faz` setting — see the existing `log_faz`
Device Review check in `app/device_review_severity.py`), or briefly
disconnected from FMG while still logging normally.

## Why `last_log_at` is always `None`

No module in this codebase currently queries FortiAnalyzer for
per-device last-log timestamps. The closest existing FortiAnalyzer
touchpoint is `app/infra_health_cache.py`'s SNMP health poll of the
FortiAnalyzer *appliance itself* (CPU/mem/disk), not per-device log
activity. Fabricating a value here would be worse than omitting it —
same principle as `change_control.oldest_pending_change_days` (see
`app/executive_summary_cache.py`'s module docstring) and
`lifecycle.models_unknown` (`app/model_eos.py`).

## Resolution

Ship the connectivity proxy now (it's genuinely useful — an
unreachable device also isn't logging). Leave `last_log_at` as `None`
until a real FortiAnalyzer log-query API is confirmed against lab
hardware, at which point `_build_silent_devices()` should be extended
(or replaced) to use actual log timestamps instead of `conn_status`.
Candidate API: FortiAnalyzer's `/logview/adom/{adom}/logsearch` or a
per-device last-log report via FortiView — neither has been confirmed
against the lab FortiAnalyzer for this purpose (distinct from the
already-confirmed admin-access/threat-stats FortiView queries shipped
in 4tlog's P12/P13).
```

- [ ] **Step 6: Expose `silent_devices` in the route payload**

In `app/routes/external_api_routes.py`, add a new helper near `_lifecycle()`:

```python
def _silent_devices(summary: dict) -> dict:
    """Devices FortiManager reports as not connected — see
    app.executive_summary_cache._build_silent_devices() and
    docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md for
    why last_log_at is always None in this release."""
    return {
        "devices_silent": summary.get("devices_silent"),
        "details": summary.get("silent_devices_details") or [],
        "collected_at": summary.get("device_sweep_collected_at"),
    }
```

Then add `"silent_devices": _silent_devices(summary),` to the payload dict in `ext_executive_summary()`, next to the existing `"lifecycle": _lifecycle(summary),` line.

- [ ] **Step 7: Add a route-level test**

Add to `tests/test_external_api_executive.py`:

```python
def test_executive_summary_includes_silent_devices(client, app_ctx):
    from app import executive_summary_cache

    with patch.dict(
        executive_summary_cache._store,
        {
            "devices_silent": 2,
            "silent_devices_details": [
                {"devid": "SN-B", "devname": "fw-b", "last_log_at": None}
            ],
            "device_sweep_collected_at": "2026-09-12T00:00:00+00:00",
        },
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer test-token"},
        )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["silent_devices"] == {
        "devices_silent": 2,
        "details": [{"devid": "SN-B", "devname": "fw-b", "last_log_at": None}],
        "collected_at": "2026-09-12T00:00:00+00:00",
    }
```

Match whatever existing pattern in that test file is used to patch `executive_summary_cache._store` for other fields (e.g. `devices_out_of_sync`) — several existing tests already do this for `change_control`/`lifecycle`; follow that exact pattern instead of `patch.dict` if the file already has a helper for it.

- [ ] **Step 8: Run tests**

Run: `uv run pytest tests/test_executive_summary_cache.py tests/test_external_api_executive.py -v --tb=short`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add app/executive_summary_cache.py app/routes/external_api_routes.py docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md tests/test_executive_summary_cache.py tests/test_external_api_executive.py
git commit -m "$(cat <<'EOF'
feat: add silent_devices rollup (connectivity proxy) to executive summary

New top-level key, devices with conn_status != 1, capped at 50. This is
a spike-documented connectivity proxy — no FortiAnalyzer log-freshness
API is queried yet, so last_log_at is always null. See
docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 5: `psirt.top_advisory.devices`

This is the one place in this plan where an *existing* field's type changes: `top_advisory.devices` is currently an `int` (device count). The spec explicitly asks for `psirt.top_advisory.devices: [{device, adom, version, workaround_applied}]`. To avoid silently destroying the existing integer (a downstream consumer may already read it as a count), the old value is preserved under a new name, `device_count`, and `devices` becomes the list. Document this rename prominently (Task 6).

**Files:**
- Modify: `app/psirt_store.py` (`compute_psirt_rollup()`)
- Test: `tests/test_psirt_store.py`

**Interfaces:**
- Consumes: `latest["devices_affected"]` (already available in-loop in `compute_psirt_rollup()`), each entry `{"name": str, "adom": str, "version": str, "workaround_applied": bool}` (see `app/psirt_store.py:105-113`'s `save_assessment_result()` for the authoritative shape).
- Produces: `top_advisory` dict gains `"device_count": int` (the old `"devices"` value) and changes `"devices"` to the capped/sorted list `[{"device": str, "adom": str, "version": str, "workaround_applied": bool}]`.

**Ordering:** capped at 50; devices without the workaround applied sort first (most urgent), tie-broken by `adom` ascending, then `device` name ascending.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_psirt_store.py` (find the existing `compute_psirt_rollup` test(s) and add near them — check how advisories/assessments are seeded in existing tests, likely via `save_advisory`/`save_assessment_result` helper calls against a temp DB fixture, and match that pattern):

```python
def test_compute_psirt_rollup_top_advisory_lists_devices_unmitigated_first(tmp_psirt_db):
    from app import psirt_store

    psirt_store.save_advisory(
        {
            "advisory_id": "FG-IR-24-001",
            "cves": ["CVE-2024-0001"],
            "cvss": 9.8,
            "severity": "critical",
            "kev": False,
            "affected_ranges": [],
            "workaround_text": "",
        }
    )
    findings = [
        {
            "device": "fw-a",
            "adom": "root",
            "current_version": "v7.4.2",
            "in_range": True,
            "workaround_status": "in_place",
        },
        {
            "device": "fw-b",
            "adom": "root",
            "current_version": "v7.4.1",
            "in_range": True,
            "workaround_status": "none",
        },
    ]
    psirt_store.save_assessment_result(
        "FG-IR-24-001", {"priority": "critical"}, findings
    )

    rollup = psirt_store.compute_psirt_rollup()

    assert rollup["top_advisory"]["device_count"] == 2
    assert rollup["top_advisory"]["devices"] == [
        {
            "device": "fw-b",
            "adom": "root",
            "version": "v7.4.1",
            "workaround_applied": False,
        },
        {
            "device": "fw-a",
            "adom": "root",
            "version": "v7.4.2",
            "workaround_applied": True,
        },
    ]
```

Before writing this, read `tests/test_psirt_store.py` in full to find the actual fixture name for a temp/isolated `psirt.db` (it is NOT `tmp_psirt_db` unless that's what the file already defines — use whatever fixture the existing tests use, and the actual call signatures of `save_advisory`/`save_assessment_result`/`get_open_advisories` as they exist in `app/psirt_store.py`, adjusting the test above to match exactly).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_store.py -v -k top_advisory_lists_devices`
Expected: FAIL — `KeyError: 'device_count'` or a mismatched `devices` value (still an int).

- [ ] **Step 3: Implement**

In `app/psirt_store.py`'s `compute_psirt_rollup()`, the `is_better` block currently ends with:

```python
        if is_better:
            top_rank, top_cvss, top_device_count = rank, cvss, device_count
            top_advisory = {
                "advisory_id": adv["advisory_id"],
                "cvss": adv["cvss"],
                "kev": adv["kev"],
                "devices": device_count,
            }
```

Change to:

```python
        if is_better:
            top_rank, top_cvss, top_device_count = rank, cvss, device_count
            top_advisory = {
                "advisory_id": adv["advisory_id"],
                "cvss": adv["cvss"],
                "kev": adv["kev"],
                "device_count": device_count,
                "devices": _top_advisory_devices(devices_affected),
            }
```

Add a module-level helper just above `compute_psirt_rollup` (after the existing `_PRIORITY_RANK` / `compute_mean_days_to_remediate` definitions):

```python
_MAX_TOP_ADVISORY_DEVICES = 50


def _top_advisory_devices(devices_affected: list[dict]) -> list[dict]:
    """Capped, most-urgent-first device list for psirt.top_advisory.devices.

    Devices without the workaround applied sort first (still fully
    exposed), tie-broken by adom then device name.
    """
    entries = [
        {
            "device": d.get("name", ""),
            "adom": d.get("adom", ""),
            "version": d.get("version", ""),
            "workaround_applied": bool(d.get("workaround_applied")),
        }
        for d in devices_affected
    ]
    entries.sort(
        key=lambda d: (d["workaround_applied"], d["adom"], d["device"])
    )
    return entries[:_MAX_TOP_ADVISORY_DEVICES]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_store.py -v -k top_advisory_lists_devices`
Expected: PASS

- [ ] **Step 5: Run the full PSIRT test suite (guard against breaking existing `top_advisory.devices` int assertions)**

Run: `uv run pytest tests/test_psirt_store.py tests/test_psirt_routes.py tests/test_external_api_executive.py -v --tb=short`
Expected: PASS. Update any existing assertion that checks `top_advisory["devices"]` as an int to check `top_advisory["device_count"]` instead — grep the whole `tests/` directory for `"devices"` near `top_advisory` to find every place that needs updating:

Run: `grep -rn "top_advisory" tests/`

- [ ] **Step 6: Commit**

```bash
git add app/psirt_store.py tests/test_psirt_store.py
git commit -m "$(cat <<'EOF'
feat: add psirt.top_advisory.devices drill-down list

BREAKING (within schema_version 2): top_advisory.devices changes from
an int count to a capped, unmitigated-first device list. The old count
is preserved as top_advisory.device_count so no information is lost.
Documented in docs/api-reference.md.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Task 6: Documentation

**Files:**
- Modify: `docs/api-reference.md`
- Modify: `docs/features.md`

**Interfaces:** none (docs only). This task must run after Tasks 1-5 are all merged into the branch, since it documents their final shapes.

- [ ] **Step 1: Update `docs/api-reference.md`**

Find the `/external/api/executive/summary` table row and the `## PSIRT Advisory Assessment` prose. Add a new subsection right after the executive-summary table row (matching this file's existing terse-table-plus-pointer-to-features.md convention):

```markdown
### Drill-down details lists

Five rollup objects in the executive summary payload carry an optional
`details` (or, for `version_breakdown`, `eol_devices`) list — a capped,
most-severe-or-most-relevant-first breakdown for a per-device drill-down
view. See [features.md](features.md#drill-down-details-lists) for the
full field shapes and exact ordering per list.

| Rollup | Field | Cap | Order |
|---|---|---|---|
| `device_review` | `details` | 50 | worst_severity (critical→low), then most failed checks, then device name |
| `rule_hygiene` | `details` | 50 | most findings first, then adom, then package name |
| `version_breakdown` | `eol_devices` | 50 | oldest firmware first, then device name |
| `silent_devices` (new) | `details` | 50 | adom, then device name (no severity gradient) |
| `psirt.top_advisory` | `devices` | 50 | unmitigated (`workaround_applied: false`) first, then adom, then device name — **note:** this field changed from an int device count to this list; the old count is now `top_advisory.device_count` |
```

- [ ] **Step 2: Update `docs/features.md`**

Add a `### Drill-down details lists` subsection under the existing `### Executive Summary Endpoint` section (`## External API`), with one worked JSON example per list (device_review.details, rule_hygiene.details, version_breakdown.eol_devices, silent_devices, psirt.top_advisory.devices), each with a one-line description of the cap/ordering (matching Task 1-5's docstrings) and, for `silent_devices`, a pointer to `docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md` explaining why `last_log_at` is always `null`.

Also fix the pre-existing doc/code drift noted during planning: `docs/features.md`'s Executive Summary section currently states *"`last_backup_status` is intentionally omitted..."* while `app/routes/external_api_routes.py` actually includes `last_backup_status` in the payload (this predates this plan's work — fix it while in this section since it's directly adjacent).

- [ ] **Step 3: Commit**

```bash
git add docs/api-reference.md docs/features.md
git commit -m "$(cat <<'EOF'
docs: document drill-down details lists and fix stale last_backup_status note

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018LKr9N53QuR8wjCvB3Nsaq
EOF
)"
```

---

## Final verification

- [ ] Run `uv run pytest tests/ -v --tb=short` — full suite passes.
- [ ] Run `uv run ruff check app/ wsgi.py manage_users.py && uv run ruff format --check app/ wsgi.py manage_users.py` — clean.
- [ ] Manually `grep -rn "top_advisory" app/ tests/ docs/` to confirm no stray reference still assumes `top_advisory["devices"]` is an int.
