# Naming Standards Admin UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin view, edit, and reset the FortiGate object-naming standards (host/network/service/policy) used by Rule Validation's AI Assist and Hygiene Fix, from a new Admin sub-tab — with edits taking effect immediately (no restart) and actually changing the names generated in CLI output.

**Architecture:** A small token-substitution template engine (`app/planner/naming_template.py`) replaces the hardcoded f-strings in `app/planner/standards.py::object_name()`/`policy_name()`, reading patterns from `naming.yaml` on every call (no more `@lru_cache`). A new persistence module (`app/naming_standards.py`) validates and atomically writes `naming.yaml`, mirroring `app/app_settings.py`. A new Admin sub-tab (4 pattern cards + live preview + YAML import + reset) talks to 3 new `admin_routes.py` endpoints.

**Tech Stack:** Flask, PyYAML, vanilla JS (existing `admin.js`/`admin.html` conventions), pytest.

**Spec:** `docs/superpowers/specs/2026-09-22-naming-standards-admin-design.md`

## Global Constraints

- In scope for live pattern-driven generation: exactly `host`, `network`, `service`, `policy` — the 4 types already centralized in `app/planner/standards.py`.
- Out of scope, must NOT be touched: FQDN/wildcard-FQDN/FQDN-group naming (`app/planner/engine.py::_fqdn_object_name`/`_fqdn_group_name` — security-sensitive sanitization, stays hardcoded); `address_group`/`service_group`/`nat_rule`/`vip` patterns (documentation-only, nothing generates them); `zone_abbrevs` (confirmed dead code, leave as-is); `review_requirements.yaml` (separate file/feature).
- With the shipped default `naming.example.yaml`, `object_name()`/`policy_name()` output must be byte-identical to today's hardcoded behavior — existing tests in `tests/test_planner_standards.py` (lines 52-69) are the regression bar and must keep passing unmodified.
- `_load_yaml()` in `standards.py` drops `@lru_cache` — re-reads from disk every call (matches `app/groups.py`/`app/app_settings.py`'s no-cache pattern).
- A save request that would produce a broken/unparseable pattern must be rejected (400 + error list) before it touches `naming.yaml` — never leave the file in a state that breaks a live AI Assist request.
- Token syntax: `<UPPER_SNAKE_CASE>`, regex `<[A-Z_]+>`. Per-type vocabulary: `host` → `<IP_ADDRESS>`; `network` → `<NETWORK_ADDRESS>`, `<PREFIX_LEN>`; `service` → `<PROTO>`, `<PORT>`; `policy` → `<TICKET_ID>`, `<SRC_INTF>`, `<DST_INTF>`, `<SEQ>` (always zero-padded to 3 digits before substitution, not configurable).
- All new admin endpoints use the existing `@admin_required` decorator (`app.decorators.admin_required`) and existing CSRF convention (`X-CSRF-Token` header on POST/PUT, per `tests/test_admin_ai_assist_setting.py`).

---

### Task 1: Naming template engine

**Files:**
- Create: `app/planner/naming_template.py`
- Test: `tests/test_planner_naming_template.py`

**Interfaces:**
- Produces: `render(pattern: str, **tokens: str) -> str` — raises `NamingTemplateError` (defined in this file, subclasses `app.planner.models.PlannerDataError` with `source="naming_template"`) on: pattern is empty/None, pattern references a `<TOKEN>` not present in `tokens` (case-sensitive exact match), or `tokens` values are not stringifiable.
- Produces: `TOKEN_PATTERN_RE` — the compiled regex `re.compile(r"<([A-Z_]+)>")` used internally by `render()`. Not consumed elsewhere in this plan (Task 3's validator calls `render()` directly rather than re-implementing token discovery), but left as a module-level name rather than a local one in case a later task needs it.

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for app/planner/naming_template.py — pattern token substitution."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.planner.models import PlannerDataError
from app.planner.naming_template import NamingTemplateError, render


def test_render_substitutes_single_token():
    assert render("H_<IP_ADDRESS>", IP_ADDRESS="10.1.2.3") == "H_10.1.2.3"


def test_render_substitutes_multiple_tokens():
    result = render(
        "<TICKET_ID>_<SRC_INTF>_TO_<DST_INTF>_<SEQ>",
        TICKET_ID="CHG0012345", SRC_INTF="WAN", DST_INTF="DMZ", SEQ="001",
    )
    assert result == "CHG0012345_WAN_TO_DMZ_001"


def test_render_no_tokens_returns_pattern_unchanged():
    assert render("STATIC_NAME") == "STATIC_NAME"


def test_render_empty_pattern_raises():
    with pytest.raises(NamingTemplateError) as exc_info:
        render("", IP_ADDRESS="10.1.2.3")
    assert exc_info.value.source == "naming_template"


def test_render_none_pattern_raises():
    with pytest.raises(NamingTemplateError):
        render(None)


def test_render_missing_token_raises():
    with pytest.raises(NamingTemplateError) as exc_info:
        render("H_<IP_ADDRESS>")
    assert "IP_ADDRESS" in exc_info.value.detail


def test_render_missing_token_raises_is_planner_data_error():
    # NamingTemplateError must be catchable anywhere PlannerDataError already is
    with pytest.raises(PlannerDataError):
        render("H_<IP_ADDRESS>")


def test_render_lowercase_angle_brackets_not_treated_as_token():
    # only <UPPER_SNAKE> matches the token regex — a literal "<foo>" in a
    # pattern passes through unchanged rather than being misidentified
    assert render("literal_<foo>_text") == "literal_<foo>_text"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_planner_naming_template.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.planner.naming_template'`

- [ ] **Step 3: Write the implementation**

```python
"""Token-substitution template engine for naming.yaml patterns.

Patterns use <UPPER_SNAKE_CASE> placeholders (e.g. "H_<IP_ADDRESS>"). This
is the single place that turns a naming.yaml pattern string plus real
request values into an actual FortiGate object/policy name — used by
app.planner.standards.object_name()/policy_name() so that an admin editing
a pattern in naming.yaml (via the Admin UI or by hand) changes what CLI
actually gets generated, not just what's displayed.
"""

from __future__ import annotations

import re

from app.planner.models import PlannerDataError

TOKEN_PATTERN_RE = re.compile(r"<([A-Z_]+)>")


class NamingTemplateError(PlannerDataError):
    """A naming.yaml pattern could not be rendered."""

    def __init__(self, detail: str) -> None:
        super().__init__("naming_template", detail)


def render(pattern: str | None, **tokens: str) -> str:
    """Substitute <TOKEN> placeholders in `pattern` with `tokens` values.

    Raises NamingTemplateError if `pattern` is empty/None, or references a
    token not present in `tokens` — never silently emits a partial name.
    """
    if not pattern:
        raise NamingTemplateError("pattern is empty or missing")

    referenced = set(TOKEN_PATTERN_RE.findall(pattern))
    missing = referenced - set(tokens)
    if missing:
        raise NamingTemplateError(
            f"pattern {pattern!r} references undefined token(s): "
            f"{', '.join(sorted(missing))}"
        )

    def _sub(match: re.Match) -> str:
        return str(tokens[match.group(1)])

    return TOKEN_PATTERN_RE.sub(_sub, pattern)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_planner_naming_template.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add app/planner/naming_template.py tests/test_planner_naming_template.py
git commit -m "feat: add naming.yaml pattern template engine

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Rewire standards.py to use the template engine, drop caching

**Files:**
- Modify: `app/planner/standards.py:1-73` (imports, `_load_yaml`, `object_name`, `policy_name`)
- Modify: `tests/test_planner_standards.py` (add new tests; existing tests at lines 52-69 must keep passing unmodified)

**Interfaces:**
- Consumes: `naming_template.render(pattern, **tokens) -> str`, `naming_template.NamingTemplateError` (Task 1).
- Produces: `object_name(obj_type, *, ip="", proto="", port="", naming=None) -> str` — same signature as today, but now accepts an optional `naming: dict | None` (loaded via `load_naming()` if not given) so callers/tests can inject a naming dict without touching disk. Raises `NamingTemplateError` if `obj_type` isn't one of `host`/`network`/`service`, or if the pattern for that type is missing/broken (unchanged: previously raised plain `ValueError` for unknown `obj_type` — this becomes `NamingTemplateError` since it's now driven by data, not a hardcoded branch; note this is a behavior change other tasks/tests must account for).
- Produces: `policy_name(ticket_id, srcintf, dstintf, seq=1, *, naming=None) -> str` — same signature plus optional `naming`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_planner_standards.py` (after the existing `test_load_naming_reads_repo_yaml` test, keep all existing tests unchanged):

```python
from app.planner.naming_template import NamingTemplateError


def test_object_name_host_uses_pattern_from_naming_dict():
    naming = {"platforms": {"fortigate": {"conventions": {
        "host": {"pattern": "CUSTOM_<IP_ADDRESS>"},
    }}}}
    assert object_name("host", ip="10.1.2.3", naming=naming) == "CUSTOM_10.1.2.3"


def test_object_name_network_uses_pattern_from_naming_dict():
    naming = {"platforms": {"fortigate": {"conventions": {
        "network": {"pattern": "NET-<NETWORK_ADDRESS>-<PREFIX_LEN>"},
    }}}}
    assert (
        object_name("network", ip="10.8.0.0/16", naming=naming)
        == "NET-10.8.0.0-16"
    )


def test_object_name_network_defaults_prefix_to_32_when_absent():
    naming = {"platforms": {"fortigate": {"conventions": {
        "network": {"pattern": "N_<NETWORK_ADDRESS>_<PREFIX_LEN>"},
    }}}}
    assert object_name("network", ip="10.8.0.0", naming=naming) == "N_10.8.0.0_32"


def test_object_name_service_uses_pattern_from_naming_dict():
    naming = {"platforms": {"fortigate": {"conventions": {
        "service": {"pattern": "SVC-<PROTO>-<PORT>"},
    }}}}
    assert (
        object_name("service", proto="tcp", port="8443", naming=naming)
        == "SVC-TCP-8443"
    )


def test_object_name_unknown_type_raises_naming_template_error():
    with pytest.raises(NamingTemplateError):
        object_name("nat_rule", ip="10.1.2.3")


def test_object_name_missing_pattern_raises_naming_template_error():
    naming = {"platforms": {"fortigate": {"conventions": {
        "host": {},  # no "pattern" key at all
    }}}}
    with pytest.raises(NamingTemplateError):
        object_name("host", ip="10.1.2.3", naming=naming)


def test_policy_name_uses_pattern_from_naming_dict():
    naming = {"platforms": {"fortigate": {"conventions": {
        "policy": {"pattern": "<TICKET_ID>-<SRC_INTF>-<DST_INTF>-<SEQ>"},
    }}}}
    assert (
        policy_name("CHG1", "wan1", "dmz", seq=2, naming=naming)
        == "CHG1-WAN1-DMZ-002"
    )


def test_load_naming_not_cached_across_calls(naming_path):
    # Regression guard: earlier versions used @lru_cache on the loader,
    # which meant an on-disk edit was invisible until process restart.
    naming = load_naming(path=naming_path)
    assert naming["platforms"]["fortigate"]["conventions"]["host"]["pattern"] == "H_<IP_ADDRESS>"
    naming_path.write_text(
        naming_path.read_text(encoding="utf-8").replace(
            'pattern: "H_<IP_ADDRESS>"', 'pattern: "CHANGED_<IP_ADDRESS>"'
        ),
        encoding="utf-8",
    )
    reloaded = load_naming(path=naming_path)
    assert (
        reloaded["platforms"]["fortigate"]["conventions"]["host"]["pattern"]
        == "CHANGED_<IP_ADDRESS>"
    )
```

Note: this last test assumes `naming.example.yaml`'s host pattern is
literally `pattern: "H_<IP_ADDRESS>"` — confirm this against the real file
content in Task 3 (it must be updated to use `<IP_ADDRESS>`-style tokens
exactly, not the current freeform placeholder text — see Task 3, Step 1).

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_planner_standards.py -v`
Expected: FAIL — `object_name`/`policy_name` don't yet accept `naming=` for
these patterns, unknown-type doesn't raise `NamingTemplateError` yet
(raises `ValueError`), and `naming.example.yaml`'s host pattern isn't yet
`<IP_ADDRESS>`-shaped (it currently reads `"H_<IP_ADDRESS>"` already per
the file dump we captured during design — verify at Step 3 time; if it's
already correct this specific sub-assertion should pass, everything else
should still fail on missing `naming=` support)

- [ ] **Step 3: Write the implementation**

Replace lines 1-73 of `app/planner/standards.py`:

```python
"""
Deterministic standards lookups for the change planner.

Loads naming.yaml/review_requirements.yaml (team-maintained, gitignored —
copy from naming.example.yaml/review_requirements.example.yaml) and encodes
the risk/logging decision rules the planner applies to every flow.

naming.yaml's host/network/service/policy patterns are rendered through
app.planner.naming_template — editing a pattern (by hand or via
Admin → Naming Standards) changes the names object_name()/policy_name()
actually generate, not just what's displayed to the AI narrator.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

from app.planner.matching import PortRange
from app.planner.models import PlannerDataError
from app.planner.naming_template import NamingTemplateError, render

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_NAMING_FILE = _REPO_ROOT / "naming.yaml"
_REVIEW_FILE = _REPO_ROOT / "review_requirements.yaml"

# Destination ports that make a rule "management access" per naming.yaml
# (interactive access logging — a common regulated-environment requirement,
# e.g. NERC CIP-005 in a regulated deployment).
_MANAGEMENT_PORTS = {("tcp", 22), ("tcp", 3389), ("tcp", 23)}


def _load_yaml(path: str) -> dict:
    # Deliberately no @lru_cache: naming.yaml can now be edited live via
    # Admin → Naming Standards, and this file is small enough (a few KB)
    # that re-reading it on every call is negligible next to the FMG API
    # calls AI Assist/Hygiene Fix already make per request.
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError as exc:
        example = (
            f"{path}.example"
            if not path.endswith(".yaml")
            else path.rsplit(".yaml", 1)[0] + ".example.yaml"
        )
        raise PlannerDataError(
            "standards",
            f"required standards file {path!r} is missing — copy it from "
            f"{example!r} and edit it for your environment before using AI Assist.",
        ) from exc


def load_naming(path: Path | None = None) -> dict:
    return _load_yaml(str(path or _NAMING_FILE))


def _pattern_for(obj_type: str, naming: dict) -> str:
    conventions = (
        naming.get("platforms", {}).get("fortigate", {}).get("conventions", {})
    )
    entry = conventions.get(obj_type)
    if not entry or not entry.get("pattern"):
        raise NamingTemplateError(
            f"naming.yaml has no pattern configured for object type {obj_type!r}"
        )
    return entry["pattern"]


def object_name(
    obj_type: str,
    *,
    ip: str = "",
    proto: str = "",
    port: str = "",
    naming: dict | None = None,
) -> str:
    """Generate an object name per the FortiGate conventions in naming.yaml."""
    naming = naming if naming is not None else load_naming()
    if obj_type == "host":
        pattern = _pattern_for("host", naming)
        return render(pattern, IP_ADDRESS=ip.split("/")[0])
    if obj_type == "network":
        pattern = _pattern_for("network", naming)
        addr, _, prefix = ip.partition("/")
        return render(pattern, NETWORK_ADDRESS=addr, PREFIX_LEN=prefix or "32")
    if obj_type == "service":
        pattern = _pattern_for("service", naming)
        return render(pattern, PROTO=proto.upper(), PORT=port)
    raise NamingTemplateError(f"No naming convention for object type {obj_type!r}")


def policy_name(
    ticket_id: str,
    srcintf: str,
    dstintf: str,
    seq: int = 1,
    *,
    naming: dict | None = None,
) -> str:
    naming = naming if naming is not None else load_naming()
    pattern = _pattern_for("policy", naming)
    ticket = ticket_id or "<TICKET_ID>"
    return render(
        pattern,
        TICKET_ID=ticket,
        SRC_INTF=srcintf.upper(),
        DST_INTF=dstintf.upper(),
        SEQ=f"{seq:03d}",
    )
```

Leave everything from `_domains_for` onward (line 76 in the original file)
unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_planner_standards.py -v`
Expected: PASS, including every pre-existing test (`test_object_name_host`,
`test_object_name_network`, `test_object_name_service`,
`test_policy_name_with_ticket`, `test_policy_name_placeholder_without_ticket`)
unmodified and byte-identical in their assertions.

- [ ] **Step 5: Run the full planner test suite to check for regressions**

Run: `pytest tests/test_planner_engine.py tests/test_planner_catalogs.py tests/test_planner_cli_gen.py -v`
Expected: PASS — these exercise `object_name`/`policy_name` indirectly
through `engine.py`/`catalogs.py`; a failure here means the rewrite
changed observable behavior with the default YAML, which must be fixed
before continuing (the byte-identical-output constraint is a hard
requirement, not a nice-to-have).

- [ ] **Step 6: Commit**

```bash
git add app/planner/standards.py tests/test_planner_standards.py
git commit -m "refactor: drive object_name/policy_name from naming.yaml patterns

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: naming.example.yaml token syntax + persistence/validation module

**Files:**
- Modify: `naming.example.yaml` (root) — update `host`/`network`/`service`/`policy` pattern strings to use the exact `<UPPER_SNAKE_CASE>` tokens Task 1/2 expect (they already appear to, but this step locks it down and updates the surrounding comment)
- Create: `app/naming_standards.py`
- Test: `tests/test_naming_standards.py`

**Interfaces:**
- Consumes: `app.planner.naming_template.render` (Task 1); `app.planner.standards.load_naming` (Task 2, for `get_naming()`); `app.atomic_io.atomic_write_text`.
- Produces: `get_naming() -> dict`; `validate_naming(data: dict) -> list[str]`; `save_naming(data: dict) -> None` (raises `NamingValidationError(errors: list[str])` — new exception in this file — if `validate_naming` returns any errors; caller/route catches this); `reset_to_default() -> None`.

- [ ] **Step 1: Confirm/update naming.example.yaml pattern tokens**

Read `naming.example.yaml` and confirm each of these 4 `pattern:` lines
matches the token vocabulary exactly (edit any that don't):

```yaml
      host:
        pattern: "H_<IP_ADDRESS>"
      network:
        pattern: "N_<NETWORK_ADDRESS>_<PREFIX_LEN>"
      service:
        pattern: "SVC_<PROTO>_<PORT>"
      policy:
        pattern: "<TICKET_ID>_<SRC_INTF>_TO_<DST_INTF>_<SEQ>"
```

(Based on the file content captured during design, these already match —
this step is a verification, not necessarily a rewrite. If they already
match, skip the edit and note it in the commit message body instead of
committing a no-op diff.)

- [ ] **Step 2: Write the failing tests**

```python
"""Tests for app/naming_standards.py — validation and persistence for
naming.yaml, used by the Admin → Naming Standards UI."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.naming_standards import (
    NamingValidationError,
    get_naming,
    reset_to_default,
    save_naming,
    validate_naming,
)

_REPO_ROOT = Path(__file__).parent.parent
_NAMING_EXAMPLE = _REPO_ROOT / "naming.example.yaml"


def _valid_naming_dict():
    import yaml
    return yaml.safe_load(_NAMING_EXAMPLE.read_text(encoding="utf-8"))


def test_validate_naming_accepts_shipped_default():
    assert validate_naming(_valid_naming_dict()) == []


def test_validate_naming_rejects_missing_pattern():
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["host"]["pattern"] = ""
    errors = validate_naming(data)
    assert any("host" in e for e in errors)


def test_validate_naming_rejects_unknown_token():
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["service"]["pattern"] = (
        "SVC_<NOT_A_REAL_TOKEN>"
    )
    errors = validate_naming(data)
    assert any("NOT_A_REAL_TOKEN" in e for e in errors)


def test_validate_naming_rejects_missing_convention_entirely():
    data = _valid_naming_dict()
    del data["platforms"]["fortigate"]["conventions"]["policy"]
    errors = validate_naming(data)
    assert any("policy" in e for e in errors)


def test_validate_naming_reports_all_errors_not_just_first():
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["host"]["pattern"] = ""
    data["platforms"]["fortigate"]["conventions"]["network"]["pattern"] = ""
    errors = validate_naming(data)
    assert len(errors) >= 2


def test_save_naming_writes_valid_data(tmp_path, monkeypatch):
    dest = tmp_path / "naming.yaml"
    monkeypatch.setattr("app.naming_standards._NAMING_PATH", dest)
    save_naming(_valid_naming_dict())
    assert dest.exists()
    assert "H_<IP_ADDRESS>" in dest.read_text(encoding="utf-8")


def test_save_naming_rejects_invalid_data_without_writing(tmp_path, monkeypatch):
    dest = tmp_path / "naming.yaml"
    monkeypatch.setattr("app.naming_standards._NAMING_PATH", dest)
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["host"]["pattern"] = ""
    with pytest.raises(NamingValidationError) as exc_info:
        save_naming(data)
    assert not dest.exists()
    assert any("host" in e for e in exc_info.value.errors)


def test_reset_to_default_copies_example_file(tmp_path, monkeypatch):
    dest = tmp_path / "naming.yaml"
    dest.write_text("stale: true", encoding="utf-8")
    monkeypatch.setattr("app.naming_standards._NAMING_PATH", dest)
    monkeypatch.setattr("app.naming_standards._NAMING_EXAMPLE_PATH", _NAMING_EXAMPLE)
    reset_to_default()
    assert "H_<IP_ADDRESS>" in dest.read_text(encoding="utf-8")


def test_get_naming_reads_current_file(tmp_path, monkeypatch):
    dest = tmp_path / "naming.yaml"
    dest.write_text(_NAMING_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    # get_naming() passes path=_NAMING_PATH explicitly to load_naming(), so
    # the module attribute to patch is this file's own _NAMING_PATH, not
    # app.planner.standards._NAMING_FILE (that default is only used when
    # load_naming() is called with no path argument at all).
    monkeypatch.setattr("app.naming_standards._NAMING_PATH", dest)
    naming = get_naming()
    assert "fortigate" in naming["platforms"]
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_naming_standards.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.naming_standards'`

- [ ] **Step 4: Write the implementation**

```python
"""Validation and atomic persistence for naming.yaml, backing the
Admin → Naming Standards UI.

Mirrors app/app_settings.py's atomic-write pattern. Unlike app_settings.py
this file validates before writing: an admin save that would leave
naming.yaml unable to render a name (missing pattern, unknown token) is
rejected with a 400 and a list of errors, never partially applied.
"""

from __future__ import annotations

import shutil
import threading
from pathlib import Path

import yaml

from app.atomic_io import atomic_write_text
from app.planner import standards as _standards
from app.planner.naming_template import render

_REPO_ROOT = Path(__file__).parent.parent
_NAMING_PATH = _REPO_ROOT / "naming.yaml"
_NAMING_EXAMPLE_PATH = _REPO_ROOT / "naming.example.yaml"

_lock = threading.Lock()

# In-scope, live-rendered object types (see spec's Scope section) and the
# dummy token values used to smoke-test every pattern before a save.
_EDITABLE_TYPES = ("host", "network", "service", "policy")
_DUMMY_TOKENS = {
    "IP_ADDRESS": "10.0.0.1",
    "NETWORK_ADDRESS": "10.0.0.0",
    "PREFIX_LEN": "24",
    "PROTO": "tcp",
    "PORT": "443",
    "TICKET_ID": "CHG000000",
    "SRC_INTF": "WAN1",
    "DST_INTF": "DMZ",
    "SEQ": "001",
}


class NamingValidationError(Exception):
    """Raised by save_naming() when validate_naming() finds errors."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def get_naming() -> dict:
    return _standards.load_naming(path=_NAMING_PATH)


def validate_naming(data: dict) -> list[str]:
    """Render each in-scope pattern against a dummy token set. Returns a
    list of human-readable errors (empty = valid)."""
    errors: list[str] = []
    conventions = (
        (data or {}).get("platforms", {}).get("fortigate", {}).get("conventions", {})
    )
    for obj_type in _EDITABLE_TYPES:
        entry = conventions.get(obj_type)
        if not entry:
            errors.append(f"{obj_type}: no convention entry found")
            continue
        pattern = entry.get("pattern")
        if not pattern:
            errors.append(f"{obj_type}: pattern is empty or missing")
            continue
        try:
            render(pattern, **_DUMMY_TOKENS)
        except Exception as exc:  # NamingTemplateError, but keep this broad
            errors.append(f"{obj_type}: {exc}")
    return errors


def save_naming(data: dict) -> None:
    errors = validate_naming(data)
    if errors:
        raise NamingValidationError(errors)
    with _lock:
        atomic_write_text(_NAMING_PATH, yaml.safe_dump(data, sort_keys=False))


def reset_to_default() -> None:
    with _lock:
        shutil.copyfile(_NAMING_EXAMPLE_PATH, _NAMING_PATH)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_naming_standards.py -v`
Expected: PASS (9 passed)

- [ ] **Step 6: Commit**

```bash
git add naming.example.yaml app/naming_standards.py tests/test_naming_standards.py
git commit -m "feat: add naming.yaml validation and atomic persistence module

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Admin API endpoints

**Files:**
- Modify: `app/routes/admin_routes.py` (add imports near line 63-68, add endpoints near the settings endpoints ~line 277-300, add docstring lines near the top ~line 30-40)
- Test: `tests/test_admin_naming_standards_routes.py`

**Interfaces:**
- Consumes: `app.naming_standards.get_naming`, `save_naming`, `reset_to_default`, `NamingValidationError` (Task 3); `yaml.safe_load` (PyYAML, already a repo dependency).
- Produces: `GET /admin/api/naming-standards` → 200 `{naming: <dict>}`; `PUT /admin/api/naming-standards` body `{naming: <dict>}` → 200 `{ok: true}` or 400 `{ok: false, errors: [...]}`; `POST /admin/api/naming-standards/reset` → 200 `{ok: true, naming: <dict>}`; `POST /admin/api/naming-standards/parse` body `{yaml_text: str}` → 200 `{ok: true, naming: <dict>}` or 400 `{ok: false, error: str}` — parses pasted YAML server-side for the Admin UI's "Import from YAML" box (no client-side YAML parser needed; nothing is saved by this endpoint).

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for /admin/api/naming-standards* routes."""
import time
from unittest.mock import patch

import pytest

from app import create_app
from app.naming_standards import NamingValidationError


@pytest.fixture
def admin_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def test_get_naming_standards_returns_current_naming(admin_client):
    fake = {"platforms": {"fortigate": {"conventions": {}}}}
    with patch("app.routes.admin_routes.get_naming", return_value=fake):
        resp = admin_client.get("/admin/api/naming-standards")
    assert resp.status_code == 200
    assert resp.get_json()["naming"] == fake


def test_put_naming_standards_saves_valid_data(admin_client):
    body = {"naming": {"platforms": {"fortigate": {"conventions": {}}}}}
    with patch("app.routes.admin_routes.save_naming") as mock_save:
        resp = admin_client.put(
            "/admin/api/naming-standards",
            json=body,
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
    mock_save.assert_called_once_with(body["naming"])


def test_put_naming_standards_returns_400_on_validation_error(admin_client):
    body = {"naming": {"platforms": {"fortigate": {"conventions": {}}}}}
    with patch(
        "app.routes.admin_routes.save_naming",
        side_effect=NamingValidationError(["host: pattern is empty or missing"]),
    ):
        resp = admin_client.put(
            "/admin/api/naming-standards",
            json=body,
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["ok"] is False
    assert "host: pattern is empty or missing" in data["errors"]


def test_put_naming_standards_requires_naming_key(admin_client):
    resp = admin_client.put(
        "/admin/api/naming-standards",
        json={},
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 400


def test_post_naming_standards_reset(admin_client):
    fake = {"platforms": {"fortigate": {"conventions": {}}}}
    with patch("app.routes.admin_routes.reset_to_default") as mock_reset, \
         patch("app.routes.admin_routes.get_naming", return_value=fake):
        resp = admin_client.post("/admin/api/naming-standards/reset")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["naming"] == fake
    mock_reset.assert_called_once()


def test_post_naming_standards_parse_valid_yaml(admin_client):
    resp = admin_client.post(
        "/admin/api/naming-standards/parse",
        json={"yaml_text": "platforms:\n  fortigate:\n    conventions:\n      host:\n        pattern: \"H_<IP_ADDRESS>\"\n"},
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["naming"]["platforms"]["fortigate"]["conventions"]["host"]["pattern"] == "H_<IP_ADDRESS>"


def test_post_naming_standards_parse_invalid_yaml_returns_400(admin_client):
    resp = admin_client.post(
        "/admin/api/naming-standards/parse",
        json={"yaml_text": "not: valid: yaml: [unbalanced"},
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_post_naming_standards_parse_requires_yaml_text(admin_client):
    resp = admin_client.post(
        "/admin/api/naming-standards/parse",
        json={},
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 400


def test_naming_standards_routes_require_admin():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["user"] = "viewer"
            sess["role"] = "viewer"
            sess["login_at"] = int(time.time())
        resp = c.get("/admin/api/naming-standards")
    assert resp.status_code in (302, 403)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_admin_naming_standards_routes.py -v`
Expected: FAIL — 404s, since the routes don't exist yet (9 tests total).

- [ ] **Step 3: Write the implementation**

In `app/routes/admin_routes.py`, add to the docstring block (after the
"External API tokens" section, ~line 40):

```
Naming Standards (JSON):
  GET    /admin/api/naming-standards         current naming.yaml content: {"naming": {...}}
  PUT    /admin/api/naming-standards         {"naming": {...}} — validate + save; 400 + {"errors": [...]} on failure
  POST   /admin/api/naming-standards/reset   reset naming.yaml to naming.example.yaml
  POST   /admin/api/naming-standards/parse   {"yaml_text": str} — parse only (no save), for the Import YAML box
```

Add `import yaml` alongside the existing `import os` / `import re` lines at
the top of the file (~line 43-44), and add to the `from app...` imports
block (near line 63-68):

```python
from app.naming_standards import (
    NamingValidationError,
    get_naming,
    reset_to_default,
    save_naming,
)
```

Add near the settings endpoints (after `api_settings_put`, ~line 300):

```python
# ── Naming Standards API ───────────────────────────────────────────────────


@bp.route("/api/naming-standards")
@_admin_required
def api_naming_standards_get():
    return jsonify({"naming": get_naming()})


@bp.route("/api/naming-standards", methods=["PUT"])
@_admin_required
def api_naming_standards_put():
    data = request.get_json(silent=True) or {}
    naming = data.get("naming")
    if not isinstance(naming, dict):
        return jsonify({"ok": False, "errors": ["'naming' object is required"]}), 400
    try:
        save_naming(naming)
    except NamingValidationError as exc:
        return jsonify({"ok": False, "errors": exc.errors}), 400
    return jsonify({"ok": True})


@bp.route("/api/naming-standards/reset", methods=["POST"])
@_admin_required
def api_naming_standards_reset():
    reset_to_default()
    return jsonify({"ok": True, "naming": get_naming()})


@bp.route("/api/naming-standards/parse", methods=["POST"])
@_admin_required
def api_naming_standards_parse():
    data = request.get_json(silent=True) or {}
    yaml_text = data.get("yaml_text")
    if not yaml_text or not isinstance(yaml_text, str):
        return jsonify({"ok": False, "error": "'yaml_text' is required"}), 400
    try:
        parsed = _yaml.safe_load(yaml_text)
    except _yaml.YAMLError as exc:
        return jsonify({"ok": False, "error": f"Invalid YAML: {exc}"}), 400
    if not isinstance(parsed, dict):
        return jsonify({"ok": False, "error": "YAML must parse to a mapping"}), 400
    return jsonify({"ok": True, "naming": parsed})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_admin_naming_standards_routes.py -v`
Expected: PASS (9 passed)

- [ ] **Step 5: Run the full test suite to check for regressions**

Run: `pytest tests/ -v -x --ignore=tests/test_planner_naming_template.py --ignore=tests/test_naming_standards.py --ignore=tests/test_admin_naming_standards_routes.py -k "admin or planner"`
Expected: PASS — no other admin route or planner test should be affected
by these additions.

- [ ] **Step 6: Commit**

```bash
git add app/routes/admin_routes.py tests/test_admin_naming_standards_routes.py
git commit -m "feat: add /admin/api/naming-standards routes

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Admin UI markup and CSS

**Files:**
- Modify: `app/templates/admin.html` — add sub-tab button (~line 64, after "Zone Policy") and new panel section (after the Zone Policy panel's closing `</div>`)
- Modify: `app/static/css/style.css` — add 2 new small rules after the existing `.zp-edit-*` block (~line 2070)

No test file for this task — markup/CSS has no unit-testable behavior; it
is exercised end-to-end by Task 6's JS and by manual verification (final
step below).

- [ ] **Step 1: Add the sub-tab button**

In `app/templates/admin.html`, change line 64-65 from:

```html
  <button class="admin-tab" data-panel="zone-policy">Zone Policy</button>
  <button class="admin-tab" data-panel="logs">Application Logs</button>
```

to:

```html
  <button class="admin-tab" data-panel="zone-policy">Zone Policy</button>
  <button class="admin-tab" data-panel="naming-standards">Naming Standards</button>
  <button class="admin-tab" data-panel="logs">Application Logs</button>
```

- [ ] **Step 2: Add the panel markup**

Find the Zone Policy panel's closing tag (the `</div>` that closes
`<div class="admin-panel" id="panel-zone-policy">`, which itself closes
after the `<div class="zp-edit-grid">` block — locate it by reading
`app/templates/admin.html` around the line found via
`grep -n 'id="panel-zone-policy"' app/templates/admin.html` and tracing to
its matching close). Insert this new panel immediately after that closing
`</div>`, before the next `<div class="admin-panel" id="panel-logs">`:

```html
<div class="admin-panel" id="panel-naming-standards">

  <div class="admin-panel-header">
    <h3>
      Naming Standards
      <span class="hm-info-icon" id="nsHelpIcon" title="Object/policy names are built from these patterns using &lt;TOKEN&gt; placeholders (e.g. H_&lt;IP_ADDRESS&gt;). Edit a pattern, check the live preview, then Save. See docs/naming-conventions.md for the full token reference and an AI prompt that turns your company's naming policy document into these patterns.">&#9432;</span>
    </h3>
    <p class="admin-panel-desc">
      Controls the FortiGate object/policy names Rule Validation's AI Assist and Hygiene Fix generate.
      Changes take effect immediately — no restart required.
    </p>
  </div>

  <div id="nsFlash" class="alert" style="display:none;margin-bottom:1rem"></div>

  <div class="zp-edit-grid">
    <div class="zp-edit-section" style="grid-column:1/-1">
      <div class="zp-edit-section-title">Import from YAML</div>
      <p class="admin-panel-desc" style="margin-top:-.3rem">
        Paste a full naming.yaml (or the output of an AI prompt built from your naming policy document — see docs/naming-conventions.md) to populate the fields below. Nothing is saved until you click Save.
      </p>
      <div class="zp-edit-row">
        <textarea id="nsImportYaml" class="form-control" rows="4" style="flex:1;font-family:monospace;font-size:.82rem" placeholder="platforms:&#10;  fortigate:&#10;    conventions:&#10;      host:&#10;        pattern: &quot;H_&lt;IP_ADDRESS&gt;&quot;&#10;      ..."></textarea>
        <button class="btn btn-sm btn-secondary" id="nsImportBtn">Apply to Fields</button>
      </div>
    </div>

    <div class="zp-edit-section" id="nsCardHost">
      <div class="zp-edit-section-title">Host</div>
      <div class="zp-edit-group">
        <div class="zp-edit-label">Pattern (tokens: &lt;IP_ADDRESS&gt;)</div>
        <input type="text" class="form-control ns-pattern" data-type="host" />
      </div>
      <div class="zp-edit-group">
        <div class="zp-edit-label">Notes</div>
        <textarea class="form-control ns-notes" data-type="host" rows="2"></textarea>
      </div>
      <div class="ns-preview" data-type="host"></div>
    </div>

    <div class="zp-edit-section" id="nsCardNetwork">
      <div class="zp-edit-section-title">Network</div>
      <div class="zp-edit-group">
        <div class="zp-edit-label">Pattern (tokens: &lt;NETWORK_ADDRESS&gt;, &lt;PREFIX_LEN&gt;)</div>
        <input type="text" class="form-control ns-pattern" data-type="network" />
      </div>
      <div class="zp-edit-group">
        <div class="zp-edit-label">Notes</div>
        <textarea class="form-control ns-notes" data-type="network" rows="2"></textarea>
      </div>
      <div class="ns-preview" data-type="network"></div>
    </div>

    <div class="zp-edit-section" id="nsCardService">
      <div class="zp-edit-section-title">Service</div>
      <div class="zp-edit-group">
        <div class="zp-edit-label">Pattern (tokens: &lt;PROTO&gt;, &lt;PORT&gt;)</div>
        <input type="text" class="form-control ns-pattern" data-type="service" />
      </div>
      <div class="zp-edit-group">
        <div class="zp-edit-label">Notes</div>
        <textarea class="form-control ns-notes" data-type="service" rows="2"></textarea>
      </div>
      <div class="ns-preview" data-type="service"></div>
    </div>

    <div class="zp-edit-section" id="nsCardPolicy">
      <div class="zp-edit-section-title">Policy</div>
      <div class="zp-edit-group">
        <div class="zp-edit-label">Pattern (tokens: &lt;TICKET_ID&gt;, &lt;SRC_INTF&gt;, &lt;DST_INTF&gt;, &lt;SEQ&gt;)</div>
        <input type="text" class="form-control ns-pattern" data-type="policy" />
      </div>
      <div class="zp-edit-group">
        <div class="zp-edit-label">Notes</div>
        <textarea class="form-control ns-notes" data-type="policy" rows="2"></textarea>
      </div>
      <div class="ns-preview" data-type="policy"></div>
    </div>
  </div>

  <div style="margin-top:1.25rem;display:flex;gap:.75rem;align-items:center">
    <button class="btn btn-primary" id="nsSaveBtn">Save</button>
    <button class="btn btn-secondary" id="nsResetBtn">Reset to Defaults</button>
  </div>

</div>
```

- [ ] **Step 3: Add the preview/error CSS**

In `app/static/css/style.css`, after the `.zp-checkbox-label` rule
(confirmed at line 2068), add:

```css
.ns-preview {
  margin-top: .5rem;
  font-size: .82rem;
  font-family: monospace;
  color: var(--text-muted);
}

.ns-preview.ns-preview-error {
  color: var(--danger);
}
```

- [ ] **Step 4: Manual verification**

Run: `python wsgi.py` (or the app's existing dev-run command), log in as
an admin, open **Admin → Naming Standards**, confirm the 4 cards, import
box, Save/Reset buttons render without console errors (JS wiring lands in
Task 6, so buttons are inert at this point — that's expected).

- [ ] **Step 5: Commit**

```bash
git add app/templates/admin.html app/static/css/style.css
git commit -m "feat: add Naming Standards admin panel markup

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 6: Admin UI JavaScript wiring

**Files:**
- Modify: `app/static/js/admin.js` — add sub-tab dispatch (~line 21), add a new section near the Zone Policy section (after line 1039's `_zonePolicyLoaded` block or at end of file)

No automated test file — this is DOM-wiring JS with no existing JS test
harness in this repo (confirmed: no `*.test.js`/Jest config found during
design). Verified by the manual walkthrough in Step 6 below, which is the
task's actual acceptance gate.

**Interfaces:**
- Consumes: `GET/PUT /admin/api/naming-standards`, `POST /admin/api/naming-standards/reset` (Task 4); the `esc()` helper and `zpFlash`-style flash pattern already present in `admin.js`.

- [ ] **Step 1: Add the sub-tab dispatch line**

In `app/static/js/admin.js`, change line 21 from:

```javascript
      if (btn.dataset.panel === 'zone-policy' && !_zonePolicyLoaded) loadZonePolicyEdit();
```

to:

```javascript
      if (btn.dataset.panel === 'zone-policy' && !_zonePolicyLoaded) loadZonePolicyEdit();
      if (btn.dataset.panel === 'naming-standards' && !_namingStandardsLoaded) loadNamingStandards();
```

- [ ] **Step 2: Add the JS section**

Add this block at the end of the IIFE in `app/static/js/admin.js` (just
before the file's closing `})();`):

```javascript
  // ══════════════════════  NAMING STANDARDS  ═════════════════════════════════

  let _namingStandardsLoaded = false;
  const NS_TYPES = ['host', 'network', 'service', 'policy'];
  const NS_TOKEN_FIELDS = {
    host:    { IP_ADDRESS: '10.0.0.1' },
    network: { NETWORK_ADDRESS: '10.0.0.0', PREFIX_LEN: '24' },
    service: { PROTO: 'tcp', PORT: '443' },
    policy:  { TICKET_ID: 'CHG000000', SRC_INTF: 'WAN1', DST_INTF: 'DMZ', SEQ: '001' },
  };
  let _nsNaming = null;

  function nsFlash(msg, ok) {
    const el = document.getElementById('nsFlash');
    if (!el) return;
    el.textContent   = msg;
    el.className     = `alert ${ok ? 'alert-success' : 'alert-danger'}`;
    el.style.display = '';
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.style.display = 'none'; }, 6000);
  }

  function nsRenderPreview(type) {
    const card    = document.getElementById(`nsCard${type[0].toUpperCase()}${type.slice(1)}`);
    const pattern = card.querySelector('.ns-pattern').value;
    const previewEl = card.querySelector('.ns-preview');
    const tokens = NS_TOKEN_FIELDS[type];

    try {
      const rendered = pattern.replace(/<([A-Z_]+)>/g, (m, name) => {
        if (!(name in tokens)) throw new Error(`unknown token <${name}>`);
        return tokens[name];
      });
      previewEl.textContent = `Example: ${rendered}`;
      previewEl.classList.remove('ns-preview-error');
    } catch (e) {
      previewEl.textContent = `Invalid pattern: ${e.message}`;
      previewEl.classList.add('ns-preview-error');
    }
  }

  function nsPopulateFields(naming) {
    const conventions = ((naming || {}).platforms || {}).fortigate?.conventions || {};
    NS_TYPES.forEach(type => {
      const card = document.getElementById(`nsCard${type[0].toUpperCase()}${type.slice(1)}`);
      const entry = conventions[type] || {};
      card.querySelector('.ns-pattern').value = entry.pattern || '';
      card.querySelector('.ns-notes').value   = entry.notes || '';
      nsRenderPreview(type);
    });
  }

  function nsCollectFields() {
    const naming = JSON.parse(JSON.stringify(_nsNaming || {}));
    naming.platforms = naming.platforms || {};
    naming.platforms.fortigate = naming.platforms.fortigate || {};
    naming.platforms.fortigate.conventions = naming.platforms.fortigate.conventions || {};
    NS_TYPES.forEach(type => {
      const card = document.getElementById(`nsCard${type[0].toUpperCase()}${type.slice(1)}`);
      const existing = naming.platforms.fortigate.conventions[type] || {};
      naming.platforms.fortigate.conventions[type] = {
        ...existing,
        pattern: card.querySelector('.ns-pattern').value,
        notes:   card.querySelector('.ns-notes').value,
      };
    });
    return naming;
  }

  async function loadNamingStandards() {
    _namingStandardsLoaded = true;
    try {
      const resp = await fetch('/admin/api/naming-standards');
      const data = await resp.json();
      _nsNaming = data.naming || {};
      nsPopulateFields(_nsNaming);
    } catch (e) {
      nsFlash(`Failed to load naming standards: ${e.message}`, false);
    }

    document.querySelectorAll('.ns-pattern').forEach(input => {
      input.addEventListener('input', () => nsRenderPreview(input.dataset.type));
    });

    document.getElementById('nsImportBtn').addEventListener('click', async () => {
      const raw = document.getElementById('nsImportYaml').value.trim();
      if (!raw) return;
      const btn = document.getElementById('nsImportBtn');
      btn.disabled = true;
      try {
        const resp = await fetch('/admin/api/naming-standards/parse', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCSRF() },
          body:    JSON.stringify({ yaml_text: raw }),
        });
        const data = await resp.json();
        if (data.ok) {
          _nsNaming = data.naming;
          nsPopulateFields(_nsNaming);
          nsFlash('Imported — review the fields, then Save.', true);
        } else {
          nsFlash(`Import failed: ${data.error}`, false);
        }
      } catch (e) {
        nsFlash(`Import failed: ${e.message}`, false);
      } finally {
        btn.disabled = false;
      }
    });

    document.getElementById('nsSaveBtn').addEventListener('click', async () => {
      const btn = document.getElementById('nsSaveBtn');
      btn.disabled = true;
      try {
        const naming = nsCollectFields();
        const resp = await fetch('/admin/api/naming-standards', {
          method:  'PUT',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCSRF() },
          body:    JSON.stringify({ naming }),
        });
        const data = await resp.json();
        if (data.ok) {
          _nsNaming = naming;
          nsFlash('Naming standards saved.', true);
        } else {
          nsFlash(`Save failed: ${(data.errors || []).join('; ')}`, false);
        }
      } catch (e) {
        nsFlash(`Save failed: ${e.message}`, false);
      } finally {
        btn.disabled = false;
      }
    });

    document.getElementById('nsResetBtn').addEventListener('click', async () => {
      if (!confirm('Reset naming standards to the shipped defaults? This discards all custom patterns.')) return;
      const btn = document.getElementById('nsResetBtn');
      btn.disabled = true;
      try {
        const resp = await fetch('/admin/api/naming-standards/reset', {
          method:  'POST',
          headers: { 'X-CSRF-Token': getCSRF() },
        });
        const data = await resp.json();
        if (data.ok) {
          _nsNaming = data.naming;
          nsPopulateFields(_nsNaming);
          nsFlash('Naming standards reset to defaults.', true);
        } else {
          nsFlash('Reset failed.', false);
        }
      } catch (e) {
        nsFlash(`Reset failed: ${e.message}`, false);
      } finally {
        btn.disabled = false;
      }
    });
  }
```

This uses the `getCSRF()` helper already defined in `admin.js` (confirmed
at line 1515, and already the pattern every other mutating fetch call in
this file uses — e.g. `zpEditPost`-adjacent calls, backup job calls,
scheduled-job calls).

- [ ] **Step 3: Manual verification**

With the app running and logged in as admin:
1. Open Admin → Naming Standards. Confirm the 4 cards populate with the
   values from the server's current `naming.yaml`.
2. Edit the Host pattern to `TEST_<IP_ADDRESS>` — confirm the preview
   updates to `Example: TEST_10.0.0.1` as you type.
3. Edit the Service pattern to include an invalid token, e.g.
   `SVC_<BOGUS>` — confirm the preview shows `Invalid pattern: unknown
   token <BOGUS>` in red.
4. Fix the Service pattern back, click **Save** — confirm a success flash
   appears and `naming.yaml` on disk now contains `TEST_<IP_ADDRESS>` for
   host.
5. Go to Rule Validation → AI Assist, run a change plan that generates a
   host object CLI snippet — confirm the generated name uses the
   `TEST_<IP_ADDRESS>` pattern (proves the live-edit-without-restart
   requirement).
6. Click **Reset to Defaults**, confirm the confirm dialog, confirm
   `naming.yaml` reverts to match `naming.example.yaml` and the cards
   repopulate with default values.
7. Paste a small YAML snippet with a different host pattern (e.g.
   `platforms:\n  fortigate:\n    conventions:\n      host:\n        pattern: "IMPORTED_<IP_ADDRESS>"`)
   into the Import box and click **Apply to Fields** — confirm the Host
   card's pattern field updates to `IMPORTED_<IP_ADDRESS>` and its preview
   re-renders, without anything being saved until you click **Save**
   separately.

- [ ] **Step 4: Commit**

```bash
git add app/static/js/admin.js
git commit -m "feat: wire up Naming Standards admin UI

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 7: Documentation

**Files:**
- Create: `docs/naming-conventions.md`
- Modify: `docs/configuration.md:136` (naming.yaml table row)
- Modify: `CLAUDE.md` (Rule Validation tab section)

No test file — documentation-only task.

- [ ] **Step 1: Write `docs/naming-conventions.md`**

```markdown
# Naming Conventions

Rule Validation's AI Assist and Hygiene Fix generate FortiGate object and
policy names according to patterns in `naming.yaml`. The app ships with a
generic default (`naming.example.yaml`); every install should replace the
`host`/`network`/`service`/`policy` patterns with its own organization's
actual naming standard.

## Editing your standard

**Admin UI (recommended):** Admin → Naming Standards. Edit a pattern, watch
the live preview update, click Save. Changes apply immediately across the
whole app — no restart required.

**By hand:** edit `naming.yaml` directly at the project root and reload
the Admin → Naming Standards tab to see the change reflected (or just use
the app — the next AI Assist/Hygiene Fix request picks it up immediately).

## Token syntax

A pattern is a string containing `<UPPER_SNAKE_CASE>` placeholders, which
are substituted with real values when a name is generated. Each object
type accepts a fixed set of tokens:

| Type | Tokens | Default pattern | Example output |
|---|---|---|---|
| Host | `<IP_ADDRESS>` | `H_<IP_ADDRESS>` | `H_10.1.2.3` |
| Network | `<NETWORK_ADDRESS>`, `<PREFIX_LEN>` | `N_<NETWORK_ADDRESS>_<PREFIX_LEN>` | `N_10.8.0.0_16` |
| Service | `<PROTO>`, `<PORT>` | `SVC_<PROTO>_<PORT>` | `SVC_TCP_8443` |
| Policy | `<TICKET_ID>`, `<SRC_INTF>`, `<DST_INTF>`, `<SEQ>` | `<TICKET_ID>_<SRC_INTF>_TO_<DST_INTF>_<SEQ>` | `CHG0012345_WAN_TO_DMZ_001` |

A pattern that references a token outside this list is rejected at save
time with an error naming the unrecognized token — the app never silently
generates a broken or partial name.

`<SEQ>` is always zero-padded to 3 digits (e.g. `001`, `002`) before
substitution and is not itself configurable in this version.

**Naming customization is currently limited to these 4 object types.**
FQDN/wildcard-FQDN/FQDN-destination-group object naming is not
customizable — those names are generated by fixed, security-hardened
logic elsewhere in the app. `address_group`, `service_group`, `nat_rule`,
and `vip` entries in `naming.yaml` are informational only (shown to the AI
narrator) — nothing in the app currently generates names for those types.

## Example patterns

**Ticket-based (shipped default)** — every object traces back to a change
ticket:
```yaml
policy:
  pattern: "<TICKET_ID>_<SRC_INTF>_TO_<DST_INTF>_<SEQ>"
  examples:
    - "CHG0012345_OT_LAN_TO_IT_001"
```

**Minimal, no ticket reference** — for teams that track changes elsewhere:
```yaml
policy:
  pattern: "<SRC_INTF>-<DST_INTF>-<SEQ>"
  examples:
    - "OT_LAN-IT-001"
```

**Department-code prefixed:**
```yaml
host:
  pattern: "NET-HOST-<IP_ADDRESS>"
  examples:
    - "NET-HOST-10.1.2.3"
```

## Generating a starting point with AI

If you already have a naming-convention policy document (Word, PDF, or a
screenshot from your network/security team), you can use Claude to turn
it into a first draft. Paste this prompt into Claude (or Claude Code),
attaching your document:

```
I am configuring 4THealth+'s Rule Validation naming standards, which use
<UPPER_SNAKE_CASE> token placeholders in a naming.yaml pattern string.

Attached is our organization's naming convention policy document. Please
read it and produce pattern strings for these 4 object types, using only
these exact tokens (do not invent new ones):

  host:     <IP_ADDRESS>
  network:  <NETWORK_ADDRESS>, <PREFIX_LEN>
  service:  <PROTO>, <PORT>
  policy:   <TICKET_ID>, <SRC_INTF>, <DST_INTF>, <SEQ>

For each type, give me: the pattern string, 1-2 example rendered names,
and a one-line note on any assumption you made where the document didn't
explicitly cover that object type.
```

Paste each resulting pattern into the matching card in
**Admin → Naming Standards**, check the live preview, then Save.

## Resetting to defaults

**Admin → Naming Standards → Reset to Defaults** overwrites `naming.yaml`
with the shipped `naming.example.yaml` content. This cannot be undone —
back up `naming.yaml` first if you want to keep your current patterns.
```

- [ ] **Step 2: Update `docs/configuration.md`**

Change line 136 from:

```
| `naming.yaml` | `naming.example.yaml` | Rule-naming standards used by Rule Validation's AI Assist |
```

to:

```
| `naming.yaml` | `naming.example.yaml` | Rule-naming standards used by Rule Validation's AI Assist — editable via **Admin → Naming Standards**, see `docs/naming-conventions.md` |
```

- [ ] **Step 3: Update CLAUDE.md**

In the "Rule Validation tab" section of `CLAUDE.md`, immediately after the
paragraph describing `app/planner/standards.py`'s role (the paragraph
starting "`app/planner/`... deterministic change-planning engine"), add:

```markdown
**Naming Standards admin UI:** `naming.yaml`'s `host`/`network`/`service`/`policy`
patterns are editable live from **Admin → Naming Standards** (no restart
required) — `app/naming_standards.py` validates and atomically persists
edits, `app/planner/naming_template.py` renders `<TOKEN>`-style patterns
into real names, and `standards.py::object_name()`/`policy_name()` call it
instead of hardcoded f-strings. Scope is deliberately limited to these 4
types — FQDN/wildcard-FQDN/FQDN-group naming
(`app/planner/engine.py::_fqdn_object_name`/`_fqdn_group_name`) keeps its
own hardcoded, security-hardened sanitization and is not
admin-configurable; `address_group`/`service_group`/`nat_rule`/`vip`
entries in `naming.yaml` remain documentation-only since nothing generates
names for them. See `docs/naming-conventions.md` for the token reference
and example patterns.
```

- [ ] **Step 4: Commit**

```bash
git add docs/naming-conventions.md docs/configuration.md CLAUDE.md
git commit -m "docs: document Naming Standards admin UI and token syntax

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] Run the full test suite: `pytest tests/ -v`
  Expected: all tests pass, including every new test file from Tasks 1-4
  and every pre-existing test (especially `tests/test_planner_standards.py`,
  `tests/test_planner_engine.py`, `tests/test_planner_catalogs.py`,
  `tests/test_planner_cli_gen.py` — the byte-identical-output regression
  bar from the Global Constraints).
- [ ] Run `ruff check app/ tests/` (or whatever lint command this repo's
  CI uses — confirm via `.github/workflows/` if present) and fix any
  findings before considering the plan complete.
- [ ] Re-read the manual verification checklist in Task 6 Step 4 end to
  end one more time against the finished state of all 7 tasks.
