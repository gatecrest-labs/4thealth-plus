# PSIRT Advisory Assessment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a PSIRT Advisory Assessment section to the Device Review tab: paste/upload a Fortinet PSIRT advisory email, extract structured fields via LLM, let the user confirm/edit them, then deterministically scan the selected ADOM (or all ADOMs) for affected firmware and workaround status, and render a self-contained HTML report.

**Architecture:** Port the deterministic core of `~/code/github/ai/4tanalyst/psirt/` (version matching, workaround checks, priority scoring) into a new `app/psirt/` package, adapted to call `app/fmg_client.py` directly instead of `fortimanager_mcp`. Add a new `extract_json()` capability to the existing `app/llm/` provider layer for the one LLM touchpoint (structured extraction from free-text email). Everything downstream — matching, scoring, the HTML report — is pure deterministic Python, matching this repo's `app/planner/` precedent.

**Tech Stack:** Flask blueprint (`app/routes/psirt_routes.py`), Python dataclasses, `requests` (already a dependency, replacing the source's `httpx`), Jinja2 template for the report, vanilla JS frontend matching `device_review.js`/`hygiene.js` conventions.

**Spec:** `docs/superpowers/specs/2026-08-25-psirt-advisory-assessment-design.md`

## Global Constraints

- LLM is used for extraction only — never to compute a verdict, version match, or score. All of that is deterministic Python (spec Goals).
- Unparseable version syntax, unrecognized workaround text, and missing required extracted fields must surface explicitly — never silently guessed or defaulted (spec Non-goals, Error handling).
- No automated remediation, no mailbox polling, no FortiSwitch/FortiAP/FortiAnalyzer version matching (spec Non-goals).
- No disposition/audit persistence in v1 — one-off analysis only (spec Non-goals).
- No second LLM pass over the finished report — pure deterministic templating (spec Non-goals).
- Enrichment (fortiguard.com + CISA KEV) must be fully disable-able via `PSIRT_ENRICHMENT_ENABLED=false` and must never raise — failures degrade to `enrichment_degraded=True` (spec Configuration, Error handling).
- A degraded scan never claims "no action needed" for a device it couldn't fully check — that device gets `verdict=unknown_needs_manual_check` (spec Error handling).
- `"*"` ADOM scope must respect existing ADOM access control (`app.groups.get_allowed_adoms`) — never scan an ADOM the requesting user can't access (spec Components / Routes).
- Reuse the existing `ai_assist_enabled` app-settings flag and `AI_PROVIDER` selection — no new AI toggle (spec Components).
- Follow `uv add` (never raw `pip install`) if any new dependency is needed — but this plan introduces none; `requests` is already a dependency.

---

## File Structure

```
app/psirt/
  __init__.py
  models.py              # Advisory, AffectedRange, DeviceFinding, PsirtAssessment
  version_match.py        # parse_version, compare_versions, version_in_range, VersionMatchError
  scoring.py               # compute_priority
  enrich.py                 # fetch_advisory_page, check_kev, enrich_advisory (requests-based)
  workaround_checks.py      # WORKAROUND_REGISTRY, match_workaround_pattern, check_workaround
  engine.py                  # assess() — the single entry point
  extract.py                  # build_extraction_prompt, extract_advisory, validate_extracted
  render.py                    # render_psirt_html
  VENDORED_FROM.md              # provenance marker (source commit/date)

app/llm/base.py            # MODIFY: add extract_json() concrete method to LLMProvider

app/routes/psirt_routes.py  # NEW blueprint: extract-status, extract, assess/device, assess, report
app/__init__.py              # MODIFY: register "app.routes.psirt_routes" in _BLUEPRINT_MODULES

app/templates/psirt_report.html   # NEW: Jinja2 report template
app/templates/device_review.html  # MODIFY: add PSIRT section markup + script include
app/static/js/psirt.js             # NEW: extract/review-form/progress-loop/results/report-download

.env.example    # MODIFY: add PSIRT_ENRICHMENT_ENABLED, PSIRT_KEV_URL, PSIRT_FETCH_TIMEOUT
app/config.py     # MODIFY: read the three new env vars onto Config
CLAUDE.md          # MODIFY: document the new section
CHANGELOG.md         # MODIFY: add Unreleased entry

tests/test_psirt_models.py
tests/test_psirt_version_match.py
tests/test_psirt_scoring.py
tests/test_psirt_enrich.py
tests/test_psirt_workaround_checks.py
tests/test_psirt_engine.py
tests/test_llm_extract_json.py
tests/test_psirt_extract.py
tests/test_psirt_render.py
tests/test_psirt_routes.py
```

---

### Task 1: `app/psirt` package skeleton + data models

**Files:**
- Create: `app/psirt/__init__.py` (empty)
- Create: `app/psirt/models.py`
- Create: `app/psirt/VENDORED_FROM.md`
- Test: `tests/test_psirt_models.py`

**Interfaces:**
- Produces: `app.psirt.models.PsirtDataError(source, detail)`, `AffectedRange(product, min_version="", max_version="", fixed_version="", notes="")` with `.to_dict()`, `Advisory(advisory_id, advisory_url="", cve_ids=[], published_date="", fortinet_severity="", cvss_score=None, description="", affected_ranges=[], workaround_text="", exploited_in_wild_text="", enrichment_degraded=False)` with `.to_dict()`, `DeviceFinding(device, adom, product, current_version, in_range, workaround_status, verdict, reason)` with `.to_dict()`, `PsirtAssessment(advisory, findings=[], out_of_scope_products=[], priority="", priority_rationale="", kev_hit=False, degraded=False, warnings=[])` with `.to_dict()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_psirt_models.py
"""Tests for PSIRT dataclass models — construction and to_dict() shape."""
from app.psirt.models import AffectedRange, Advisory, DeviceFinding, PsirtAssessment


def test_affected_range_to_dict():
    r = AffectedRange(product="FortiOS", min_version="7.4.0", max_version="7.4.4",
                       fixed_version="7.4.5", notes="")
    assert r.to_dict() == {
        "product": "FortiOS", "min_version": "7.4.0", "max_version": "7.4.4",
        "fixed_version": "7.4.5", "notes": "",
    }


def test_advisory_to_dict_round_trip():
    adv = Advisory(
        advisory_id="FG-IR-24-001",
        cve_ids=["CVE-2024-12345"],
        affected_ranges=[AffectedRange(product="FortiOS", max_version="7.4.4")],
    )
    d = adv.to_dict()
    assert d["advisory_id"] == "FG-IR-24-001"
    assert d["cve_ids"] == ["CVE-2024-12345"]
    assert d["affected_ranges"] == [
        {"product": "FortiOS", "min_version": "", "max_version": "7.4.4",
         "fixed_version": "", "notes": ""}
    ]
    assert d["enrichment_degraded"] is False


def test_device_finding_to_dict():
    f = DeviceFinding(device="FW01", adom="Corp", product="FortiOS",
                       current_version="7.4.2", in_range=True,
                       workaround_status="not_in_place",
                       verdict="config_change_required", reason="test reason")
    assert f.to_dict()["verdict"] == "config_change_required"
    assert f.to_dict()["in_range"] is True


def test_psirt_assessment_to_dict():
    adv = Advisory(advisory_id="FG-IR-24-001")
    finding = DeviceFinding(device="FW01", adom="Corp", product="FortiOS",
                             current_version="7.4.2", in_range=True,
                             workaround_status="not_in_place",
                             verdict="config_change_required", reason="r")
    assessment = PsirtAssessment(advisory=adv, findings=[finding], priority="high",
                                  priority_rationale="CVSS 8.1", kev_hit=True)
    d = assessment.to_dict()
    assert d["advisory"]["advisory_id"] == "FG-IR-24-001"
    assert d["findings"][0]["device"] == "FW01"
    assert d["priority"] == "high"
    assert d["kev_hit"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.psirt'`

- [ ] **Step 3: Write the package skeleton and models**

Create `app/psirt/__init__.py` (empty file).

Create `app/psirt/models.py`:

```python
"""
Data models for the PSIRT advisory assessment engine.

Ported from ~/code/github/ai/4tanalyst/psirt/models.py — see VENDORED_FROM.md
for the source commit. PsirtDataError means "a source failed", never "no
results" — same discipline as app.planner.models.PlannerDataError.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class PsirtDataError(Exception):
    """A data source (FortiManager, advisory enrichment) failed outright."""

    def __init__(self, source: str, detail: str):
        self.source = source
        self.detail = detail
        super().__init__(f"[{source}] {detail}")


@dataclass
class AffectedRange:
    product: str
    min_version: str = ""
    max_version: str = ""
    fixed_version: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "product": self.product,
            "min_version": self.min_version,
            "max_version": self.max_version,
            "fixed_version": self.fixed_version,
            "notes": self.notes,
        }


@dataclass
class Advisory:
    advisory_id: str
    advisory_url: str = ""
    cve_ids: list[str] = field(default_factory=list)
    published_date: str = ""
    fortinet_severity: str = ""
    cvss_score: float | None = None
    description: str = ""
    affected_ranges: list[AffectedRange] = field(default_factory=list)
    workaround_text: str = ""
    exploited_in_wild_text: str = ""
    enrichment_degraded: bool = False

    def to_dict(self) -> dict:
        return {
            "advisory_id": self.advisory_id,
            "advisory_url": self.advisory_url,
            "cve_ids": list(self.cve_ids),
            "published_date": self.published_date,
            "fortinet_severity": self.fortinet_severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "affected_ranges": [r.to_dict() for r in self.affected_ranges],
            "workaround_text": self.workaround_text,
            "exploited_in_wild_text": self.exploited_in_wild_text,
            "enrichment_degraded": self.enrichment_degraded,
        }


@dataclass
class DeviceFinding:
    device: str
    adom: str
    product: str
    current_version: str
    in_range: bool
    workaround_status: str  # in_place | not_in_place | manual_verification_required | not_applicable
    verdict: str  # no_action | config_change_required | upgrade_required | unknown_needs_manual_check
    reason: str

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "adom": self.adom,
            "product": self.product,
            "current_version": self.current_version,
            "in_range": self.in_range,
            "workaround_status": self.workaround_status,
            "verdict": self.verdict,
            "reason": self.reason,
        }


@dataclass
class PsirtAssessment:
    advisory: Advisory
    findings: list[DeviceFinding] = field(default_factory=list)
    out_of_scope_products: list[str] = field(default_factory=list)
    priority: str = ""
    priority_rationale: str = ""
    kev_hit: bool = False
    degraded: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "advisory": self.advisory.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "out_of_scope_products": list(self.out_of_scope_products),
            "priority": self.priority,
            "priority_rationale": self.priority_rationale,
            "kev_hit": self.kev_hit,
            "degraded": self.degraded,
            "warnings": list(self.warnings),
        }
```

Create `app/psirt/VENDORED_FROM.md`:

```markdown
# Provenance

`app/psirt/` is an adapted port of the `psirt/` package from
`~/code/github/ai/4tanalyst`, following the same fork-not-dependency
pattern documented in `app/planner/VENDORED_FROM.md`.

- Source repo: `~/code/github/ai/4tanalyst`
- Source path: `psirt/`
- Ported from commit: (fill in with `git -C ~/code/github/ai/4tanalyst rev-parse HEAD` at port time)
- Port date: 2026-08-25

## Why a fork, not a dependency

The source's `psirt/workaround_checks.py` and `psirt/engine.py` call
`fortimanager_mcp.query`/`fortimanager_mcp.client` — a separate MCP-server
FortiManager client. This repo's `app/fmg_client.py` is a different,
already-authenticated client used in-process by every other feature. The
port swaps every FMG call site to the equivalent `app/fmg_client.py`
method; `models.py`, `version_match.py`, `scoring.py`, and `enrich.py` have
no FMG dependency and port close to verbatim (enrich.py: `httpx` swapped
for this repo's existing `requests` dependency).

## Syncing future changes

Same workflow as `app/planner/`'s (see the `4tanalyst-sync-workflow`
memory): run
`git -C ~/code/github/ai/4tanalyst log <last-synced-sha>..HEAD --oneline -- psirt/`
to see what changed upstream, review each change, and manually port the
relevant parts — never blindly copy, since the FMG data-access layer has
diverged by design. Update the "Ported from commit" line above after each
sync.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_models.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/psirt/__init__.py app/psirt/models.py app/psirt/VENDORED_FROM.md tests/test_psirt_models.py
git commit -m "Add app/psirt package skeleton and data models"
```

---

### Task 2: `version_match.py`

**Files:**
- Create: `app/psirt/version_match.py`
- Test: `tests/test_psirt_version_match.py`

**Interfaces:**
- Consumes: `app.psirt.models.AffectedRange` (Task 1)
- Produces: `VersionMatchError(Exception)`, `parse_version(text: str) -> tuple[int, ...]`, `compare_versions(a: str, b: str) -> int`, `version_in_range(version: str, rng: AffectedRange) -> bool`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_psirt_version_match.py
"""Tests for FortiOS/FortiManager version comparison."""
import pytest
from app.psirt.models import AffectedRange
from app.psirt.version_match import VersionMatchError, compare_versions, parse_version, version_in_range


def test_parse_version_three_part():
    assert parse_version("7.4.4") == (7, 4, 4)


def test_parse_version_two_part_padded():
    assert parse_version("7.4") == (7, 4, 0)


def test_parse_version_invalid_raises():
    with pytest.raises(VersionMatchError):
        parse_version("not-a-version")


def test_parse_version_empty_raises():
    with pytest.raises(VersionMatchError):
        parse_version("")


def test_compare_versions():
    assert compare_versions("7.4.4", "7.4.5") == -1
    assert compare_versions("7.4.5", "7.4.4") == 1
    assert compare_versions("7.4.4", "7.4.4") == 0


def test_version_in_range_bounded():
    rng = AffectedRange(product="FortiOS", min_version="7.4.0", max_version="7.4.4")
    assert version_in_range("7.4.2", rng) is True
    assert version_in_range("7.4.5", rng) is False
    assert version_in_range("7.3.9", rng) is False


def test_version_in_range_open_ended_below():
    """'X and below' — no min_version, everything <= max matches."""
    rng = AffectedRange(product="FortiOS", max_version="7.4.0")
    assert version_in_range("7.0.0", rng) is True
    assert version_in_range("7.4.0", rng) is True
    assert version_in_range("7.4.1", rng) is False


def test_version_in_range_open_ended_above():
    """No max_version — everything >= min matches."""
    rng = AffectedRange(product="FortiOS", min_version="7.4.0")
    assert version_in_range("7.4.0", rng) is True
    assert version_in_range("9.9.9", rng) is True
    assert version_in_range("7.3.9", rng) is False


def test_version_in_range_unparseable_device_version_raises():
    rng = AffectedRange(product="FortiOS", max_version="7.4.0")
    with pytest.raises(VersionMatchError):
        version_in_range("garbage", rng)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_version_match.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.psirt.version_match'`

- [ ] **Step 3: Write the implementation**

```python
# app/psirt/version_match.py
"""
FortiOS/FortiManager version comparison.

Versions are MAJOR.MINOR.PATCH (e.g. "7.4.4"); a two-component version
("7.4") is padded with a zero patch level. Advisory ranges arrive already
structured (min/max version strings from the LLM extraction step, not raw
"X through Y" prose) — this module only compares dotted version strings,
it does not parse English range text.

Unparseable version syntax raises VersionMatchError rather than defaulting
to "not affected" — callers must surface this, never silently skip a device.
"""

from __future__ import annotations

import re

from app.psirt.models import AffectedRange

_VERSION_RE = re.compile(r"^\d+(\.\d+){1,2}$")


class VersionMatchError(Exception):
    """A version string could not be parsed."""


def parse_version(text: str) -> tuple[int, ...]:
    text = (text or "").strip()
    if not _VERSION_RE.match(text):
        raise VersionMatchError(f"cannot parse version string: {text!r}")
    parts = [int(p) for p in text.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def compare_versions(a: str, b: str) -> int:
    va, vb = parse_version(a), parse_version(b)
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def version_in_range(version: str, rng: AffectedRange) -> bool:
    v = parse_version(version)
    if rng.min_version and v < parse_version(rng.min_version):
        return False
    if rng.max_version and v > parse_version(rng.max_version):
        return False
    return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_version_match.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add app/psirt/version_match.py tests/test_psirt_version_match.py
git commit -m "Add PSIRT version_match module"
```

---

### Task 3: `scoring.py`

**Files:**
- Create: `app/psirt/scoring.py`
- Test: `tests/test_psirt_scoring.py`

**Interfaces:**
- Produces: `compute_priority(cvss_score: float | None, fortinet_severity: str, exploited_in_wild_text: str, kev_hit: bool, any_device_in_range: bool) -> tuple[str, str]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_psirt_scoring.py
"""Tests for deterministic PSIRT priority scoring."""
from app.psirt.scoring import compute_priority


def test_zero_exposure_is_informational_regardless_of_severity():
    priority, rationale = compute_priority(
        cvss_score=9.8, fortinet_severity="Critical",
        exploited_in_wild_text="actively exploited",
        kev_hit=True, any_device_in_range=False,
    )
    assert priority == "informational"
    assert "no devices" in rationale.lower() or "nothing to act on" in rationale.lower()


def test_cvss_band_critical():
    priority, _ = compute_priority(9.5, "", "", False, True)
    assert priority == "critical"


def test_cvss_band_high():
    priority, _ = compute_priority(7.5, "", "", False, True)
    assert priority == "high"


def test_cvss_band_medium():
    priority, _ = compute_priority(5.0, "", "", False, True)
    assert priority == "medium"


def test_cvss_band_low():
    priority, _ = compute_priority(2.0, "", "", False, True)
    assert priority == "low"


def test_no_cvss_falls_back_to_fortinet_severity():
    priority, rationale = compute_priority(None, "High", "", False, True)
    assert priority == "high"
    assert "fortinet" in rationale.lower()


def test_no_cvss_no_severity_defaults_medium():
    priority, _ = compute_priority(None, "", "", False, True)
    assert priority == "medium"


def test_kev_hit_forces_at_least_high():
    priority, rationale = compute_priority(4.0, "", "", kev_hit=True, any_device_in_range=True)
    assert priority == "high"
    assert "kev" in rationale.lower()


def test_exploited_text_forces_at_least_high():
    priority, rationale = compute_priority(
        3.0, "", "actively exploited in the wild", kev_hit=False, any_device_in_range=True,
    )
    assert priority == "high"
    assert "exploit" in rationale.lower()


def test_negative_exploitation_language_does_not_force_high():
    """'Fortinet is not aware of exploitation' must NOT trigger escalation."""
    priority, _ = compute_priority(
        3.0, "", "Fortinet is not aware of any instance where this vulnerability has been exploited",
        kev_hit=False, any_device_in_range=True,
    )
    assert priority == "low"


def test_kev_does_not_downgrade_an_already_critical_score():
    priority, _ = compute_priority(9.5, "", "", kev_hit=True, any_device_in_range=True)
    assert priority == "critical"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_scoring.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.psirt.scoring'`

- [ ] **Step 3: Write the implementation**

```python
# app/psirt/scoring.py
"""
Deterministic PSIRT priority scoring.

Priority starts from a CVSS band (or Fortinet's own severity label when no
CVSS score was extracted), then is forced to at least "high" if the
advisory text states exploitation or the CVE is CISA KEV-listed — a
vulnerability being actively exploited outranks a merely high CVSS score.
A zero-exposure fleet always scores "informational" regardless of
severity, since there is nothing to act on.
"""

from __future__ import annotations

_PRIORITY_RANK = {"unknown": -1, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_FALLBACK = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
}

_EXPLOITED_POSITIVE = frozenset({
    "actively exploited",
    "exploitation in the wild",
    "exploited in the wild",
    "being exploited",
    "has been exploited",
    "was exploited",
    "exploitation has been detected",
    "exploitation detected",
    "confirmed exploitation",
    "reported exploitation",
    "exploitation observed",
    "is being exploited",
    "instance of exploitation",
    "instances of exploitation",
})

_EXPLOITED_NEGATIVE = frozenset({
    "not aware of",
    "no known exploitation",
    "not exploited",
    "no exploitation",
    "not been exploited",
    "no active exploit",
    "is not being exploited",
    "not actively exploited",
    "no reports of exploitation",
})


def _indicates_exploitation(text: str) -> bool:
    """Return True only if advisory text contains positive exploitation language.

    A non-empty string is NOT sufficient — advisories commonly include phrases
    like "Fortinet is not aware of exploitation in the wild" which must NOT
    trigger the HIGH escalation. Negative qualifiers take precedence.
    """
    t = (text or "").lower()
    if not t:
        return False
    if any(neg in t for neg in _EXPLOITED_NEGATIVE):
        return False
    return any(pos in t for pos in _EXPLOITED_POSITIVE)


def _cvss_band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def compute_priority(
    cvss_score: float | None,
    fortinet_severity: str,
    exploited_in_wild_text: str,
    kev_hit: bool,
    any_device_in_range: bool,
) -> tuple[str, str]:
    if not any_device_in_range:
        return "informational", (
            "No devices in the fleet fall within the advisory's affected "
            "version range(s) — nothing to act on."
        )

    if cvss_score is not None:
        base = _cvss_band(cvss_score)
        base_reason = f"CVSS base score {cvss_score}"
    else:
        base = _SEVERITY_FALLBACK.get((fortinet_severity or "").strip().lower(), "medium")
        base_reason = f"no CVSS score extracted; used Fortinet's own severity rating ({fortinet_severity or 'unspecified'})"

    exploited = _indicates_exploitation(exploited_in_wild_text)
    forced_reasons = []
    if exploited:
        forced_reasons.append("advisory states exploitation in the wild")
    if kev_hit:
        forced_reasons.append("CVE is listed in the CISA KEV catalog")

    priority = base
    if forced_reasons and _PRIORITY_RANK[base] < _PRIORITY_RANK["high"]:
        priority = "high"

    rationale = base_reason
    if forced_reasons:
        rationale += f"; forced to at least High because: {', '.join(forced_reasons)}"

    return priority, rationale
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_scoring.py -v`
Expected: PASS (10 tests)

- [ ] **Step 5: Commit**

```bash
git add app/psirt/scoring.py tests/test_psirt_scoring.py
git commit -m "Add PSIRT scoring module"
```

---

### Task 4: `enrich.py` (requests-based)

**Files:**
- Create: `app/psirt/enrich.py`
- Test: `tests/test_psirt_enrich.py`

**Interfaces:**
- Consumes: `app.psirt.models.Advisory` (Task 1)
- Produces: `check_kev(cve_ids: list[str], http_client, kev_url: str, timeout: float = 5.0) -> bool`, `fetch_advisory_page(advisory_url: str, http_client, timeout: float = 5.0) -> dict`, `enrich_advisory(advisory: Advisory, http_client, kev_url: str, enrichment_enabled: bool, timeout: float = 5.0) -> Advisory` (note: `enrichment_enabled` param added vs. source — see Global Constraints on the opt-out flag)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_psirt_enrich.py
"""Tests for PSIRT advisory enrichment (fortiguard.com + CISA KEV), mocked HTTP."""
from unittest.mock import MagicMock

from app.psirt.enrich import check_kev, enrich_advisory, fetch_advisory_page
from app.psirt.models import Advisory


def _fake_response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    return resp


def test_check_kev_hit():
    client = MagicMock()
    client.get.return_value = _fake_response(
        json_data={"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}
    )
    assert check_kev(["CVE-2024-12345"], client, "https://kev.example/feed.json") is True


def test_check_kev_miss():
    client = MagicMock()
    client.get.return_value = _fake_response(json_data={"vulnerabilities": []})
    assert check_kev(["CVE-2024-99999"], client, "https://kev.example/feed.json") is False


def test_check_kev_empty_url_returns_false():
    client = MagicMock()
    assert check_kev(["CVE-2024-12345"], client, "") is False
    client.get.assert_not_called()


def test_check_kev_network_failure_returns_false():
    client = MagicMock()
    client.get.side_effect = Exception("connection refused")
    assert check_kev(["CVE-2024-12345"], client, "https://kev.example/feed.json") is False


def test_fetch_advisory_page_extracts_cvss_and_severity():
    client = MagicMock()
    client.get.return_value = _fake_response(
        text="Some advisory text. CVSS Score: 8.1 more text. Severity: High done."
    )
    result = fetch_advisory_page("https://fortiguard.com/psirt/FG-IR-24-001", client)
    assert result["fetched"] is True
    assert result["cvss_score"] == 8.1
    assert result["fortinet_severity"] == "High"


def test_fetch_advisory_page_network_failure_degrades():
    client = MagicMock()
    client.get.side_effect = Exception("timeout")
    result = fetch_advisory_page("https://fortiguard.com/psirt/FG-IR-24-001", client)
    assert result["fetched"] is False
    assert result["cvss_score"] is None


def test_fetch_advisory_page_empty_url_returns_not_fetched():
    client = MagicMock()
    result = fetch_advisory_page("", client)
    assert result["fetched"] is False
    client.get.assert_not_called()


def test_enrich_advisory_fills_missing_fields():
    client = MagicMock()
    client.get.side_effect = [
        _fake_response(text="CVSS Score: 7.2. Severity: High."),  # advisory page
        _fake_response(json_data={"vulnerabilities": []}),         # KEV feed
    ]
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    enriched = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=True)
    assert enriched.cvss_score == 7.2
    assert enriched.fortinet_severity == "High"
    assert enriched.enrichment_degraded is False


def test_enrich_advisory_disabled_flag_skips_fetches_entirely():
    client = MagicMock()
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    enriched = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=False)
    client.get.assert_not_called()
    assert enriched.enrichment_degraded is True
    assert enriched._kev_hit is False


def test_enrich_advisory_never_raises_on_total_failure():
    client = MagicMock()
    client.get.side_effect = Exception("dns failure")
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    enriched = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=True)
    assert enriched.enrichment_degraded is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_enrich.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.psirt.enrich'`

- [ ] **Step 3: Write the implementation**

```python
# app/psirt/enrich.py
"""
Best-effort enrichment of an LLM-extracted Advisory from two external
sources: the live fortiguard.com advisory page (fills/corroborates CVSS
and severity) and the CISA Known Exploited Vulnerabilities catalog (an
independent signal that a CVE is being actively exploited).

Both fetches are optional and failures never raise — enrichment always
degrades gracefully to "use what the email gave us." Callers pass in a
requests-compatible http_client (requests itself, or a mock/session in
tests) so tests never touch the network. enrichment_enabled=False skips
both fetches entirely (PSIRT_ENRICHMENT_ENABLED=false — air-gapped
deployments).
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from app.psirt.models import Advisory

_CVSS_RE = re.compile(r"CVSS\s*Score:?\s*([\d.]+)", re.IGNORECASE)
_SEVERITY_RE = re.compile(r"Severity:?\s*(Critical|High|Medium|Low)", re.IGNORECASE)


def check_kev(cve_ids: list[str], http_client: Any, kev_url: str, timeout: float = 5.0) -> bool:
    """Check if any CVE in cve_ids appears in the CISA KEV catalog.

    Never raises — network failures return False.
    """
    if not cve_ids or not kev_url:
        return False
    try:
        resp = http_client.get(kev_url, timeout=timeout)
        if resp.status_code != 200:
            return False
        data = resp.json()
    except Exception:
        return False
    entries = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    known = {e.get("cveID", "") for e in entries if isinstance(e, dict)}
    return any(cve in known for cve in cve_ids)


def fetch_advisory_page(advisory_url: str, http_client: Any, timeout: float = 5.0) -> dict:
    """Fetch the fortiguard.com advisory page and extract CVSS score and severity.

    Never raises — network failures or parse errors return fetched=False.
    """
    if not advisory_url:
        return {"fetched": False, "cvss_score": None, "fortinet_severity": "", "raw_text": ""}
    try:
        resp = http_client.get(advisory_url, timeout=timeout)
        if resp.status_code != 200:
            return {"fetched": False, "cvss_score": None, "fortinet_severity": "", "raw_text": ""}
        text = resp.text
    except Exception:
        return {"fetched": False, "cvss_score": None, "fortinet_severity": "", "raw_text": ""}

    cvss_match = _CVSS_RE.search(text)
    severity_match = _SEVERITY_RE.search(text)
    return {
        "fetched": True,
        "cvss_score": float(cvss_match.group(1)) if cvss_match else None,
        "fortinet_severity": severity_match.group(1) if severity_match else "",
        "raw_text": text,
    }


def enrich_advisory(
    advisory: Advisory,
    http_client: Any,
    kev_url: str,
    enrichment_enabled: bool = True,
    timeout: float = 5.0,
) -> Advisory:
    """Enrich an Advisory from fortiguard.com and CISA KEV catalog.

    Returns a new Advisory; never raises. When enrichment_enabled is False,
    both fetches are skipped entirely and enrichment_degraded is set True.
    """
    if not enrichment_enabled:
        enriched = replace(advisory, enrichment_degraded=True)
        enriched._kev_hit = False  # type: ignore[attr-defined]
        return enriched

    page = fetch_advisory_page(advisory.advisory_url, http_client, timeout=timeout)
    kev_hit = check_kev(advisory.cve_ids, http_client, kev_url, timeout=timeout)

    updates: dict = {}
    if page["fetched"]:
        if advisory.cvss_score is None and page["cvss_score"] is not None:
            updates["cvss_score"] = page["cvss_score"]
        if not advisory.fortinet_severity and page["fortinet_severity"]:
            updates["fortinet_severity"] = page["fortinet_severity"]

    updates["enrichment_degraded"] = not page["fetched"]

    enriched = replace(advisory, **updates)
    enriched._kev_hit = kev_hit  # type: ignore[attr-defined]
    return enriched
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_enrich.py -v`
Expected: PASS (10 tests)

- [ ] **Step 5: Commit**

```bash
git add app/psirt/enrich.py tests/test_psirt_enrich.py
git commit -m "Add PSIRT enrichment module (requests-based, opt-out flag)"
```

---

### Task 5: `workaround_checks.py` (adapted to FMGClient, real trusted-hosts check)

**Files:**
- Create: `app/psirt/workaround_checks.py`
- Test: `tests/test_psirt_workaround_checks.py`

**Interfaces:**
- Consumes: `app.fmg_client.FMGClient.get_device_interfaces_all_vdoms(adom, device_name) -> list` (existing), `app.fmg_client.FMGClient.get_device_admins(adom, device_name) -> list` (existing)
- Produces: `WORKAROUND_REGISTRY: dict[str, tuple[tuple[str,...], Callable]]`, `match_workaround_pattern(workaround_text: str) -> str | None`, `check_workaround(pattern_key: str, client, adom: str, device: str) -> str` (returns `"in_place"` / `"not_in_place"` / `"manual_verification_required"`)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_psirt_workaround_checks.py
"""Tests for the PSIRT workaround-pattern registry and FMG-backed checks."""
from unittest.mock import MagicMock

from app.psirt.workaround_checks import check_workaround, match_workaround_pattern


def test_match_workaround_pattern_http_admin_access():
    assert match_workaround_pattern("Disable HTTP/HTTPS admin access on all interfaces") \
        == "disable_http_https_admin_access"


def test_match_workaround_pattern_internet_facing():
    assert match_workaround_pattern("Disable GUI on internet-facing interfaces") \
        == "disable_gui_internet_facing"


def test_match_workaround_pattern_trusted_hosts():
    assert match_workaround_pattern("Configure trusted hosts to restrict management access") \
        == "configure_trusted_hosts"


def test_match_workaround_pattern_unrecognized_returns_none():
    assert match_workaround_pattern("Contact support for a hotfix") is None


def test_match_workaround_pattern_empty_returns_none():
    assert match_workaround_pattern("") is None


def test_check_workaround_unregistered_pattern_returns_manual():
    client = MagicMock()
    assert check_workaround("not_a_real_pattern", client, "Corp", "FW01") == "manual_verification_required"


def test_check_disable_http_https_admin_access_in_place():
    """No interface allows http/https admin access → in_place."""
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "port1", "allowaccess": "ping"},
        {"name": "wan1", "allowaccess": "ping ssh"},
    ]
    status = check_workaround("disable_http_https_admin_access", client, "Corp", "FW01")
    assert status == "in_place"


def test_check_disable_http_https_admin_access_not_in_place():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "port1", "allowaccess": "ping"},
        {"name": "wan1", "allowaccess": "ping https"},
    ]
    status = check_workaround("disable_http_https_admin_access", client, "Corp", "FW01")
    assert status == "not_in_place"


def test_check_disable_http_https_admin_access_no_interfaces_is_manual():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = []
    status = check_workaround("disable_http_https_admin_access", client, "Corp", "FW01")
    assert status == "manual_verification_required"


def test_check_disable_gui_internet_facing_public_ip_allows_https_not_in_place():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "wan1", "ip": "203.0.113.5/24", "allowaccess": "https ping"},
        {"name": "port1", "ip": "10.1.1.1/24", "allowaccess": "https ping"},  # private, ignored
    ]
    status = check_workaround("disable_gui_internet_facing", client, "Corp", "FW01")
    assert status == "not_in_place"


def test_check_disable_gui_internet_facing_public_ip_no_gui_in_place():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "wan1", "ip": "203.0.113.5/24", "allowaccess": "ping"},
    ]
    status = check_workaround("disable_gui_internet_facing", client, "Corp", "FW01")
    assert status == "in_place"


def test_check_disable_gui_internet_facing_no_public_interfaces_is_manual():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "port1", "ip": "10.1.1.1/24", "allowaccess": "https"},
    ]
    status = check_workaround("disable_gui_internet_facing", client, "Corp", "FW01")
    assert status == "manual_verification_required"


def test_check_trusted_hosts_in_place_when_all_admins_restricted():
    """Real check (upgraded from the source's permanent stub) — reuses the
    same unrestricted-trusthost detection as app.device_review._run_trusted_hosts."""
    client = MagicMock()
    client.get_device_admins.return_value = [
        {"name": "admin", "trusthost1": "10.1.1.0 255.255.255.0"},
    ]
    status = check_workaround("configure_trusted_hosts", client, "Corp", "FW01")
    assert status == "in_place"


def test_check_trusted_hosts_not_in_place_when_any_admin_unrestricted():
    client = MagicMock()
    client.get_device_admins.return_value = [
        {"name": "admin", "trusthost1": "10.1.1.0 255.255.255.0"},
        {"name": "backup_admin", "trusthost1": "0.0.0.0 0.0.0.0"},
    ]
    status = check_workaround("configure_trusted_hosts", client, "Corp", "FW01")
    assert status == "not_in_place"


def test_check_trusted_hosts_no_admin_data_is_manual():
    client = MagicMock()
    client.get_device_admins.return_value = "not-a-list"
    status = check_workaround("configure_trusted_hosts", client, "Corp", "FW01")
    assert status == "manual_verification_required"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_workaround_checks.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.psirt.workaround_checks'`

- [ ] **Step 3: Write the implementation**

```python
# app/psirt/workaround_checks.py
"""
Registry of recognized PSIRT workaround patterns and the deterministic
FortiManager config checks that verify whether each is already applied.

Advisory workaround text is free-form English written by Fortinet. Rather
than have the LLM guess whether a workaround is in place, extraction only
captures the raw text; this module matches that text against a small,
explicitly-registered set of patterns and runs a real config check for
each match via app.fmg_client.FMGClient. Unrecognized text never gets a
guessed status — it comes back as "manual_verification_required", and the
registry is expected to grow one advisory at a time.

configure_trusted_hosts is a REAL check here (unlike the 4tanalyst source,
where it was a permanent stub returning manual_verification_required
because the underlying FMG query wasn't implemented there) — this repo
already has FMGClient.get_device_admins() and the exact unrestricted-host
detection logic in app.device_review._run_trusted_hosts, reused below.
"""

from __future__ import annotations

import ipaddress as _ipaddress
from collections.abc import Callable
from typing import Any

_ADMIN_ACCESS_SERVICES = {"http", "https"}

_RFC1918_NETS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("100.64.0.0/10"),   # shared address space (RFC 6598)
    _ipaddress.ip_network("169.254.0.0/16"),  # link-local
    _ipaddress.ip_network("127.0.0.0/8"),     # loopback
]

# Same unrestricted-trusthost values app.device_review._run_trusted_hosts uses.
_UNRESTRICTED_HOSTS = {"0.0.0.0/0", "0.0.0.0 0.0.0.0", "0.0.0.0/0.0.0.0"}


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is publicly routable (not RFC1918 / link-local / loopback)."""
    try:
        addr = _ipaddress.ip_address(str(ip_str or "").split("/")[0].split()[0])
        return (
            not addr.is_loopback
            and not addr.is_link_local
            and not any(addr in net for net in _RFC1918_NETS)
        )
    except ValueError:
        return False


def _allowaccess_has_gui(iface: dict) -> bool:
    allowaccess = iface.get("allowaccess", []) or []
    if isinstance(allowaccess, str):
        allowaccess = allowaccess.split()
    return bool(_ADMIN_ACCESS_SERVICES & {str(a).lower() for a in allowaccess})


def _check_disable_http_https_admin_access(client: Any, adom: str, device: str) -> str:
    """Check that no interface allows HTTP/HTTPS admin access (any interface)."""
    interfaces = client.get_device_interfaces_all_vdoms(adom, device)
    if not isinstance(interfaces, list):
        return "manual_verification_required"
    found_any_interface = False
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        found_any_interface = True
        if _allowaccess_has_gui(iface):
            return "not_in_place"
    if not found_any_interface:
        return "manual_verification_required"
    return "in_place"


def _check_disable_gui_internet_facing(client: Any, adom: str, device: str) -> str:
    """Check that no internet-facing interface (public IP) allows HTTP/HTTPS admin access."""
    interfaces = client.get_device_interfaces_all_vdoms(adom, device)
    if not isinstance(interfaces, list):
        return "manual_verification_required"
    found_any_interface = False
    found_any_public = False
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        found_any_interface = True
        ip_raw = str(iface.get("ip", "") or "")
        if not ip_raw or ip_raw in ("0.0.0.0/0", "0.0.0.0 0.0.0.0", "0.0.0.0"):
            continue
        if not _is_public_ip(ip_raw):
            continue
        found_any_public = True
        if _allowaccess_has_gui(iface):
            return "not_in_place"
    if not found_any_interface:
        return "manual_verification_required"
    if not found_any_public:
        return "manual_verification_required"
    return "in_place"


def _check_trusted_hosts(client: Any, adom: str, device: str) -> str:
    """Real check — mirrors app.device_review._run_trusted_hosts' unrestricted-host detection."""
    admins = client.get_device_admins(adom, device)
    if not isinstance(admins, list):
        return "manual_verification_required"
    for acct in admins:
        if not isinstance(acct, dict):
            continue
        hosts = [str(acct.get(f"trusthost{i}", "")).strip() for i in range(1, 11)]
        non_empty = [h for h in hosts if h and h != "0.0.0.0/255.255.255.255"]
        if not non_empty or all(
            h in _UNRESTRICTED_HOSTS or h == "0.0.0.0 0.0.0.0" for h in non_empty
        ):
            return "not_in_place"
    return "in_place"


# pattern key -> (substrings that identify this workaround in advisory text, check function)
WORKAROUND_REGISTRY: dict[str, tuple[tuple[str, ...], Callable[[Any, str, str], str]]] = {
    "disable_http_https_admin_access": (
        ("http/https admin", "https admin access", "http admin access",
         "disable http", "disable https"),
        _check_disable_http_https_admin_access,
    ),
    "disable_gui_internet_facing": (
        ("internet-facing", "internet facing", "external interface",
         "wan interface", "disable gui on", "gui on internet",
         "internet exposed", "publicly accessible"),
        _check_disable_gui_internet_facing,
    ),
    "configure_trusted_hosts": (
        ("trusted host", "trusthost", "restrict management access",
         "limit management access", "management access restriction",
         "allowed management ip"),
        _check_trusted_hosts,
    ),
}


def match_workaround_pattern(workaround_text: str) -> str | None:
    text = (workaround_text or "").lower()
    for key, (substrings, _fn) in WORKAROUND_REGISTRY.items():
        if any(s in text for s in substrings):
            return key
    return None


def check_workaround(pattern_key: str, client: Any, adom: str, device: str) -> str:
    entry = WORKAROUND_REGISTRY.get(pattern_key)
    if entry is None:
        return "manual_verification_required"
    _substrings, check_fn = entry
    return check_fn(client, adom, device)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_workaround_checks.py -v`
Expected: PASS (14 tests)

- [ ] **Step 5: Commit**

```bash
git add app/psirt/workaround_checks.py tests/test_psirt_workaround_checks.py
git commit -m "Add PSIRT workaround_checks module with real trusted-hosts check"
```

---

### Task 6: `engine.py` — `assess()` with ADOM scope

**Files:**
- Create: `app/psirt/engine.py`
- Test: `tests/test_psirt_engine.py`

**Interfaces:**
- Consumes: `app.psirt.models.{Advisory, AffectedRange, DeviceFinding, PsirtAssessment}`, `app.psirt.enrich.enrich_advisory`, `app.psirt.scoring.compute_priority`, `app.psirt.version_match.{version_in_range, VersionMatchError}`, `app.psirt.workaround_checks.{check_workaround, match_workaround_pattern}`
- Produces: `assess(advisory: Advisory, fmg_client: Any, adom_scope: str, http_client: Any, kev_url: str, enrichment_enabled: bool = True, fetch_timeout: float = 5.0) -> PsirtAssessment`. `adom_scope` is either one ADOM name or the literal `"*"` — when `"*"`, the caller (the route, Task 11) is responsible for passing only ADOMs the requesting user may access; `engine.py` itself has no user/session concept. `fetch_timeout` forwards to `enrich_advisory()` — the route passes `Config.PSIRT_FETCH_TIMEOUT`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_psirt_engine.py
"""End-to-end tests for psirt.engine.assess() against a fake FMGClient."""
from unittest.mock import MagicMock

from app.psirt.engine import assess
from app.psirt.models import Advisory, AffectedRange


def _fake_http_client():
    client = MagicMock()
    resp = MagicMock()
    resp.status_code = 404  # advisory page not found — degrade gracefully
    resp.json.return_value = {"vulnerabilities": []}
    resp.text = ""
    client.get.return_value = resp
    return client


def _make_advisory(**overrides):
    defaults = dict(
        advisory_id="FG-IR-24-001",
        cve_ids=["CVE-2024-12345"],
        cvss_score=8.1,
        affected_ranges=[AffectedRange(product="FortiOS", min_version="", max_version="7.4.4",
                                        fixed_version="7.4.5")],
        workaround_text="",
        exploited_in_wild_text="",
    )
    defaults.update(overrides)
    return Advisory(**defaults)


def test_assess_single_adom_no_workaround_upgrade_required():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"},
    ]
    advisory = _make_advisory()
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.device == "FW01"
    assert f.current_version == "7.4.2"
    assert f.in_range is True
    assert f.verdict == "upgrade_required"
    assert result.priority == "high"  # CVSS 8.1 band


def test_assess_out_of_range_device_no_action():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW02", "os_ver": "7.0", "mr": "6", "patch": "1"},  # 7.6.1, out of range
    ]
    advisory = _make_advisory()
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert result.findings[0].verdict == "no_action"
    assert result.priority == "informational"


def test_assess_workaround_in_place_no_action():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"},
    ]
    fmg.get_device_interfaces_all_vdoms.return_value = [
        {"name": "port1", "allowaccess": "ping"},
    ]
    advisory = _make_advisory(workaround_text="Disable HTTP/HTTPS admin access")
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    f = result.findings[0]
    assert f.workaround_status == "in_place"
    assert f.verdict == "no_action"


def test_assess_unrecognized_workaround_text_is_manual_verification():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"},
    ]
    advisory = _make_advisory(workaround_text="Contact Fortinet support for a hotfix")
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    f = result.findings[0]
    assert f.workaround_status == "manual_verification_required"
    assert f.verdict == "config_change_required"


def test_assess_scans_all_adoms_when_scope_is_star():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}, {"name": "Branch"}]

    def _devices(adom):
        return [{"name": f"FW-{adom}", "os_ver": "7.0", "mr": "4", "patch": "2"}]
    fmg.get_devices.side_effect = _devices

    advisory = _make_advisory()
    result = assess(advisory, fmg, "*", _fake_http_client(), "", enrichment_enabled=True)
    devices_seen = {f.device for f in result.findings}
    assert devices_seen == {"FW-Corp", "FW-Branch"}


def test_assess_missing_firmware_is_unknown_needs_manual_check():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [{"name": "FW01"}]  # no os_ver/mr/patch
    advisory = _make_advisory()
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert result.findings[0].verdict == "unknown_needs_manual_check"


def test_assess_device_list_failure_is_degraded():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.side_effect = Exception("FMG unreachable")
    advisory = _make_advisory()
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert result.degraded is True
    assert result.findings == []
    assert result.priority == "unknown"


def test_assess_fortimanager_product_evaluated():
    fmg = MagicMock()
    fmg.get_system_status.return_value = {"Version": "v7.4.5,build2360,240702 (GA)"}
    fmg.get_adoms.return_value = []
    advisory = _make_advisory(affected_ranges=[
        AffectedRange(product="FortiManager", max_version="7.4.4", fixed_version="7.4.5"),
    ])
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert len(result.findings) == 1
    assert result.findings[0].product == "FortiManager"
    assert result.findings[0].current_version == "7.4.5"
    assert result.findings[0].verdict == "no_action"  # 7.4.5 is the fixed version, out of range


def test_assess_out_of_scope_product_listed():
    fmg = MagicMock()
    fmg.get_adoms.return_value = []
    advisory = _make_advisory(affected_ranges=[
        AffectedRange(product="FortiSwitch", max_version="7.0.0"),
    ])
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert result.out_of_scope_products == ["FortiSwitch"]
    assert result.findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_engine.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.psirt.engine'`

- [ ] **Step 3: Write the implementation**

```python
# app/psirt/engine.py
"""
The PSIRT assessment engine: given a structured Advisory, determines the
verdict for every FortiGate + the FortiManager itself. This is the
deterministic core other packages call — it never asks an LLM anything.

adom_scope is either one ADOM name or the literal "*" for every ADOM
fmg_client.get_adoms() returns. Access-control filtering of which ADOMs a
"*" scan may touch is the caller's responsibility (app/routes/psirt_routes.py)
— this module has no session/user concept.

Fleet scan strategy: for each ADOM in scope, list every device, evaluate
FortiOS findings for each device plus one FortiManager-itself finding (if
the advisory names FortiManager as a product). A per-ADOM device-list
failure degrades the assessment (those devices become
unknown_needs_manual_check via the degraded flag) rather than being
silently skipped.
"""

from __future__ import annotations

import re
from typing import Any

from app.psirt.enrich import enrich_advisory
from app.psirt.models import Advisory, DeviceFinding, PsirtAssessment
from app.psirt.scoring import compute_priority
from app.psirt.version_match import VersionMatchError, version_in_range
from app.psirt.workaround_checks import check_workaround, match_workaround_pattern

_SUPPORTED_PRODUCTS = {"fortios", "fortigate", "fortimanager"}
_VERSION_EXTRACT = re.compile(r"\d+\.\d+\.\d+")


def _fmg_version(raw: str) -> str:
    """Extract a clean X.Y.Z version from a FortiManager get_system_status() Version string.

    FortiManager returns strings like "v7.4.5,build2360,240702 (GA)". Strip
    the leading 'v', take the first X.Y.Z component found. "" if not found.
    """
    m = _VERSION_EXTRACT.search(raw)
    return m.group(0) if m else ""


def _device_firmware(device: dict) -> str:
    # FortiManager stores versions across three fields:
    #   os_ver  — major version, sometimes "7.0" where ".0" is a legacy
    #             branch suffix, NOT the minor release. Take the leading int.
    #   mr      — the actual minor/feature release (e.g. 4 for FortiOS 7.4.x)
    #   patch   — patch level; -1 means no specific patch is tracked (unknown)
    os_ver_raw = str(device.get("os_ver", "")).strip()
    major_str = os_ver_raw.split(".")[0] if os_ver_raw else ""
    mr_str = str(device.get("mr", "")).strip()
    patch_str = str(device.get("patch", "")).strip()
    if not major_str or not mr_str or not patch_str:
        return ""
    try:
        major, mr, patch = int(major_str), int(mr_str), int(patch_str)
    except ValueError:
        return ""
    if patch < 0:
        return ""
    return f"{major}.{mr}.{patch}"


def _evaluate_device(
    advisory: Advisory,
    ranges: list,
    device_name: str,
    adom: str,
    product_label: str,
    firmware: str,
    fmg_client: Any,
) -> DeviceFinding:
    if not firmware:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version="", in_range=False,
            workaround_status="not_applicable", verdict="unknown_needs_manual_check",
            reason="No firmware version reported by FortiManager for this device.",
        )

    in_range = False
    matched_range = None
    try:
        for rng in ranges:
            if version_in_range(firmware, rng):
                in_range = True
                matched_range = rng
                break
    except VersionMatchError as exc:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=False,
            workaround_status="not_applicable", verdict="unknown_needs_manual_check",
            reason=f"Could not compare firmware version: {exc}",
        )

    if not in_range:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=False,
            workaround_status="not_applicable", verdict="no_action",
            reason=f"Firmware {firmware} is outside the advisory's affected range(s).",
        )

    pattern_key = match_workaround_pattern(advisory.workaround_text)
    if pattern_key is None:
        if advisory.workaround_text.strip():
            return DeviceFinding(
                device=device_name, adom=adom, product=product_label,
                current_version=firmware, in_range=True,
                workaround_status="manual_verification_required",
                verdict="config_change_required",
                reason=(
                    f"Firmware {firmware} is affected. A workaround is published "
                    f"but not automatically verifiable: {advisory.workaround_text!r}. "
                    "Manually confirm it's applied, or upgrade to "
                    f"{matched_range.fixed_version or 'the fixed version'}."
                ),
            )
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="not_applicable", verdict="upgrade_required",
            reason=(
                f"Firmware {firmware} is affected and no workaround is published. "
                f"Upgrade to {matched_range.fixed_version or 'the fixed version'}."
            ),
        )

    try:
        status = check_workaround(pattern_key, fmg_client, adom, device_name)
    except Exception as exc:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="manual_verification_required",
            verdict="config_change_required",
            reason=f"Firmware {firmware} is affected. Workaround check failed: {exc}. Manual verification required.",
        )
    if status == "in_place":
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="in_place", verdict="no_action",
            reason=(
                f"Firmware {firmware} is affected, but the workaround is already "
                f"in place: {advisory.workaround_text}"
            ),
        )
    elif status == "not_in_place":
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="not_in_place",
            verdict="config_change_required",
            reason=(
                f"Firmware {firmware} is affected and the workaround is NOT in place: "
                f"{advisory.workaround_text}"
            ),
        )
    else:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="manual_verification_required",
            verdict="config_change_required",
            reason=(
                f"Firmware {firmware} is affected and the workaround status is unknown "
                f"(manual verification required): {advisory.workaround_text}"
            ),
        )


def assess(
    advisory: Advisory,
    fmg_client: Any,
    adom_scope: str,
    http_client: Any,
    kev_url: str,
    enrichment_enabled: bool = True,
    fetch_timeout: float = 5.0,
) -> PsirtAssessment:
    """Main entry point.

    adom_scope: a single ADOM name, or "*" to scan every ADOM
    fmg_client.get_adoms() returns (caller is responsible for pre-filtering
    which ADOMs "*" may include for the requesting user).
    fetch_timeout: seconds, forwarded to enrich_advisory()'s HTTP calls
    (Config.PSIRT_FETCH_TIMEOUT at the route layer).
    """
    advisory = enrich_advisory(
        advisory, http_client, kev_url,
        enrichment_enabled=enrichment_enabled, timeout=fetch_timeout,
    )
    kev_hit = getattr(advisory, "_kev_hit", False)

    out_of_scope = sorted({
        r.product for r in advisory.affected_ranges
        if r.product.strip().lower() not in _SUPPORTED_PRODUCTS
    })

    findings: list[DeviceFinding] = []
    warnings: list[str] = []
    degraded = advisory.enrichment_degraded

    fortios_ranges = [
        r for r in advisory.affected_ranges
        if r.product.strip().lower() in ("fortios", "fortigate")
    ]
    fmg_ranges = [
        r for r in advisory.affected_ranges
        if r.product.strip().lower() == "fortimanager"
    ]

    if fmg_ranges:
        try:
            status = fmg_client.get_system_status()
            fmg_version = _fmg_version(str(status.get("Version", "")))
            findings.append(_evaluate_device(
                advisory, fmg_ranges, "FortiManager (primary)", "-", "FortiManager",
                fmg_version, fmg_client,
            ))
        except Exception as exc:
            degraded = True
            warnings.append(f"Could not reach FortiManager (primary): {exc}")

    if fortios_ranges:
        if adom_scope == "*":
            try:
                adoms = [a.get("name", "") for a in fmg_client.get_adoms() if isinstance(a, dict)]
            except Exception as exc:
                degraded = True
                warnings.append(f"Could not list ADOMs: {exc}")
                adoms = []
        else:
            adoms = [adom_scope]

        for adom in adoms:
            try:
                devices = fmg_client.get_devices(adom)
            except Exception as exc:
                degraded = True
                warnings.append(f"Could not list devices in ADOM {adom!r}: {exc}")
                continue
            for d in devices:
                if not isinstance(d, dict):
                    continue
                name = d.get("name", "")
                firmware = _device_firmware(d)
                findings.append(_evaluate_device(
                    advisory, fortios_ranges, name, adom, "FortiOS", firmware, fmg_client,
                ))

    any_in_range = any(f.in_range for f in findings)

    if degraded and not findings:
        return PsirtAssessment(
            advisory=advisory,
            findings=findings,
            out_of_scope_products=out_of_scope,
            priority="unknown",
            priority_rationale=(
                "Fleet assessment is degraded and no devices could be checked. "
                "Manual verification required."
            ),
            kev_hit=kev_hit,
            degraded=degraded,
            warnings=warnings,
        )

    priority, rationale = compute_priority(
        cvss_score=advisory.cvss_score,
        fortinet_severity=advisory.fortinet_severity,
        exploited_in_wild_text=advisory.exploited_in_wild_text,
        kev_hit=kev_hit,
        any_device_in_range=any_in_range,
    )

    return PsirtAssessment(
        advisory=advisory,
        findings=findings,
        out_of_scope_products=out_of_scope,
        priority=priority,
        priority_rationale=rationale,
        kev_hit=kev_hit,
        degraded=degraded,
        warnings=warnings,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_engine.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add app/psirt/engine.py tests/test_psirt_engine.py
git commit -m "Add PSIRT engine.assess() with ADOM-scope support"
```

---

### Task 7: `LLMProvider.extract_json()` — structured extraction capability

**Files:**
- Modify: `app/llm/base.py`
- Test: `tests/test_llm_extract_json.py`

**Interfaces:**
- Produces: `LLMProvider.extract_json(system_prompt: str, user_prompt: str) -> dict` (concrete method on the existing `LLMProvider` ABC — no changes needed to `claude_provider.py`/`codex_provider.py`/`ollama_provider.py`, since it's implemented once in terms of the existing abstract `narrate()`). Raises `LLMError` if `narrate()` fails, the response isn't valid JSON, or the parsed JSON isn't an object.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_extract_json.py
"""Tests for LLMProvider.extract_json() — structured JSON extraction on top of narrate()."""
import pytest
from app.llm.base import LLMError, LLMProvider


class _FakeProvider(LLMProvider):
    def __init__(self, response: str):
        self._response = response

    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        return self._response


def test_extract_json_parses_plain_json():
    provider = _FakeProvider('{"advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"]}')
    result = provider.extract_json("system", "user")
    assert result == {"advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"]}


def test_extract_json_strips_markdown_fences():
    provider = _FakeProvider('```json\n{"advisory_id": "FG-IR-24-001"}\n```')
    result = provider.extract_json("system", "user")
    assert result == {"advisory_id": "FG-IR-24-001"}


def test_extract_json_strips_bare_fences_no_language_tag():
    provider = _FakeProvider('```\n{"advisory_id": "FG-IR-24-001"}\n```')
    result = provider.extract_json("system", "user")
    assert result == {"advisory_id": "FG-IR-24-001"}


def test_extract_json_malformed_raises_llm_error():
    provider = _FakeProvider("this is not json at all")
    with pytest.raises(LLMError):
        provider.extract_json("system", "user")


def test_extract_json_non_object_json_raises():
    provider = _FakeProvider('["just", "a", "list"]')
    with pytest.raises(LLMError):
        provider.extract_json("system", "user")


def test_extract_json_narrate_failure_propagates():
    class _FailingProvider(LLMProvider):
        def narrate(self, system_prompt: str, user_prompt: str) -> str:
            raise LLMError("API call failed")

    with pytest.raises(LLMError):
        _FailingProvider().extract_json("system", "user")


def test_extract_json_appends_json_only_instruction_to_system_prompt():
    """The system prompt narrate() receives must instruct JSON-only output."""
    captured = {}

    class _CapturingProvider(LLMProvider):
        def narrate(self, system_prompt: str, user_prompt: str) -> str:
            captured["system_prompt"] = system_prompt
            return "{}"

    _CapturingProvider().extract_json("Extract PSIRT fields.", "email text")
    assert "Extract PSIRT fields." in captured["system_prompt"]
    assert "json" in captured["system_prompt"].lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_llm_extract_json.py -v`
Expected: FAIL with `AttributeError: 'LLMProvider' object has no attribute 'extract_json'` (or similar — the concrete subclasses in the test define only `narrate`, so `extract_json` doesn't exist yet)

- [ ] **Step 3: Write the implementation**

```python
# app/llm/base.py
"""Provider-agnostic interface every LLM narration backend implements."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod


class LLMError(Exception):
    """Raised when a provider is misconfigured or a completion call fails."""


class LLMProvider(ABC):
    @abstractmethod
    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        """Return the model's text completion for one single-shot prompt.

        Raises LLMError on any failure (missing key, network error, non-2xx
        response) — callers must catch this and degrade gracefully rather
        than let it propagate to the user as a raw exception.
        """

    def extract_json(self, system_prompt: str, user_prompt: str) -> dict:
        """Call narrate() with a JSON-only instruction and parse the result.

        Used for structured extraction (e.g. pulling PSIRT advisory fields
        out of a pasted email) — narrate() itself stays free-text-in/out for
        every other caller. Raises LLMError if narrate() fails, the response
        isn't valid JSON, or the parsed value isn't a JSON object. Never
        returns a partially-guessed dict.
        """
        strict_system_prompt = (
            system_prompt
            + "\n\nRespond with ONLY a single valid JSON object — no prose, "
              "no markdown code fences, no explanation before or after."
        )
        raw = self.narrate(strict_system_prompt, user_prompt)
        text = raw.strip()
        if text.startswith("```"):
            text = text[3:]
            if text.lower().startswith("json"):
                text = text[4:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError(f"model did not return valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise LLMError("model's JSON response was not a JSON object")
        return parsed
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_llm_extract_json.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add app/llm/base.py tests/test_llm_extract_json.py
git commit -m "Add LLMProvider.extract_json() structured-extraction capability"
```

---

### Task 8: `app/psirt/extract.py` — advisory extraction prompt + validation

**Files:**
- Create: `app/psirt/extract.py`
- Test: `tests/test_psirt_extract.py`

**Interfaces:**
- Consumes: `app.llm.LLMProvider.extract_json()` (Task 7), `app.psirt.models.{Advisory, AffectedRange}` (Task 1)
- Produces: `class ExtractionError(Exception)` (carries `.field` and `.detail`), `extract_advisory(raw_text: str, provider: LLMProvider) -> Advisory` — calls the LLM, validates required fields (mirrors 4tanalyst's `parse_advisory` validation), raises `ExtractionError` naming the specific missing/malformed field.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_psirt_extract.py
"""Tests for app.psirt.extract — LLM-backed advisory field extraction + validation."""
import pytest
from app.llm.base import LLMError, LLMProvider
from app.psirt.extract import ExtractionError, extract_advisory


class _FakeProvider(LLMProvider):
    def __init__(self, response: dict):
        self._response = response

    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        import json
        return json.dumps(self._response)


_VALID_EXTRACTION = {
    "advisory_id": "FG-IR-24-001",
    "advisory_url": "https://fortiguard.com/psirt/FG-IR-24-001",
    "cve_ids": ["CVE-2024-12345"],
    "published_date": "2024-01-15",
    "fortinet_severity": "High",
    "cvss_score": 8.1,
    "description": "A vulnerability in FortiOS allows...",
    "affected_ranges": [
        {"product": "FortiOS", "min_version": "", "max_version": "7.4.4",
         "fixed_version": "7.4.5", "notes": ""},
    ],
    "workaround_text": "Disable HTTP/HTTPS admin access",
    "exploited_in_wild_text": "",
}


def test_extract_advisory_happy_path():
    provider = _FakeProvider(_VALID_EXTRACTION)
    advisory = extract_advisory("raw email text here", provider)
    assert advisory.advisory_id == "FG-IR-24-001"
    assert advisory.cve_ids == ["CVE-2024-12345"]
    assert len(advisory.affected_ranges) == 1
    assert advisory.affected_ranges[0].product == "FortiOS"
    assert advisory.cvss_score == 8.1


def test_extract_advisory_missing_advisory_id_raises():
    data = dict(_VALID_EXTRACTION)
    data["advisory_id"] = ""
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "advisory_id"


def test_extract_advisory_invalid_advisory_id_characters_raises():
    data = dict(_VALID_EXTRACTION)
    data["advisory_id"] = "FG-IR-24-001; DROP TABLE"
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "advisory_id"


def test_extract_advisory_missing_cve_ids_raises():
    data = dict(_VALID_EXTRACTION)
    data["cve_ids"] = []
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "cve_ids"


def test_extract_advisory_malformed_cve_id_raises():
    data = dict(_VALID_EXTRACTION)
    data["cve_ids"] = ["not-a-cve"]
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "cve_ids"


def test_extract_advisory_missing_affected_ranges_raises():
    data = dict(_VALID_EXTRACTION)
    data["affected_ranges"] = []
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "affected_ranges"


def test_extract_advisory_affected_range_missing_product_raises():
    data = dict(_VALID_EXTRACTION)
    data["affected_ranges"] = [{"min_version": "", "max_version": "7.4.4"}]
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "affected_ranges"


def test_extract_advisory_llm_failure_propagates_as_extraction_error():
    class _FailingProvider(LLMProvider):
        def narrate(self, system_prompt: str, user_prompt: str) -> str:
            raise LLMError("API unreachable")

    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", _FailingProvider())
    assert exc_info.value.field == "llm"


def test_extract_advisory_optional_fields_default_when_absent():
    minimal = {
        "advisory_id": "FG-IR-24-002",
        "cve_ids": ["CVE-2024-99999"],
        "affected_ranges": [{"product": "FortiOS", "max_version": "7.2.0"}],
    }
    provider = _FakeProvider(minimal)
    advisory = extract_advisory("raw email text", provider)
    assert advisory.workaround_text == ""
    assert advisory.exploited_in_wild_text == ""
    assert advisory.cvss_score is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_extract.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.psirt.extract'`

- [ ] **Step 3: Write the implementation**

```python
# app/psirt/extract.py
"""
LLM-backed extraction of structured Advisory fields from a raw PSIRT
advisory email/text.

This is the one point in the PSIRT feature where an LLM is involved — it
only extracts; it never computes a verdict, version match, or score.
Mirrors the validation 4tanalyst's parse_advisory tool performs (CVE ID
regex, non-empty affected_ranges, advisory_id character whitelist), since
there's no conversational back-and-forth to ask the user for a missing
field here — invalid extraction surfaces as a specific field name the
caller (the route) turns into a targeted UI error instead.
"""

from __future__ import annotations

import re

from app.llm.base import LLMError, LLMProvider
from app.psirt.models import Advisory, AffectedRange

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ADVISORY_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

_SYSTEM_PROMPT = """You are extracting structured fields from a Fortinet PSIRT
security advisory email. Read the provided text and return a JSON object
with these keys:

- advisory_id (string, required): Fortinet's advisory ID, e.g. "FG-IR-24-001"
- advisory_url (string, optional): link to the fortiguard.com advisory page
- cve_ids (array of strings, required): CVE identifiers, format "CVE-YYYY-NNNN"
- published_date (string, optional): the advisory's published date
- fortinet_severity (string, optional): "Critical", "High", "Medium", or "Low"
- cvss_score (number or null, optional): the CVSS base score if stated
- description (string, optional): one-line summary of the vulnerability
- affected_ranges (array of objects, required, at least one entry): each with
  "product" (required — use "FortiOS" or "FortiManager" for anything you want
  matched against a fleet; use the exact product name from the email for
  anything else), "min_version" (empty string for an open-ended lower bound),
  "max_version" (empty string for an open-ended upper bound), "fixed_version",
  "notes"
- workaround_text (string, optional): the vendor's workaround/mitigation text, verbatim
- exploited_in_wild_text (string, optional): Fortinet's own exploitation
  language, verbatim (empty string if the advisory doesn't mention it)

Do not guess at a value you cannot find in the text — omit the key or use
an empty string/null instead."""


class ExtractionError(Exception):
    """A required field was missing/malformed, or the LLM call itself failed."""

    def __init__(self, field: str, detail: str):
        self.field = field
        self.detail = detail
        super().__init__(f"[{field}] {detail}")


def extract_advisory(raw_text: str, provider: LLMProvider) -> Advisory:
    try:
        extracted = provider.extract_json(_SYSTEM_PROMPT, raw_text)
    except LLMError as exc:
        raise ExtractionError("llm", str(exc)) from exc

    advisory_id = str(extracted.get("advisory_id", "")).strip()
    if not advisory_id:
        raise ExtractionError("advisory_id", "advisory_id is required")
    if not _ADVISORY_ID_RE.match(advisory_id):
        raise ExtractionError(
            "advisory_id",
            f"advisory_id contains invalid characters: {advisory_id!r} (allowed: A-Z a-z 0-9 . _ -)",
        )

    cve_ids = extracted.get("cve_ids", [])
    if not isinstance(cve_ids, list) or not cve_ids:
        raise ExtractionError("cve_ids", "cve_ids must be a non-empty list")
    for cve in cve_ids:
        if not _CVE_RE.match(str(cve)):
            raise ExtractionError("cve_ids", f"malformed CVE id: {cve!r} (expected CVE-YYYY-NNNN)")

    raw_ranges = extracted.get("affected_ranges", [])
    if not isinstance(raw_ranges, list) or not raw_ranges:
        raise ExtractionError("affected_ranges", "affected_ranges must be a non-empty list")
    ranges: list[AffectedRange] = []
    for r in raw_ranges:
        if not isinstance(r, dict) or not r.get("product"):
            raise ExtractionError(
                "affected_ranges", f"malformed affected_ranges entry: {r!r} (product is required)",
            )
        ranges.append(AffectedRange(
            product=str(r.get("product", "")),
            min_version=str(r.get("min_version", "") or ""),
            max_version=str(r.get("max_version", "") or ""),
            fixed_version=str(r.get("fixed_version", "") or ""),
            notes=str(r.get("notes", "") or ""),
        ))

    cvss_raw = extracted.get("cvss_score")
    cvss_score = float(cvss_raw) if isinstance(cvss_raw, (int, float)) else None

    return Advisory(
        advisory_id=advisory_id,
        advisory_url=str(extracted.get("advisory_url", "") or ""),
        cve_ids=[str(c) for c in cve_ids],
        published_date=str(extracted.get("published_date", "") or ""),
        fortinet_severity=str(extracted.get("fortinet_severity", "") or ""),
        cvss_score=cvss_score,
        description=str(extracted.get("description", "") or ""),
        affected_ranges=ranges,
        workaround_text=str(extracted.get("workaround_text", "") or ""),
        exploited_in_wild_text=str(extracted.get("exploited_in_wild_text", "") or ""),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_extract.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add app/psirt/extract.py tests/test_psirt_extract.py
git commit -m "Add PSIRT LLM extraction + validation module"
```

---

### Task 9: Configuration — `.env.example`, `app/config.py`

**Files:**
- Modify: `.env.example`
- Modify: `app/config.py`

**Interfaces:**
- Produces: `Config.PSIRT_ENRICHMENT_ENABLED: bool`, `Config.PSIRT_KEV_URL: str`, `Config.PSIRT_FETCH_TIMEOUT: int`

No test for this task — it's config wiring with no branching logic to unit test in isolation; the enrichment on/off behavior is already covered by `test_psirt_enrich.py` (Task 4), which tests the `enrichment_enabled` parameter directly. This task is verified by import (Step 2 below).

- [ ] **Step 1: Add the new variables to `.env.example`**

Add after the `# ── Reverse proxy ─────` block at the end of `.env.example`:

```
# ── PSIRT Advisory Assessment (Device Review tab) ─────────────────────────────
# Best-effort enrichment against fortiguard.com and the CISA KEV feed.
# Set to false for air-gapped/restricted deployments — the assessment still
# runs on email-derived data alone, just without corroboration.

PSIRT_ENRICHMENT_ENABLED=true
PSIRT_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
PSIRT_FETCH_TIMEOUT=5
```

- [ ] **Step 2: Add the corresponding Config fields**

In `app/config.py`, add after the `# ── AI Assist (Rule Validation) ───` block (find the existing `AI_PROVIDER`/`ANTHROPIC_API_KEY` lines and add immediately after them):

```python
    # PSIRT Advisory Assessment enrichment (fortiguard.com + CISA KEV feed)
    PSIRT_ENRICHMENT_ENABLED = os.environ.get("PSIRT_ENRICHMENT_ENABLED", "true").lower() == "true"
    PSIRT_KEV_URL = os.environ.get(
        "PSIRT_KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    PSIRT_FETCH_TIMEOUT = int(os.environ.get("PSIRT_FETCH_TIMEOUT", "5"))
```

Run: `uv run python -c "from app.config import Config; print(Config.PSIRT_ENRICHMENT_ENABLED, Config.PSIRT_KEV_URL, Config.PSIRT_FETCH_TIMEOUT)"`
Expected: prints `True https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json 5` with no error

- [ ] **Step 3: Commit**

```bash
git add .env.example app/config.py
git commit -m "Add PSIRT enrichment configuration"
```

---

### Task 10: `app/psirt/render.py` + `psirt_report.html` — HTML report

**Files:**
- Create: `app/psirt/render.py`
- Create: `app/templates/psirt_report.html`
- Test: `tests/test_psirt_render.py`

**Interfaces:**
- Consumes: `app.psirt.models.PsirtAssessment.to_dict()` shape (Task 1)
- Produces: `render_psirt_html(assessment_dict: dict) -> str` — renders `app/templates/psirt_report.html` via Flask's `render_template_string`/Jinja2 environment, self-contained (inline `<style>`, no external assets), returns the full HTML document as a string.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_psirt_render.py
"""Tests for PSIRT HTML report rendering."""
from app.psirt.models import Advisory, AffectedRange, DeviceFinding, PsirtAssessment
from app.psirt.render import render_psirt_html


def _sample_assessment():
    advisory = Advisory(
        advisory_id="FG-IR-24-001",
        advisory_url="https://fortiguard.com/psirt/FG-IR-24-001",
        cve_ids=["CVE-2024-12345"],
        fortinet_severity="High",
        cvss_score=8.1,
        description="A vulnerability in FortiOS allows remote code execution.",
        affected_ranges=[AffectedRange(product="FortiOS", max_version="7.4.4", fixed_version="7.4.5")],
        exploited_in_wild_text="actively exploited in the wild",
    )
    findings = [
        DeviceFinding(device="FW01", adom="Corp", product="FortiOS", current_version="7.4.2",
                      in_range=True, workaround_status="not_applicable",
                      verdict="upgrade_required", reason="Firmware 7.4.2 is affected."),
        DeviceFinding(device="FW02", adom="Corp", product="FortiOS", current_version="7.6.1",
                      in_range=False, workaround_status="not_applicable",
                      verdict="no_action", reason="Out of affected range."),
    ]
    return PsirtAssessment(
        advisory=advisory, findings=findings, out_of_scope_products=["FortiSwitch"],
        priority="critical", priority_rationale="CVSS 8.1; forced to at least High because exploited",
        kev_hit=True, degraded=False, warnings=[],
    )


def test_render_includes_advisory_id_and_cve():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert "FG-IR-24-001" in html
    assert "CVE-2024-12345" in html


def test_render_includes_priority_and_kev_badge():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert "critical" in html.lower()
    assert "kev" in html.lower()


def test_render_includes_all_device_findings():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert "FW01" in html
    assert "FW02" in html
    assert "upgrade_required" in html.lower() or "upgrade required" in html.lower()


def test_render_includes_out_of_scope_products():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert "FortiSwitch" in html


def test_render_includes_warnings_when_present():
    data = _sample_assessment().to_dict()
    data["warnings"] = ["Could not reach FortiManager (primary): timeout"]
    html = render_psirt_html(data)
    assert "Could not reach FortiManager" in html


def test_render_escapes_html_in_reason_field():
    """User/advisory-derived text must be escaped — no injection into the report."""
    data = _sample_assessment().to_dict()
    data["findings"][0]["reason"] = "<script>alert(1)</script>"
    html = render_psirt_html(data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_is_self_contained_document():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert html.strip().startswith("<!DOCTYPE html>")
    assert "<style>" in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_render.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.psirt.render'`

- [ ] **Step 3: Write the template**

Create `app/templates/psirt_report.html` (standalone document — NOT extending `base.html`, since this is a downloadable/printable artifact like other exports in this repo, not a page in the app shell):

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>PSIRT Assessment — {{ advisory.advisory_id }}</title>
<style>
  body { font-family: -apple-system, sans-serif; font-size: 13px; color: #1a2133; margin: 2cm; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  h2 { font-size: 15px; margin-top: 1.5rem; border-bottom: 1px solid #d0d7e2; padding-bottom: 4px; }
  .meta { font-size: 11px; color: #5a6478; margin-bottom: 16px; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 11px; font-weight: 600; color: #fff; }
  .priority-critical { background: #b91c1c; }
  .priority-high { background: #ea580c; }
  .priority-medium { background: #ca8a04; }
  .priority-low { background: #16a34a; }
  .priority-informational { background: #6b7280; }
  .priority-unknown { background: #6b7280; }
  .verdict-no_action { background: #16a34a; }
  .verdict-config_change_required { background: #ca8a04; }
  .verdict-upgrade_required { background: #b91c1c; }
  .verdict-unknown_needs_manual_check { background: #6b7280; }
  .kev-badge { background: #7c2d12; }
  table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
  th { background: #eef1f5; text-align: left; padding: 6px 8px; font-size: 11px; text-transform: uppercase; border-bottom: 2px solid #d0d7e2; }
  td { padding: 5px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  .warnings { background: #fef3c7; border-left: 3px solid #ca8a04; padding: .6rem 1rem; margin: 1rem 0; }
  .out-of-scope { background: #f3f4f6; padding: .6rem 1rem; border-radius: 4px; }
  @media print { body { margin: 1cm; } }
</style>
</head>
<body>

<h1>PSIRT Advisory Assessment</h1>
<div class="meta">Generated {{ generated_at }}</div>

{% if warnings %}
<div class="warnings">
  <strong>Warnings — some devices may not have been fully checked:</strong>
  <ul>{% for w in warnings %}<li>{{ w }}</li>{% endfor %}</ul>
</div>
{% endif %}

<h2>Advisory Summary</h2>
<table>
  <tr><th style="width:180px">Advisory ID</th><td>{{ advisory.advisory_id }}{% if advisory.advisory_url %} — <a href="{{ advisory.advisory_url }}">{{ advisory.advisory_url }}</a>{% endif %}</td></tr>
  <tr><th>CVE ID(s)</th><td>{{ advisory.cve_ids | join(', ') }}</td></tr>
  <tr><th>Published</th><td>{{ advisory.published_date or '—' }}</td></tr>
  <tr><th>Fortinet Severity</th><td>{{ advisory.fortinet_severity or '—' }}</td></tr>
  <tr><th>CVSS Score</th><td>{{ advisory.cvss_score if advisory.cvss_score is not none else '—' }}</td></tr>
  <tr><th>Description</th><td>{{ advisory.description or '—' }}</td></tr>
  {% if advisory.enrichment_degraded %}<tr><th>Enrichment</th><td>Email-only — external corroboration unavailable or disabled.</td></tr>{% endif %}
</table>

<h2>Exploitation Signal &amp; Priority</h2>
<p>
  <span class="badge priority-{{ priority }}">{{ priority | upper }}</span>
  {% if kev_hit %}<span class="badge kev-badge">KEV-LISTED</span>{% endif %}
</p>
<p>{{ priority_rationale }}</p>
{% if advisory.exploited_in_wild_text %}<p><em>Fortinet's own wording:</em> {{ advisory.exploited_in_wild_text }}</p>{% endif %}

<h2>Fleet Exposure</h2>
<table>
  <thead><tr><th>Device</th><th>ADOM</th><th>Product</th><th>Current Version</th><th>In Range</th><th>Verdict</th></tr></thead>
  <tbody>
  {% for f in findings %}
    <tr>
      <td>{{ f.device }}</td>
      <td>{{ f.adom }}</td>
      <td>{{ f.product }}</td>
      <td>{{ f.current_version or '—' }}</td>
      <td>{{ 'Yes' if f.in_range else 'No' }}</td>
      <td><span class="badge verdict-{{ f.verdict }}">{{ f.verdict | replace('_', ' ') }}</span></td>
    </tr>
  {% endfor %}
  </tbody>
</table>

<h2>Per-Device Detail</h2>
<table>
  <thead><tr><th>Device</th><th>Workaround Status</th><th>Reason</th></tr></thead>
  <tbody>
  {% for f in findings %}
    <tr>
      <td>{{ f.device }}</td>
      <td>{{ f.workaround_status | replace('_', ' ') }}</td>
      <td>{{ f.reason }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>

{% if out_of_scope_products %}
<h2>Out of Scope Products</h2>
<div class="out-of-scope">Mentioned in the advisory but not matched by this tool — review manually: {{ out_of_scope_products | join(', ') }}</div>
{% endif %}

</body>
</html>
```

- [ ] **Step 4: Write `app/psirt/render.py`**

```python
# app/psirt/render.py
"""Render a PsirtAssessment as a self-contained HTML report.

Pure deterministic templating — no LLM involved. Jinja2 autoescaping
(Flask's default) handles HTML-escaping every advisory/finding field, so
values that end up in the report (which may originate from a pasted email)
can never inject markup into the page.
"""

from __future__ import annotations

import datetime

from flask import render_template


def render_psirt_html(assessment: dict) -> str:
    return render_template(
        "psirt_report.html",
        advisory=assessment["advisory"],
        findings=assessment["findings"],
        out_of_scope_products=assessment["out_of_scope_products"],
        priority=assessment["priority"],
        priority_rationale=assessment["priority_rationale"],
        kev_hit=assessment["kev_hit"],
        warnings=assessment["warnings"],
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
```

Note: `render_template` requires a Flask application/request context. The test in Step 1 must run inside one — update it to wrap calls in an app context:

- [ ] **Step 5: Update the test file to provide a Flask app context**

Replace the top of `tests/test_psirt_render.py` (before the test functions) with:

```python
"""Tests for PSIRT HTML report rendering."""
import os
import pytest

from app.psirt.models import Advisory, AffectedRange, DeviceFinding, PsirtAssessment


@pytest.fixture(autouse=True)
def _app_context():
    os.environ.setdefault("SECRET_KEY", "test-secret")
    os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")
    from app import create_app
    app = create_app()
    with app.app_context():
        yield


from app.psirt.render import render_psirt_html  # noqa: E402  (import after env vars set)
```

(Keep the rest of the file — `_sample_assessment()` and all `test_*` functions — unchanged below this.)

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_render.py -v`
Expected: PASS (7 tests)

- [ ] **Step 7: Commit**

```bash
git add app/psirt/render.py app/templates/psirt_report.html tests/test_psirt_render.py
git commit -m "Add PSIRT HTML report template and renderer"
```

---

### Task 11: `app/routes/psirt_routes.py` — extract + assess routes

**Files:**
- Create: `app/routes/psirt_routes.py`
- Modify: `app/__init__.py`
- Test: `tests/test_psirt_routes.py`

**Interfaces:**
- Consumes: `app.psirt.extract.{extract_advisory, ExtractionError}` (Task 8), `app.psirt.engine.assess` (Task 6), `app.psirt.render.render_psirt_html` (Task 10), `app.psirt.models.{Advisory, AffectedRange}` (Task 1), `app.llm.get_provider`, `app.app_settings.get_setting`, `app.fmg_helpers.make_client`, `app.decorators.{check_adom_access, tab_required}`, `app.groups.get_allowed_adoms`, `app.fmg_client.FMGError`, `app.security.{internal_api_error, upstream_api_error}`, `app.config.Config`
- Produces: `bp = Blueprint("psirt", __name__)` with routes `GET /api/device-review/psirt/extract-status`, `POST /api/device-review/psirt/extract`, `POST /api/device-review/psirt/assess/device`, `POST /api/device-review/psirt/assess`, `POST /api/device-review/psirt/report`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_psirt_routes.py
"""Tests for PSIRT extract/assess/report routes."""
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def app():
    os.environ.setdefault("SECRET_KEY", "test-secret")
    os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")
    from app import create_app
    return create_app()


_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def client(app):
    with app.test_client() as c, \
         patch("app.auth._load_users", return_value=_TEST_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def _post(client, url, payload):
    return client.post(url, data=json.dumps(payload), content_type="application/json",
                        headers={"X-CSRFToken": "test-csrf"})


_VALID_EXTRACTION_JSON = json.dumps({
    "advisory_id": "FG-IR-24-001",
    "cve_ids": ["CVE-2024-12345"],
    "affected_ranges": [{"product": "FortiOS", "max_version": "7.4.4", "fixed_version": "7.4.5"}],
    "workaround_text": "",
})


def test_extract_status_reports_disabled_by_default(client):
    resp = client.get("/api/device-review/psirt/extract-status")
    assert resp.status_code == 200
    assert resp.get_json()["available"] is False


def test_extract_status_reports_enabled(client):
    with patch("app.routes.psirt_routes.get_setting", return_value=True):
        resp = client.get("/api/device-review/psirt/extract-status")
    assert resp.get_json()["available"] is True


def test_extract_returns_503_when_disabled(client):
    resp = _post(client, "/api/device-review/psirt/extract", {"email_text": "some advisory"})
    assert resp.status_code == 503


def test_extract_requires_email_text(client):
    with patch("app.routes.psirt_routes.get_setting", return_value=True):
        resp = _post(client, "/api/device-review/psirt/extract", {"email_text": ""})
    assert resp.status_code == 400


def test_extract_happy_path(client):
    fake_provider = MagicMock()
    fake_provider.narrate.return_value = _VALID_EXTRACTION_JSON
    with patch("app.routes.psirt_routes.get_setting", return_value=True), \
         patch("app.routes.psirt_routes.get_provider", return_value=fake_provider):
        resp = _post(client, "/api/device-review/psirt/extract", {"email_text": "PSIRT advisory text"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["advisory"]["advisory_id"] == "FG-IR-24-001"


def test_extract_malformed_llm_output_returns_422(client):
    fake_provider = MagicMock()
    fake_provider.narrate.return_value = '{"advisory_id": ""}'  # missing required fields
    with patch("app.routes.psirt_routes.get_setting", return_value=True), \
         patch("app.routes.psirt_routes.get_provider", return_value=fake_provider):
        resp = _post(client, "/api/device-review/psirt/extract", {"email_text": "garbled text"})
    assert resp.status_code == 422
    data = resp.get_json()
    assert data["field"] == "advisory_id"


def test_assess_device_requires_adom_and_device(client):
    resp = _post(client, "/api/device-review/psirt/assess/device", {"advisory": {}})
    assert resp.status_code == 400


def test_assess_device_happy_path(client):
    fake_fmg = MagicMock()
    fake_fmg.get_devices.return_value = [{"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"}]
    fake_fmg.get_adoms.return_value = [{"name": "Corp"}]
    cm = MagicMock()
    cm.__enter__.return_value = fake_fmg
    cm.__exit__.return_value = False
    advisory_payload = {
        "advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"],
        "affected_ranges": [{"product": "FortiOS", "max_version": "7.4.4", "fixed_version": "7.4.5"}],
        "workaround_text": "", "exploited_in_wild_text": "", "cvss_score": 8.1,
        "advisory_url": "", "published_date": "", "fortinet_severity": "", "description": "",
        "enrichment_degraded": False,
    }
    with patch("app.routes.psirt_routes.make_client", return_value=cm):
        resp = _post(client, "/api/device-review/psirt/assess/device",
                      {"adom": "Corp", "device": "FW01", "advisory": advisory_payload})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["finding"]["device"] == "FW01"
    assert data["finding"]["verdict"] == "upgrade_required"


def test_assess_device_checks_adom_access(client):
    with patch("app.decorators.user_can_access_adom", return_value=False):
        with client.session_transaction() as sess:
            sess["role"] = "viewer"
        resp = _post(client, "/api/device-review/psirt/assess/device",
                      {"adom": "Restricted", "device": "FW01", "advisory": {}})
    assert resp.status_code == 403


def test_report_returns_html(client):
    advisory_payload = {
        "advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"],
        "affected_ranges": [{"product": "FortiOS", "max_version": "7.4.4", "fixed_version": "7.4.5"}],
        "workaround_text": "", "exploited_in_wild_text": "", "cvss_score": 8.1,
        "advisory_url": "", "published_date": "", "fortinet_severity": "", "description": "",
        "enrichment_degraded": False,
    }
    assessment_payload = {
        "advisory": advisory_payload,
        "findings": [{"device": "FW01", "adom": "Corp", "product": "FortiOS",
                       "current_version": "7.4.2", "in_range": True,
                       "workaround_status": "not_applicable", "verdict": "upgrade_required",
                       "reason": "affected"}],
        "out_of_scope_products": [], "priority": "high", "priority_rationale": "CVSS 8.1",
        "kev_hit": False, "degraded": False, "warnings": [],
    }
    resp = _post(client, "/api/device-review/psirt/report", {"assessment": assessment_payload})
    assert resp.status_code == 200
    assert b"FG-IR-24-001" in resp.data
    assert b"FW01" in resp.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_psirt_routes.py -v`
Expected: FAIL — `404` responses / import errors, since the blueprint doesn't exist yet.

- [ ] **Step 3: Write the route module**

```python
# app/routes/psirt_routes.py
"""PSIRT Advisory Assessment — new section on the Device Review tab.

API (JSON):
  GET  /api/device-review/psirt/extract-status
       returns: { available: bool }  (reads ai_assist_enabled, same flag as
       every other AI-Assist feature in this repo)

  POST /api/device-review/psirt/extract
       body: { email_text: str }  (or multipart with a "file" field — .eml/.txt)
       returns: { advisory: {...Advisory.to_dict()...} }
       or 422 { field, error } if the LLM's extraction was missing/malformed
       a required field — never a silent guess.

  POST /api/device-review/psirt/assess/device
       body: { adom, device, advisory: {...} }
       Single-device evaluation — used by the frontend's per-device
       progress loop (mirrors /api/device-review/run/device).
       returns: { finding: {...DeviceFinding.to_dict()...} }

  POST /api/device-review/psirt/assess
       body: { adom: "<name>" | "*", advisory: {...} }
       Bulk entry point (adom="*" resolves to every ADOM the requesting
       user can access via app.groups.get_allowed_adoms).
       returns: {...PsirtAssessment.to_dict()...}

  POST /api/device-review/psirt/report
       body: { assessment: {...PsirtAssessment.to_dict() shape...} }
       Renders the already-computed assessment to HTML — never recomputes.
       returns: HTML document (Content-Type: text/html)
"""

from __future__ import annotations

import email
from email import policy as email_policy

from flask import Blueprint, jsonify, request, session

from app.app_settings import get_setting
from app.config import Config
from app.decorators import check_adom_access, tab_required
from app.fmg_client import FMGError
from app.fmg_helpers import make_client
from app.llm import get_provider
from app.llm.base import LLMError
from app.psirt.engine import assess as psirt_assess
from app.psirt.extract import ExtractionError, extract_advisory
from app.psirt.models import Advisory, AffectedRange
from app.psirt.render import render_psirt_html
from app.security import internal_api_error, upstream_api_error

bp = Blueprint("psirt", __name__)

_ALLOWED_UPLOAD_EXTS = (".eml", ".txt")


def _advisory_from_payload(data: dict) -> Advisory:
    ranges = [
        AffectedRange(
            product=str(r.get("product", "")),
            min_version=str(r.get("min_version", "") or ""),
            max_version=str(r.get("max_version", "") or ""),
            fixed_version=str(r.get("fixed_version", "") or ""),
            notes=str(r.get("notes", "") or ""),
        )
        for r in data.get("affected_ranges", []) if isinstance(r, dict)
    ]
    return Advisory(
        advisory_id=str(data.get("advisory_id", "")),
        advisory_url=str(data.get("advisory_url", "") or ""),
        cve_ids=[str(c) for c in data.get("cve_ids", [])],
        published_date=str(data.get("published_date", "") or ""),
        fortinet_severity=str(data.get("fortinet_severity", "") or ""),
        cvss_score=data.get("cvss_score"),
        description=str(data.get("description", "") or ""),
        affected_ranges=ranges,
        workaround_text=str(data.get("workaround_text", "") or ""),
        exploited_in_wild_text=str(data.get("exploited_in_wild_text", "") or ""),
        enrichment_degraded=bool(data.get("enrichment_degraded", False)),
    )


def _http_client():
    import requests

    return requests


# ── extract-status ───────────────────────────────────────────────────────────


@bp.route("/api/device-review/psirt/extract-status")
@tab_required("device_review")
def psirt_extract_status():
    return jsonify({"available": get_setting("ai_assist_enabled", False)})


# ── extract ───────────────────────────────────────────────────────────────────


@bp.route("/api/device-review/psirt/extract", methods=["POST"])
@tab_required("device_review")
def psirt_extract():
    if not get_setting("ai_assist_enabled", False):
        return jsonify({"error": "AI Assist is not enabled"}), 503

    is_multipart = "file" in request.files
    if is_multipart:
        upload = request.files["file"]
        filename = (upload.filename or "").lower()
        if not filename.endswith(_ALLOWED_UPLOAD_EXTS):
            return jsonify({"error": "Only .eml or .txt uploads are supported"}), 400
        raw = upload.read()
        if filename.endswith(".eml"):
            msg = email.message_from_bytes(raw, policy=email_policy.default)
            body = msg.get_body(preferencelist=("plain", "html"))
            email_text = body.get_content() if body else raw.decode("utf-8", errors="replace")
        else:
            email_text = raw.decode("utf-8", errors="replace")
    else:
        data = request.get_json(silent=True) or {}
        email_text = (data.get("email_text") or "").strip()

    if not email_text:
        return jsonify({"error": "email_text (or an uploaded file) is required"}), 400

    try:
        provider = get_provider()
        advisory = extract_advisory(email_text, provider)
    except ExtractionError as exc:
        return jsonify({"field": exc.field, "error": exc.detail}), 422
    except LLMError as exc:
        return jsonify({"error": str(exc)}), 502

    return jsonify({"advisory": advisory.to_dict()})


# ── assess: single device (progress-loop entry point) ─────────────────────────


@bp.route("/api/device-review/psirt/assess/device", methods=["POST"])
@tab_required("device_review")
def psirt_assess_device():
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    device = (data.get("device") or "").strip()
    if not adom or not device:
        return jsonify({"error": "adom and device are required"}), 400
    if err := check_adom_access(adom):
        return err

    advisory = _advisory_from_payload(data.get("advisory") or {})

    try:
        with make_client() as client:
            result = psirt_assess(
                advisory, client, adom, _http_client(),
                Config.PSIRT_KEV_URL if Config.PSIRT_ENRICHMENT_ENABLED else "",
                enrichment_enabled=Config.PSIRT_ENRICHMENT_ENABLED,
                fetch_timeout=Config.PSIRT_FETCH_TIMEOUT,
            )
    except FMGError as exc:
        return upstream_api_error("psirt", exc)
    except Exception as exc:
        return internal_api_error("psirt", exc)

    matching = [f for f in result.findings if f.device == device]
    finding = matching[0] if matching else None
    return jsonify({
        "finding": finding.to_dict() if finding else None,
        "priority": result.priority,
        "priority_rationale": result.priority_rationale,
        "kev_hit": result.kev_hit,
    })


# ── assess: bulk (adom="*" resolves to every accessible ADOM) ─────────────────


@bp.route("/api/device-review/psirt/assess", methods=["POST"])
@tab_required("device_review")
def psirt_assess_bulk():
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    if not adom:
        return jsonify({"error": "adom is required (use \"*\" for all accessible ADOMs)"}), 400

    if adom != "*":
        if err := check_adom_access(adom):
            return err
        adom_scope = adom
    else:
        from app.groups import get_allowed_adoms

        allowed = get_allowed_adoms(
            session.get("user", ""), ad_groups=session.get("ad_groups", [])
        )
        # allowed is None for unrestricted users — engine.assess() handles
        # "*" itself in that case by calling fmg_client.get_adoms() directly.
        # For restricted users we can't pass "*" through (engine has no
        # user concept), so pre-resolve to their allowed ADOM list and run
        # per-ADOM, merging results.
        if allowed is None:
            adom_scope = "*"
        else:
            adom_scope = None  # signal: iterate `allowed` below

    advisory = _advisory_from_payload(data.get("advisory") or {})

    try:
        with make_client() as client:
            if adom_scope is not None:
                result = psirt_assess(
                    advisory, client, adom_scope, _http_client(),
                    Config.PSIRT_KEV_URL if Config.PSIRT_ENRICHMENT_ENABLED else "",
                    enrichment_enabled=Config.PSIRT_ENRICHMENT_ENABLED,
                    fetch_timeout=Config.PSIRT_FETCH_TIMEOUT,
                )
            else:
                from app.psirt.scoring import compute_priority

                merged = None
                for one_adom in allowed:
                    partial = psirt_assess(
                        advisory, client, one_adom, _http_client(),
                        Config.PSIRT_KEV_URL if Config.PSIRT_ENRICHMENT_ENABLED else "",
                        enrichment_enabled=Config.PSIRT_ENRICHMENT_ENABLED,
                        fetch_timeout=Config.PSIRT_FETCH_TIMEOUT,
                    )
                    if merged is None:
                        merged = partial
                    else:
                        merged.findings.extend(partial.findings)
                        merged.warnings.extend(partial.warnings)
                        merged.degraded = merged.degraded or partial.degraded
                        merged.kev_hit = merged.kev_hit or partial.kev_hit
                # Each per-ADOM psirt_assess() call computed priority from only
                # that ADOM's findings — recompute once over the full merged
                # set so "any device in range" reflects the whole scope, not
                # just whichever ADOM happened to run first.
                if merged is not None:
                    any_in_range = any(f.in_range for f in merged.findings)
                    merged.priority, merged.priority_rationale = compute_priority(
                        cvss_score=merged.advisory.cvss_score,
                        fortinet_severity=merged.advisory.fortinet_severity,
                        exploited_in_wild_text=merged.advisory.exploited_in_wild_text,
                        kev_hit=merged.kev_hit,
                        any_device_in_range=any_in_range,
                    )
                result = merged
    except FMGError as exc:
        return upstream_api_error("psirt", exc)
    except Exception as exc:
        return internal_api_error("psirt", exc)

    return jsonify(result.to_dict())


# ── report ──────────────────────────────────────────────────────────────────


@bp.route("/api/device-review/psirt/report", methods=["POST"])
@tab_required("device_review")
def psirt_report():
    data = request.get_json(silent=True) or {}
    assessment = data.get("assessment")
    if not isinstance(assessment, dict):
        return jsonify({"error": "assessment is required"}), 400
    try:
        html = render_psirt_html(assessment)
    except Exception as exc:
        return internal_api_error("psirt", exc)
    return html, 200, {"Content-Type": "text/html"}
```

- [ ] **Step 4: Register the blueprint**

In `app/__init__.py`, add `"app.routes.psirt_routes",` to `_BLUEPRINT_MODULES`, immediately after `"app.routes.device_review_routes",`:

```python
_BLUEPRINT_MODULES = [
    "app.routes.auth_routes",
    "app.routes.dashboard_routes",
    "app.routes.api_routes",
    "app.routes.admin_routes",
    "app.routes.hygiene_routes",
    "app.routes.device_review_routes",
    "app.routes.psirt_routes",
    "app.routes.rule_review_routes",
    "app.routes.zone_routes",
    "app.routes.pending_changes_routes",
    "app.routes.map_routes",
    "app.routes.external_api_routes",
    "app.routes.backup_routes",
    # "app.routes.my_new_module",  ← add future modules here
]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/test_psirt_routes.py -v`
Expected: PASS (10 tests). If `test_assess_device_checks_adom_access` fails because `app.decorators.user_can_access_adom` isn't the right patch target, run `grep -n "user_can_access_adom" app/decorators.py app/groups.py` to find the actual import path `check_adom_access` uses (it's imported lazily inside the function — patch `app.groups.user_can_access_adom` instead if so) and adjust the patch target in the test to match, then re-run.

- [ ] **Step 6: Commit**

```bash
git add app/routes/psirt_routes.py app/__init__.py tests/test_psirt_routes.py
git commit -m "Add PSIRT extract/assess/report routes"
```

---

### Task 12: Frontend — Device Review page PSIRT section

**Files:**
- Modify: `app/templates/device_review.html`
- Create: `app/static/js/psirt.js`

No automated test for this task (no JS test harness exists in this repo — every other frontend feature in this codebase is verified manually in-browser, matching existing convention). Verified via Step 4 (manual browser check) instead of pytest.

- [ ] **Step 1: Add the PSIRT section markup to `device_review.html`**

Wrap the existing page content in a section label (to match Hygiene's multi-section pattern), then append the new PSIRT section. Replace the opening of the `{% block content %}` (the `<div class="page-header">` line) with:

```html
{% block content %}
<div class="page-header">
  <div>
    <h2>Device Review</h2>
    <span class="last-updated" id="drLastRunLabel"></span>
  </div>
</div>

<div class="rr-section-label">CIS Hardening &amp; Interface Protocols</div>
```

(This just adds one label line before the existing `<!-- Selectors -->` comment — no other existing markup changes.)

Then, immediately before `{% endblock %}` (after the closing `</div>` of the pagination div, and before the existing `{% block scripts %}`), insert:

```html
<!-- ── PSIRT Advisory Assessment ──────────────────────────────────────────── -->
<div class="rr-section-label" style="margin-top:2rem">PSIRT Advisory Assessment</div>

<div class="hygiene-selectors">
  <div class="hygiene-selector-row">
    <label for="psirtAdom">ADOM</label>
    <select id="psirtAdom" class="form-select">
      <option value="">— select ADOM —</option>
      <option value="*">All ADOMs</option>
    </select>
  </div>

  <div class="hygiene-selector-row" style="margin-top:.6rem;align-items:flex-start">
    <label style="padding-top:.3rem">Advisory</label>
    <div style="flex:1">
      <div style="display:flex;gap:.5rem;margin-bottom:.5rem">
        <button class="btn btn-xs active" id="psirtModePaste" type="button">Paste text</button>
        <button class="btn btn-xs" id="psirtModeFile" type="button">Upload file</button>
      </div>
      <textarea id="psirtEmailText" class="form-control" rows="8"
        placeholder="Paste the full PSIRT advisory email text here…" style="width:100%"></textarea>
      <input type="file" id="psirtEmailFile" accept=".eml,.txt" style="display:none" />
    </div>
  </div>

  <div style="margin-top:1rem;display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">
    <button class="btn btn-primary" id="psirtExtractBtn" disabled>Extract Advisory</button>
    <span id="psirtExtractRunning" class="text-muted" style="display:none;font-style:italic">Extracting…</span>
    <span id="psirtExtractError" class="text-danger" style="display:none"></span>
    <span id="psirtUnavailableNotice" class="text-muted" style="display:none;font-style:italic">
      AI Assist is not enabled — an admin can turn it on under Admin → AI Assist.
    </span>
  </div>
</div>

<!-- Editable review form — populated after extraction -->
<div id="psirtReviewForm" style="display:none;margin-top:1.25rem;padding:1rem;background:var(--surface-alt);border:1px solid var(--border);border-radius:6px">
  <div style="font-size:.8rem;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.75rem">
    Review Extracted Fields — confirm or correct before running the assessment
  </div>
  <div class="hygiene-selector-row"><label>Advisory ID</label><input type="text" id="psirtFieldAdvisoryId" class="form-control" style="max-width:280px"></div>
  <div class="hygiene-selector-row" style="margin-top:.5rem"><label>Advisory URL</label><input type="text" id="psirtFieldAdvisoryUrl" class="form-control" style="max-width:420px"></div>
  <div class="hygiene-selector-row" style="margin-top:.5rem"><label>CVE ID(s)</label><input type="text" id="psirtFieldCveIds" class="form-control" style="max-width:420px" placeholder="comma-separated, e.g. CVE-2024-12345, CVE-2024-12346"></div>
  <div class="hygiene-selector-row" style="margin-top:.5rem"><label>Severity</label><input type="text" id="psirtFieldSeverity" class="form-control" style="max-width:160px" placeholder="Critical / High / Medium / Low"></div>
  <div class="hygiene-selector-row" style="margin-top:.5rem"><label>CVSS Score</label><input type="text" id="psirtFieldCvss" class="form-control" style="max-width:100px"></div>
  <div class="hygiene-selector-row" style="margin-top:.5rem;align-items:flex-start"><label style="padding-top:.4rem">Workaround Text</label><textarea id="psirtFieldWorkaround" class="form-control" rows="2" style="width:100%;max-width:600px"></textarea></div>
  <div class="hygiene-selector-row" style="margin-top:.5rem;align-items:flex-start"><label style="padding-top:.4rem">Exploitation Text</label><textarea id="psirtFieldExploited" class="form-control" rows="2" style="width:100%;max-width:600px"></textarea></div>

  <div style="margin-top:.75rem">
    <div style="font-size:.8rem;font-weight:600;color:var(--text-muted);margin-bottom:.4rem">Affected Ranges</div>
    <div id="psirtRangesRows"></div>
    <button class="btn btn-xs" id="psirtAddRangeBtn" type="button" style="margin-top:.4rem">+ Add range</button>
  </div>

  <div style="margin-top:1rem;display:flex;align-items:center;gap:.75rem">
    <button class="btn btn-primary" id="psirtRunBtn">Run Assessment</button>
    <span id="psirtRunning" class="text-muted" style="display:none;font-style:italic">Scanning…</span>
    <span id="psirtRunError" class="text-danger" style="display:none"></span>
  </div>

  <div id="psirtProgressWrap" style="display:none;margin-top:.9rem">
    <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:.3rem">
      <span id="psirtProgressLabel" class="text-muted" style="font-size:.82rem"></span>
    </div>
    <div class="dr-progress-track"><div class="dr-progress-bar" id="psirtProgressBar">0%</div></div>
  </div>
</div>

<!-- Results -->
<div id="psirtResults" style="display:none;margin-top:1.5rem">
  <div class="obj-lookup-result-header">
    <span id="psirtSummary" class="obj-lookup-summary"></span>
    <div class="hygiene-export-row">
      <button class="btn btn-sm" id="psirtReportBtn">&#8659; View HTML Report</button>
    </div>
  </div>

  <div id="psirtWarnings" class="alert alert-danger" style="display:none;margin-top:.5rem"></div>

  <div class="table-wrapper" style="margin-top:.75rem">
    <table class="data-table" id="psirtTable">
      <thead>
        <tr>
          <th>Device</th><th>ADOM</th><th>Product</th><th>Current Version</th>
          <th>In Range</th><th>Workaround</th><th>Verdict</th><th>Reason</th>
        </tr>
      </thead>
      <tbody id="psirtTbody"></tbody>
    </table>
  </div>
</div>
```

Finally, add the script include at the end of `{% block scripts %}`, right after the existing `device_review.js` line:

```html
<script src="{{ url_for('static', filename='js/psirt.js') }}?v=1"></script>
```

- [ ] **Step 2: Write `app/static/js/psirt.js`**

```javascript
/* PSIRT Advisory Assessment — Device Review tab section */

let psirtExtracted = null;   // last extracted Advisory dict, before/after edits
let psirtAssessment = null;  // last completed PsirtAssessment dict

/* ── Availability check ───────────────────────────────────────────────────── */
async function checkPsirtAvailability() {
  try {
    const resp = await fetch('/api/device-review/psirt/extract-status');
    const data = await resp.json();
    const available = !!data.available;
    document.getElementById('psirtExtractBtn').disabled = !available;
    document.getElementById('psirtUnavailableNotice').style.display = available ? 'none' : '';
    return available;
  } catch (e) {
    return false;
  }
}

/* ── Paste vs upload toggle ───────────────────────────────────────────────── */
document.getElementById('psirtModePaste').addEventListener('click', () => {
  document.getElementById('psirtModePaste').classList.add('active');
  document.getElementById('psirtModeFile').classList.remove('active');
  document.getElementById('psirtEmailText').style.display = '';
  document.getElementById('psirtEmailFile').style.display = 'none';
});
document.getElementById('psirtModeFile').addEventListener('click', () => {
  document.getElementById('psirtModeFile').classList.add('active');
  document.getElementById('psirtModePaste').classList.remove('active');
  document.getElementById('psirtEmailText').style.display = 'none';
  document.getElementById('psirtEmailFile').style.display = '';
});

/* ── Extract ───────────────────────────────────────────────────────────────── */
document.getElementById('psirtExtractBtn').addEventListener('click', runPsirtExtract);

async function runPsirtExtract() {
  const errEl = document.getElementById('psirtExtractError');
  const runningEl = document.getElementById('psirtExtractRunning');
  errEl.style.display = 'none';
  runningEl.style.display = '';
  document.getElementById('psirtExtractBtn').disabled = true;

  const fileInput = document.getElementById('psirtEmailFile');
  const usingFile = document.getElementById('psirtEmailFile').style.display !== 'none'
    && fileInput.files.length > 0;

  try {
    let resp;
    if (usingFile) {
      const fd = new FormData();
      fd.append('file', fileInput.files[0]);
      resp = await fetch('/api/device-review/psirt/extract', { method: 'POST', body: fd });
    } else {
      const emailText = document.getElementById('psirtEmailText').value.trim();
      if (!emailText) { errEl.textContent = 'Paste the advisory text or choose a file.'; errEl.style.display = ''; return; }
      resp = await fetch('/api/device-review/psirt/extract', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_text: emailText }),
      });
    }
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (!resp.ok) {
      errEl.textContent = data.field ? `${data.field}: ${data.error}` : (data.error || `Request failed (${resp.status})`);
      errEl.style.display = '';
      return;
    }
    psirtExtracted = data.advisory;
    populatePsirtReviewForm(psirtExtracted);
    document.getElementById('psirtReviewForm').style.display = '';
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = '';
  } finally {
    runningEl.style.display = 'none';
    document.getElementById('psirtExtractBtn').disabled = false;
  }
}

/* ── Review form ───────────────────────────────────────────────────────────── */
function populatePsirtReviewForm(advisory) {
  document.getElementById('psirtFieldAdvisoryId').value = advisory.advisory_id || '';
  document.getElementById('psirtFieldAdvisoryUrl').value = advisory.advisory_url || '';
  document.getElementById('psirtFieldCveIds').value = (advisory.cve_ids || []).join(', ');
  document.getElementById('psirtFieldSeverity').value = advisory.fortinet_severity || '';
  document.getElementById('psirtFieldCvss').value = advisory.cvss_score != null ? advisory.cvss_score : '';
  document.getElementById('psirtFieldWorkaround').value = advisory.workaround_text || '';
  document.getElementById('psirtFieldExploited').value = advisory.exploited_in_wild_text || '';

  const rowsEl = document.getElementById('psirtRangesRows');
  rowsEl.innerHTML = '';
  (advisory.affected_ranges || []).forEach(r => addPsirtRangeRow(r));
  if (!(advisory.affected_ranges || []).length) addPsirtRangeRow({});
}

function addPsirtRangeRow(r) {
  const rowsEl = document.getElementById('psirtRangesRows');
  const row = document.createElement('div');
  row.className = 'psirt-range-row';
  row.style = 'display:flex;gap:.4rem;margin-bottom:.4rem;flex-wrap:wrap';
  row.innerHTML = `
    <input type="text" class="form-control psirt-range-product" placeholder="Product (FortiOS)" style="max-width:140px" value="${escAttr(r.product || '')}">
    <input type="text" class="form-control psirt-range-min" placeholder="Min version" style="max-width:110px" value="${escAttr(r.min_version || '')}">
    <input type="text" class="form-control psirt-range-max" placeholder="Max version" style="max-width:110px" value="${escAttr(r.max_version || '')}">
    <input type="text" class="form-control psirt-range-fixed" placeholder="Fixed version" style="max-width:110px" value="${escAttr(r.fixed_version || '')}">
    <input type="text" class="form-control psirt-range-notes" placeholder="Notes" style="max-width:160px" value="${escAttr(r.notes || '')}">
    <button class="btn btn-xs" type="button" onclick="this.parentElement.remove()">&#10005;</button>
  `;
  rowsEl.appendChild(row);
}
document.getElementById('psirtAddRangeBtn').addEventListener('click', () => addPsirtRangeRow({}));

function escAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

function collectPsirtAdvisoryFromForm() {
  const cveIds = document.getElementById('psirtFieldCveIds').value
    .split(',').map(s => s.trim()).filter(Boolean);
  const ranges = [...document.querySelectorAll('#psirtRangesRows .psirt-range-row')].map(row => ({
    product: row.querySelector('.psirt-range-product').value.trim(),
    min_version: row.querySelector('.psirt-range-min').value.trim(),
    max_version: row.querySelector('.psirt-range-max').value.trim(),
    fixed_version: row.querySelector('.psirt-range-fixed').value.trim(),
    notes: row.querySelector('.psirt-range-notes').value.trim(),
  })).filter(r => r.product);
  const cvssRaw = document.getElementById('psirtFieldCvss').value.trim();
  return {
    advisory_id: document.getElementById('psirtFieldAdvisoryId').value.trim(),
    advisory_url: document.getElementById('psirtFieldAdvisoryUrl').value.trim(),
    cve_ids: cveIds,
    fortinet_severity: document.getElementById('psirtFieldSeverity').value.trim(),
    cvss_score: cvssRaw ? parseFloat(cvssRaw) : null,
    workaround_text: document.getElementById('psirtFieldWorkaround').value.trim(),
    exploited_in_wild_text: document.getElementById('psirtFieldExploited').value.trim(),
    affected_ranges: ranges,
    published_date: '', description: '', enrichment_degraded: false,
  };
}

/* ── Run assessment (progress loop over ADOM's devices, or bulk for "*") ────── */
document.getElementById('psirtRunBtn').addEventListener('click', runPsirtAssessment);

async function runPsirtAssessment() {
  const errEl = document.getElementById('psirtRunError');
  errEl.style.display = 'none';
  const adom = document.getElementById('psirtAdom').value;
  if (!adom) { errEl.textContent = 'Select an ADOM.'; errEl.style.display = ''; return; }

  const advisory = collectPsirtAdvisoryFromForm();
  if (!advisory.advisory_id || !advisory.cve_ids.length || !advisory.affected_ranges.length) {
    errEl.textContent = 'Advisory ID, at least one CVE ID, and at least one affected range are required.';
    errEl.style.display = '';
    return;
  }

  document.getElementById('psirtRunBtn').disabled = true;
  document.getElementById('psirtRunning').style.display = '';
  document.getElementById('psirtResults').style.display = 'none';
  document.getElementById('psirtProgressWrap').style.display = '';
  showPsirtProgress(0, 1, 'Running assessment…');

  try {
    const resp = await fetch('/api/device-review/psirt/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ adom, advisory }),
    });
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (!resp.ok) {
      errEl.textContent = data.error || `Request failed (${resp.status})`;
      errEl.style.display = '';
      return;
    }
    psirtAssessment = data;
    renderPsirtResults(data);
    document.getElementById('psirtResults').style.display = '';
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = '';
  } finally {
    document.getElementById('psirtRunBtn').disabled = false;
    document.getElementById('psirtRunning').style.display = 'none';
    document.getElementById('psirtProgressWrap').style.display = 'none';
  }
}

function showPsirtProgress(done, total, label) {
  const bar = document.getElementById('psirtProgressBar');
  const lbl = document.getElementById('psirtProgressLabel');
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  bar.style.width = pct + '%';
  bar.textContent = pct + '%';
  lbl.textContent = label;
}

/* ── Results rendering ────────────────────────────────────────────────────── */
function renderPsirtResults(data) {
  const priorityLabel = (data.priority || '').toUpperCase();
  const kevSuffix = data.kev_hit ? ' — KEV-LISTED' : '';
  document.getElementById('psirtSummary').textContent =
    `Priority: ${priorityLabel}${kevSuffix} — ${data.findings.length} device(s) evaluated. ${data.priority_rationale || ''}`;

  const warnEl = document.getElementById('psirtWarnings');
  if (data.warnings && data.warnings.length) {
    warnEl.innerHTML = '<strong>Warnings:</strong><ul>' + data.warnings.map(w => `<li>${escHtml(w)}</li>`).join('') + '</ul>';
    warnEl.style.display = '';
  } else {
    warnEl.style.display = 'none';
  }

  const tbody = document.getElementById('psirtTbody');
  tbody.innerHTML = data.findings.map(f => `
    <tr>
      <td>${escHtml(f.device)}</td>
      <td>${escHtml(f.adom)}</td>
      <td>${escHtml(f.product)}</td>
      <td>${escHtml(f.current_version || '—')}</td>
      <td>${f.in_range ? 'Yes' : 'No'}</td>
      <td>${escHtml((f.workaround_status || '').replace(/_/g, ' '))}</td>
      <td><span class="obj-type-badge">${escHtml((f.verdict || '').replace(/_/g, ' '))}</span></td>
      <td style="font-size:.82rem;color:var(--text-muted)">${escHtml(f.reason)}</td>
    </tr>
  `).join('') || '<tr><td colspan="8" class="empty-state">No devices evaluated.</td></tr>';
}

function escHtml(s) {
  const div = document.createElement('div');
  div.textContent = String(s ?? '');
  return div.innerHTML;
}

/* ── HTML report ───────────────────────────────────────────────────────────── */
document.getElementById('psirtReportBtn').addEventListener('click', async () => {
  if (!psirtAssessment) return;
  const resp = await fetch('/api/device-review/psirt/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assessment: psirtAssessment }),
  });
  const html = await resp.text();
  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); }
});

/* ── Init ──────────────────────────────────────────────────────────────────── */
checkPsirtAvailability();
```

- [ ] **Step 3: Run the full test suite to confirm nothing else broke**

Run: `uv run pytest -q`
Expected: all existing tests plus every PSIRT test from Tasks 1–11 pass; no regressions.

- [ ] **Step 4: Manual browser verification**

Start the dev server (`python wsgi.py`), log in, navigate to `/device-review`, confirm:
- The new "PSIRT Advisory Assessment" section renders below the existing CIS checks section.
- With `ai_assist_enabled=false` (default), the Extract button is disabled and the "AI Assist is not enabled" notice shows.
- Toggle **Admin → AI Assist** on, reload — Extract button becomes enabled.
- Paste some placeholder advisory text, click Extract — confirm either a populated review form (if `ANTHROPIC_API_KEY`/provider is configured) or a clear error message (if not) — never a blank/broken state.

- [ ] **Step 5: Commit**

```bash
git add app/templates/device_review.html app/static/js/psirt.js
git commit -m "Add PSIRT Advisory Assessment UI to the Device Review page"
```

---

### Task 13: Documentation + final verification

**Files:**
- Modify: `CLAUDE.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add a "PSIRT Advisory Assessment" subsection to CLAUDE.md**

Insert a new subsection under the existing `### Device Review tab` section in `CLAUDE.md` (after the "Adding a new CIS check" block, before `### Rule Validation tab`):

```markdown
#### PSIRT Advisory Assessment

New section on the same `/device-review` page (below the CIS checks table),
not a separate nav tab. Paste or upload (`.eml`/`.txt`) a Fortinet PSIRT
advisory email; an LLM extracts structured fields (advisory ID, CVE IDs,
affected version ranges, workaround text, severity, exploitation wording)
into an editable review form — the only LLM touchpoint in this feature.
Everything downstream is deterministic: `app/psirt/engine.py::assess()`
scans the selected ADOM (or every ADOM the user can access, via `"*"`)
for affected firmware and whether any documented workaround is already
applied, then `app/psirt/scoring.py` computes priority from CVSS band,
Fortinet's exploitation wording, and CISA KEV catalog membership. Ported
from `~/code/github/ai/4tanalyst`'s `psirt/` package — see
`app/psirt/VENDORED_FROM.md` for provenance and the sync workflow.

**Workaround checks** (`app/psirt/workaround_checks.py`) — a registry
matching recognized workaround phrasing to real FortiManager config
checks via `app/fmg_client.py`: disabling HTTP/HTTPS admin access,
disabling GUI on internet-facing interfaces, and trusted-hosts
restriction (the last one reuses the same logic as Device Review's
`trusted_hosts` CIS check). Unrecognized workaround text always yields
`manual_verification_required` — never guessed.

**Enrichment** — best-effort fetches against the fortiguard.com advisory
page and the CISA KEV feed, gated by `PSIRT_ENRICHMENT_ENABLED` (default
`true`; set `false` for air-gapped deployments). Failures degrade
gracefully — the assessment proceeds on email-derived data alone.

**Feature gate:** reuses the same `ai_assist_enabled` app-settings flag as
every other AI-Assist feature in this repo (Admin → AI Assist) — no
separate PSIRT toggle.

**API endpoints:**
- `GET  /api/device-review/psirt/extract-status`
- `POST /api/device-review/psirt/extract` — body `{ email_text }` or multipart file upload
- `POST /api/device-review/psirt/assess/device` — body `{ adom, device, advisory }`
- `POST /api/device-review/psirt/assess` — body `{ adom: "<name>" | "*", advisory }`
- `POST /api/device-review/psirt/report` — body `{ assessment }`, returns HTML

No persistence — each assessment is a one-off analysis, same as NAT Lookup
and Rule Validation's AI Assist.
```

- [ ] **Step 2: Add a CHANGELOG.md entry**

Add under `## [Unreleased] > ### Added` (find the first `### Added` block near the top of the file, add as a new bullet before the existing first entry):

```markdown
- **PSIRT Advisory Assessment (Device Review tab):** New section — paste or
  upload a Fortinet PSIRT advisory email, get an LLM-assisted structured
  extraction (editable before running), then a deterministic per-device
  fleet scan across one ADOM or all accessible ADOMs: firmware version vs.
  the advisory's affected ranges, workaround-in-place verification against
  live FortiManager config, and exploit-aware priority scoring (CVSS band,
  Fortinet's own exploitation wording, CISA KEV catalog). Renders a
  self-contained HTML report. Ported from the sibling
  [4tanalyst](https://github.com/gatecrest-labs) `psirt/` package — see
  `app/psirt/VENDORED_FROM.md`. Enrichment against fortiguard.com/CISA KEV
  is opt-out via `PSIRT_ENRICHMENT_ENABLED` for air-gapped deployments. No
  disposition persistence in v1 — one-off analysis, same as NAT Lookup.
```

- [ ] **Step 3: Run the full test suite and linter**

Run: `uv run pytest -q`
Expected: all tests pass (existing + all new PSIRT tests), zero failures.

Run: `uv run ruff check app/ tests/`
Expected: `All checks passed!` — fix any findings before proceeding.

- [ ] **Step 4: Update the graphify knowledge graph**

Run: `graphify update .`
Expected: completes without error; graph now includes `app/psirt/`, `app/routes/psirt_routes.py`, and the new templates/JS.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md CHANGELOG.md
git commit -m "Document PSIRT Advisory Assessment in CLAUDE.md and CHANGELOG.md"
```

---

## Self-Review Notes

**Spec coverage:** Architecture & data flow (Tasks 1–12 implement every stage of the diagram). Components: `app/psirt/` deterministic core (Tasks 1–6, 10), new LLM capability (Task 7), `app/psirt/extract.py` (Task 8), routes (Task 11), UI (Task 12). Configuration (Task 9). Report content structure — all 6 numbered sections from the spec are present in `psirt_report.html` (Task 10). Error handling — covered per-module in Tasks 4 (enrichment), 6 (degraded scans), 8 (extraction validation), 11 (route-level 422/502/503). Testing section — every file the spec lists a test for has a corresponding Task test file. Open questions (prompt wording, `.eml` parsing depth, registry size) are left as noted follow-ups, not blockers — the plan implements a working, testable v1 per the spec's own framing of them as "for implementation planning," not "must resolve before starting."

**Type/signature consistency check:** `Advisory`/`AffectedRange`/`DeviceFinding`/`PsirtAssessment` (Task 1) are used identically in Tasks 2, 4, 6, 8, 10, 11. `assess()`'s signature (`advisory, fmg_client, adom_scope, http_client, kev_url, enrichment_enabled`) defined in Task 6 matches every call site in Task 11. `extract_advisory(raw_text, provider)` (Task 8) matches its call in Task 11. `LLMProvider.extract_json()` (Task 7) matches its use in Task 8. `render_psirt_html(assessment_dict)` (Task 10) matches its call in Task 11 and the shape asserted in Task 10's own tests.

**Placeholder scan:** no TBD/TODO markers; every step has runnable code or an exact command.
