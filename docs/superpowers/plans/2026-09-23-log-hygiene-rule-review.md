# Log-Based Rule Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a single-rule Log-Based Rule Review feature to Audit Review that flags which configured source/destination host members and service ports of one firewall rule saw zero traffic over a user-chosen day range (1–60), by calling a new external API on 4tlog.

**Architecture:** A new outbound HTTP client (`app/log_usage_client.py`) calls 4tlog's (separately implemented) `POST /external/api/log-usage` endpoint using admin-configured connection settings (`app/log_source.py`). A new check engine (`app/log_hygiene.py`) fetches one rule's data from FortiManager, expands its address/service group members (reusing `app.hygiene._expand_group_members`), classifies each resolved leaf as an evaluable single host/port or an informational "not evaluated" object, calls the client, and diffs configured members against observed traffic. New routes expose this to a new "Log-Based Rule Review" section on the existing Audit Review page.

**Tech Stack:** Flask, `requests` (already a dependency), pytest + `unittest.mock`, vanilla JS (no framework), existing atomic-JSON-write config pattern (`app/atomic_io.py`).

**Spec:** `docs/superpowers/specs/2026-09-23-log-hygiene-rule-review-design.md` (companion 4tlog handoff spec: `docs/superpowers/specs/2026-09-23-log-usage-endpoint-design.md`, implemented separately in that repo).

## Global Constraints

- Read-only throughout: this feature never writes to FortiManager, FortiGate, or 4tlog — only reads.
- `days` is always clamped server-side to the inclusive range [1, 60], regardless of client input.
- Only address objects that resolve to exactly one host IP (`/32`) and service objects that resolve to exactly one discrete TCP/UDP port are ever flagged Used/Unused. Everything else (subnets, ranges, FQDN, `all`/`any`, multi-port services, non-TCP/UDP services) goes into an informational "not evaluated" bucket and is never flagged.
- Every external failure (4tlog disabled/unreachable/unauthorized, FMG error, stale rule) must degrade to a JSON error response — never a raw 500.
- The 4tlog bearer token is stored reversibly (plaintext in a gitignored JSON file), never hashed — this app sends it, it does not verify it. It must never be returned to the browser in plaintext after the first save (masked as `••••••`, same convention as SMTP's password field).
- New code follows this repo's existing conventions exactly: atomic-JSON-write config pattern (`app/atomic_io.py`), `@tab_required("audit_review")` / `@check_adom_access(adom)` on every ADOM-scoped route, `internal_api_error`/`upstream_api_error` helpers from `app/security.py` for uncaught exceptions.

## Review Focus

- A rule's `policyid` may no longer exist in the package by the time the check runs (renumbered/deleted since the package was last viewed) — the check must return a clear "rule not found" error, not crash or silently return an empty result.
- 4tlog's `truncated: true` flag (log search hit its row cap) must reach the final JSON response unchanged — silently dropping it would let a reviewer treat an incomplete "unused" flag as certain.
- The same leaf address/service member reachable through two different paths (referenced directly on the rule AND nested inside a group also on the rule) must appear exactly once in the evaluated/not-evaluated output, not duplicated.
- `days` sent by the client as `0`, `61`, negative, a string, or missing must never reach the 4tlog call unclamped/unvalidated — always coerced into [1, 60].
- A service object's port range field using FortiManager's `"src:dst"` colon syntax (e.g. `"0:443"`) represents a single destination port (443) and must be classified as evaluable, not mistaken for a multi-value range.

---

## Task 1: `app/log_source.py` — 4tlog connection config storage

**Files:**
- Create: `app/log_source.py`
- Create: `log_source_config.example.json`
- Modify: `.gitignore` (add `log_source_config.json`)
- Test: `tests/test_log_source.py`

**Interfaces:**
- Produces: `load_log_source_config() -> dict` returning `{"enabled": bool, "base_url": str, "token": str, "verify_ssl": bool}` (defaults: `False`, `""`, `""`, `True`). `save_log_source_config(cfg: dict) -> None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_log_source.py
def test_load_log_source_config_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    cfg = log_source.load_log_source_config()
    assert cfg["enabled"] is False
    assert cfg["base_url"] == ""
    assert cfg["token"] == ""
    assert cfg["verify_ssl"] is True


def test_save_and_reload_log_source_config(tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({
        "enabled": True, "base_url": "https://4tlog.internal:5443",
        "token": "secret-token", "verify_ssl": False,
    })
    cfg = log_source.load_log_source_config()
    assert cfg["enabled"] is True
    assert cfg["base_url"] == "https://4tlog.internal:5443"
    assert cfg["token"] == "secret-token"
    assert cfg["verify_ssl"] is False


def test_load_log_source_config_survives_corrupt_file(tmp_path, monkeypatch):
    path = tmp_path / "log_source_config.json"
    path.write_text("not json")
    monkeypatch.setattr("app.log_source._CONFIG_PATH", path)
    from app import log_source
    cfg = log_source.load_log_source_config()
    assert cfg["enabled"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_log_source.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.log_source'`

- [ ] **Step 3: Implement `app/log_source.py`**

```python
"""4tlog connection config — Admin -> Log Hygiene. Mirrors app/smtp_client.py's
atomic-JSON config pattern. The token is stored reversibly (this app sends
it on every call to 4tlog; it does not verify inbound tokens), unlike
app/api_tokens.py's hashed inbound tokens."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from app.atomic_io import atomic_write_json

_CONFIG_PATH = Path(__file__).parent.parent / "log_source_config.json"
_lock = threading.Lock()

_DEFAULTS: dict = {
    "enabled": False,
    "base_url": "",
    "token": "",
    "verify_ssl": True,
}


def load_log_source_config() -> dict:
    with _lock:
        if not _CONFIG_PATH.exists():
            return dict(_DEFAULTS)
        try:
            with open(_CONFIG_PATH) as f:
                data = json.load(f)
            return {**_DEFAULTS, **data}
        except Exception:
            return dict(_DEFAULTS)


def save_log_source_config(cfg: dict) -> None:
    with _lock:
        atomic_write_json(_CONFIG_PATH, {**_DEFAULTS, **cfg})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_log_source.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Add the example config file and gitignore entry**

```json
{
  "enabled": false,
  "base_url": "https://4tlog.example.internal:5443",
  "token": "paste-a-4tlog-external-api-token-here",
  "verify_ssl": true
}
```

Save as `log_source_config.example.json`. Add `log_source_config.json` to `.gitignore` next to the existing `smtp_config.json` / `api_tokens.json` entries.

- [ ] **Step 6: Commit**

```bash
git add app/log_source.py log_source_config.example.json .gitignore tests/test_log_source.py
git commit -m "$(cat <<'EOF'
feat: add log_source config module for 4tlog connection settings

Stores the base URL, bearer token, and enabled flag for the upcoming
Log-Based Rule Review feature's outbound call to 4tlog, mirroring
smtp_client.py's atomic-JSON config pattern.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 2: `app/log_usage_client.py` — 4tlog HTTP client

**Files:**
- Create: `app/log_usage_client.py`
- Test: `tests/test_log_usage_client.py`

**Interfaces:**
- Consumes: `app.log_source.load_log_source_config() -> dict` (Task 1).
- Produces: `class LogUsageError(Exception)`; `get_rule_log_usage(adom: str, devices: list[str], policy_id: int, days: int) -> dict` (raises `LogUsageError` on any failure, otherwise returns 4tlog's decoded JSON response body verbatim); `test_connection() -> dict` returning `{"ok": bool, "error": str | None}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_log_usage_client.py
from unittest.mock import MagicMock, patch

import pytest


def _cfg(**overrides):
    base = {"enabled": True, "base_url": "https://4tlog.test:5443",
            "token": "tok123", "verify_ssl": True}
    base.update(overrides)
    return base


def test_get_rule_log_usage_not_enabled_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg(enabled=False))
    with pytest.raises(log_usage_client.LogUsageError, match="not enabled"):
        log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_not_configured_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config",
                         lambda: _cfg(base_url="", token=""))
    with pytest.raises(log_usage_client.LogUsageError, match="not configured"):
        log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_success(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"srcips": ["10.1.1.5"], "dstips": [], "dstports": [443]}
    with patch("app.log_usage_client.requests.post", return_value=mock_resp) as mock_post:
        result = log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 123, 30)
    assert result["srcips"] == ["10.1.1.5"]
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["json"] == {"adom": "ADOM", "devices": ["FW01"], "policyid": 123, "days": 30}
    assert call_kwargs["headers"]["Authorization"] == "Bearer tok123"


def test_get_rule_log_usage_unauthorized_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=401)
    with patch("app.log_usage_client.requests.post", return_value=mock_resp):
        with pytest.raises(log_usage_client.LogUsageError, match="rejected"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_disabled_on_4tlog_side_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=503)
    with patch("app.log_usage_client.requests.post", return_value=mock_resp):
        with pytest.raises(log_usage_client.LogUsageError, match="disabled"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_connection_error_raises(monkeypatch):
    import requests

    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    with patch("app.log_usage_client.requests.post",
               side_effect=requests.ConnectionError("refused")):
        with pytest.raises(log_usage_client.LogUsageError, match="Could not reach"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_bad_json_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.side_effect = ValueError("bad json")
    with patch("app.log_usage_client.requests.post", return_value=mock_resp):
        with pytest.raises(log_usage_client.LogUsageError, match="invalid response"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_test_connection_ok(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=200)
    with patch("app.log_usage_client.requests.get", return_value=mock_resp):
        result = log_usage_client.test_connection()
    assert result == {"ok": True, "error": None}


def test_test_connection_not_configured(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config",
                         lambda: _cfg(base_url="", token=""))
    result = log_usage_client.test_connection()
    assert result["ok"] is False
    assert "required" in result["error"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_log_usage_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.log_usage_client'`

- [ ] **Step 3: Implement `app/log_usage_client.py`**

```python
"""Outbound client for 4tlog's external log-usage API. Single POST, no
session/login lifecycle -- 4tlog's external API is stateless bearer-token
auth, same as this app's own app/routes/external_api_routes.py."""

from __future__ import annotations

import requests

from app.log_source import load_log_source_config


class LogUsageError(Exception):
    """Raised on any failure talking to 4tlog: not configured/enabled,
    unreachable, unauthorized, or a well-formed error response. Callers
    must never let a raw exception from this module propagate — this is
    the single error type routes need to catch."""


def _require_config() -> dict:
    cfg = load_log_source_config()
    if not cfg.get("enabled"):
        raise LogUsageError(
            "Log Hygiene is not enabled -- configure it in Admin → Log Hygiene"
        )
    base_url = (cfg.get("base_url") or "").rstrip("/")
    token = cfg.get("token") or ""
    if not base_url or not token:
        raise LogUsageError(
            "4tlog connection is not configured -- set the base URL and "
            "token in Admin → Log Hygiene"
        )
    cfg["base_url"] = base_url
    return cfg


def get_rule_log_usage(adom: str, devices: list[str], policy_id: int, days: int) -> dict:
    cfg = _require_config()
    try:
        resp = requests.post(
            f"{cfg['base_url']}/external/api/log-usage",
            json={"adom": adom, "devices": devices, "policyid": policy_id, "days": days},
            headers={"Authorization": f"Bearer {cfg['token']}"},
            verify=cfg.get("verify_ssl", True),
            timeout=90,
        )
    except requests.RequestException as exc:
        raise LogUsageError(f"Could not reach 4tlog: {exc}") from exc

    if resp.status_code == 401:
        raise LogUsageError("4tlog rejected the configured token")
    if resp.status_code == 503:
        raise LogUsageError("4tlog's external API is disabled")
    if resp.status_code >= 400:
        try:
            msg = resp.json().get("error", resp.text)
        except ValueError:
            msg = resp.text
        raise LogUsageError(f"4tlog returned an error: {msg}")

    try:
        return resp.json()
    except ValueError as exc:
        raise LogUsageError("4tlog returned an invalid response") from exc


def test_connection() -> dict:
    """Lightweight reachability/auth probe for the Admin 'Test Connection'
    button -- calls 4tlog's existing executive/summary endpoint rather than
    running a real log search."""
    cfg = load_log_source_config()
    base_url = (cfg.get("base_url") or "").rstrip("/")
    token = cfg.get("token") or ""
    if not base_url or not token:
        return {"ok": False, "error": "Base URL and token are required"}
    try:
        resp = requests.get(
            f"{base_url}/external/api/executive/summary",
            headers={"Authorization": f"Bearer {token}"},
            verify=cfg.get("verify_ssl", True),
            timeout=10,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}
    if resp.status_code == 200:
        return {"ok": True, "error": None}
    if resp.status_code == 401:
        return {"ok": False, "error": "Token rejected by 4tlog"}
    if resp.status_code == 503:
        return {"ok": False, "error": "4tlog's external API is disabled"}
    return {"ok": False, "error": f"Unexpected response: {resp.status_code}"}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_log_usage_client.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add app/log_usage_client.py tests/test_log_usage_client.py
git commit -m "$(cat <<'EOF'
feat: add log_usage_client for calling 4tlog's log-usage API

Thin bearer-token HTTP client; every failure mode (not configured,
unreachable, unauthorized, bad response) raises LogUsageError so
callers never see a raw exception.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 3: `app/log_hygiene.py` — member classification helpers

**Files:**
- Create: `app/log_hygiene.py`
- Test: `tests/test_log_hygiene_classification.py`

**Interfaces:**
- Consumes: `app.hygiene._expand_group_members(groups: list[dict], direct_refs: set[str]) -> set[str]` (existing, already imported cross-module by `app/routes/hygiene_routes.py` — same established pattern).
- Produces: `_addr_object_host_ip(ao: dict) -> str | None`, `_service_single_port(so: dict) -> tuple[str, int] | None`, `_expand_addr_members(names: list[str], addr_objects: list[dict], addr_groups: list[dict]) -> tuple[list[dict], list[dict]]` (returns `(evaluated, not_evaluated)` where evaluated items are `{"name": str, "value": str}` and not_evaluated items are `{"name": str, "type": str}`), `_expand_service_members(names: list[str], svc_objects: list[dict], svc_groups: list[dict]) -> tuple[list[dict], list[dict]]` (evaluated items are `{"name": str, "proto": str, "port": int}`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_log_hygiene_classification.py

def test_addr_object_host_ip_single_host_ipmask_form():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "srv1", "subnet": "10.1.1.5 255.255.255.255"}
    assert _addr_object_host_ip(ao) == "10.1.1.5"


def test_addr_object_host_ip_single_host_cidr_form():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "srv1", "subnet": "10.1.1.5/32"}
    assert _addr_object_host_ip(ao) == "10.1.1.5"


def test_addr_object_host_ip_subnet_returns_none():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "net1", "subnet": "10.1.0.0 255.255.0.0"}
    assert _addr_object_host_ip(ao) is None


def test_addr_object_host_ip_range_returns_none():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "range1", "subnet": "10.1.1.1-10.1.1.10"}
    assert _addr_object_host_ip(ao) is None


def test_addr_object_host_ip_fqdn_returns_none():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "fqdn1"}
    assert _addr_object_host_ip(ao) is None


def test_service_single_port_plain_port():
    from app.log_hygiene import _service_single_port
    so = {"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}
    assert _service_single_port(so) == ("tcp", 443)


def test_service_single_port_colon_form():
    """FortiManager 'src:dst' portrange syntax: only the dst side matters."""
    from app.log_hygiene import _service_single_port
    so = {"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "0:443"}
    assert _service_single_port(so) == ("tcp", 443)


def test_service_single_port_range_returns_none():
    from app.log_hygiene import _service_single_port
    so = {"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8000-8100"}
    assert _service_single_port(so) is None


def test_service_single_port_udp():
    from app.log_hygiene import _service_single_port
    so = {"name": "svc1", "protocol": "TCP/UDP/SCTP", "udp-portrange": "53"}
    assert _service_single_port(so) == ("udp", 53)


def test_service_single_port_icmp_returns_none():
    from app.log_hygiene import _service_single_port
    so = {"name": "ping", "protocol": "ICMP"}
    assert _service_single_port(so) is None


def test_expand_addr_members_direct_host():
    from app.log_hygiene import _expand_addr_members
    addr_objects = [{"name": "srv1", "subnet": "10.1.1.5 255.255.255.255"}]
    evaluated, not_evaluated = _expand_addr_members(["srv1"], addr_objects, [])
    assert evaluated == [{"name": "srv1", "value": "10.1.1.5"}]
    assert not_evaluated == []


def test_expand_addr_members_via_group_and_direct_dedup():
    """A leaf reachable both directly on the rule and via a nested group
    must appear exactly once."""
    from app.log_hygiene import _expand_addr_members
    addr_objects = [
        {"name": "srv1", "subnet": "10.1.1.5 255.255.255.255"},
        {"name": "srv2", "subnet": "10.1.1.6 255.255.255.255"},
    ]
    addr_groups = [{"name": "grp1", "member": [{"name": "srv1"}, {"name": "srv2"}]}]
    evaluated, not_evaluated = _expand_addr_members(["grp1", "srv1"], addr_objects, addr_groups)
    names = sorted(e["name"] for e in evaluated)
    assert names == ["srv1", "srv2"]
    assert not_evaluated == []


def test_expand_addr_members_subnet_goes_to_not_evaluated():
    from app.log_hygiene import _expand_addr_members
    addr_objects = [{"name": "net1", "subnet": "10.1.0.0 255.255.0.0"}]
    evaluated, not_evaluated = _expand_addr_members(["net1"], addr_objects, [])
    assert evaluated == []
    assert not_evaluated == [{"name": "net1", "type": "ipmask"}]


def test_expand_addr_members_unresolved_name_goes_to_not_evaluated():
    from app.log_hygiene import _expand_addr_members
    evaluated, not_evaluated = _expand_addr_members(["all"], [], [])
    assert evaluated == []
    assert not_evaluated == [{"name": "all", "type": "unresolved"}]


def test_expand_service_members_single_port():
    from app.log_hygiene import _expand_service_members
    svc_objects = [{"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}]
    evaluated, not_evaluated = _expand_service_members(["svc1"], svc_objects, [])
    assert evaluated == [{"name": "svc1", "proto": "tcp", "port": 443}]
    assert not_evaluated == []


def test_expand_service_members_group_expansion():
    from app.log_hygiene import _expand_service_members
    svc_objects = [
        {"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
        {"name": "svc2", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8443"},
    ]
    svc_groups = [{"name": "grp1", "member": [{"name": "svc1"}, {"name": "svc2"}]}]
    evaluated, not_evaluated = _expand_service_members(["grp1"], svc_objects, svc_groups)
    ports = sorted(e["port"] for e in evaluated)
    assert ports == [443, 8443]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_log_hygiene_classification.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.log_hygiene'`

- [ ] **Step 3: Implement the classification helpers in `app/log_hygiene.py`**

```python
"""Log-Based Rule Review check engine -- purely local FMG-data logic plus
one call out to 4tlog's log-usage API. Never writes to FortiManager,
FortiGate, or 4tlog."""

from __future__ import annotations

import ipaddress

from app.fmg_helpers import make_client
from app.hygiene import _expand_group_members
from app.log_usage_client import LogUsageError, get_rule_log_usage


class LogHygieneError(Exception):
    """Raised for FMG-side problems this check can't proceed past: the rule
    no longer exists in the package, or the package has no device scope."""


def _addr_object_host_ip(ao: dict) -> str | None:
    """Return the single host IP string if this address object resolves to
    exactly one /32, else None (subnet, range, FQDN, or unparseable)."""
    subnet = ao.get("subnet") or ao.get("ip-range") or ""
    if isinstance(subnet, list):
        subnet = " ".join(str(x) for x in subnet)
    subnet = str(subnet).strip()
    if not subnet:
        return None
    parts = subnet.split()
    try:
        if len(parts) == 2:
            net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
        elif "/" in subnet and len(parts) == 1:
            net = ipaddress.ip_network(subnet, strict=False)
        else:
            return None  # iprange ("start-end") or other unresolvable format
    except ValueError:
        return None
    if net.num_addresses == 1:
        return str(net.network_address)
    return None


def _service_single_port(so: dict) -> tuple[str, int] | None:
    """Return (proto, port) if this service object resolves to exactly one
    discrete TCP or UDP port, else None (range, multi-entry, or a protocol
    other than TCP/UDP)."""
    tcp_r = str(so.get("tcp-portrange") or "").strip()
    udp_r = str(so.get("udp-portrange") or "").strip()
    if tcp_r and udp_r:
        return None  # both set -- ambiguous which single port was meant
    raw, proto = (tcp_r, "tcp") if tcp_r else (udp_r, "udp")
    if not raw or " " in raw:
        return None  # empty, or multiple space-separated entries
    if ":" in raw:
        raw = raw.split(":", 1)[1]  # "src:dst" -- only dst matters
    if "-" in raw:
        return None  # port range
    try:
        return proto, int(raw)
    except ValueError:
        return None


def _expand_members(
    names: list[str],
    objects: list[dict],
    groups: list[dict],
    classify,
) -> tuple[list[dict], list[dict]]:
    """Shared BFS-expansion + classification for both address and service
    fields. `classify(obj)` returns the evaluated dict's extra fields (minus
    "name") on success, or None to route the object to not_evaluated."""
    by_name = {o.get("name"): o for o in objects if isinstance(o, dict) and o.get("name")}
    group_names = {g.get("name") for g in groups if isinstance(g, dict) and g.get("name")}
    direct = {n for n in names if n}
    reachable = _expand_group_members(groups, direct)
    leaf_names = (direct | reachable) - group_names

    evaluated: list[dict] = []
    not_evaluated: list[dict] = []
    for name in sorted(leaf_names):
        obj = by_name.get(name)
        if obj is None:
            not_evaluated.append({"name": name, "type": "unresolved"})
            continue
        extra = classify(obj)
        if extra is not None:
            evaluated.append({"name": name, **extra})
        else:
            not_evaluated.append({"name": name, "type": str(obj.get("type") or obj.get("protocol") or "ipmask")})
    return evaluated, not_evaluated


def _expand_addr_members(
    names: list[str], addr_objects: list[dict], addr_groups: list[dict]
) -> tuple[list[dict], list[dict]]:
    def classify(ao: dict) -> dict | None:
        host_ip = _addr_object_host_ip(ao)
        return {"value": host_ip} if host_ip is not None else None

    return _expand_members(names, addr_objects, addr_groups, classify)


def _expand_service_members(
    names: list[str], svc_objects: list[dict], svc_groups: list[dict]
) -> tuple[list[dict], list[dict]]:
    def classify(so: dict) -> dict | None:
        single = _service_single_port(so)
        return {"proto": single[0], "port": single[1]} if single is not None else None

    return _expand_members(names, svc_objects, svc_groups, classify)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_log_hygiene_classification.py -v`
Expected: PASS (16 tests)

- [ ] **Step 5: Commit**

```bash
git add app/log_hygiene.py tests/test_log_hygiene_classification.py
git commit -m "$(cat <<'EOF'
feat: add address/service member classification for log hygiene

Classifies each resolved leaf member of a rule's src/dst/service fields
as an evaluable single host/port or an informational "not evaluated"
object (subnet, range, FQDN, multi-port service), reusing
app.hygiene._expand_group_members for group BFS expansion.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 4: `app/log_hygiene.py::check_rule_log_usage` — orchestration

**Files:**
- Modify: `app/log_hygiene.py` (append)
- Test: `tests/test_log_hygiene_check.py`

**Interfaces:**
- Consumes: `_expand_addr_members`, `_expand_service_members` (Task 3); `app.log_usage_client.get_rule_log_usage(adom, devices, policy_id, days) -> dict` and `LogUsageError` (Task 2); `app.fmg_helpers.make_client()` (existing context-manager client factory, same one `app/routes/hygiene_routes.py` uses); `FMGClient.get_policies`, `get_address_objects`, `get_address_groups`, `get_service_objects`, `get_service_groups`, `get_pkg_scope_members` (existing, `app/fmg_client.py`).
- Produces: `LogHygieneError` (Task 3, already defined); `check_rule_log_usage(adom: str, pkg: str, policy_id: int, days: int) -> dict` returning the shape documented in the spec (`rule`, `days`, `time_range`, `log_count`, `truncated`, `devices_queried`, `devices_not_found`, `source`, `destination`, `service`, each of the latter three being `{"evaluated": [...], "not_evaluated": [...]}` with evaluated entries carrying an added `"status": "used"|"unused"` key).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_log_hygiene_check.py
from unittest.mock import MagicMock, patch

import pytest


def _mock_client(policies, addr_objects=None, addr_groups=None,
                  svc_objects=None, svc_groups=None, scope=None):
    client = MagicMock()
    client.get_policies.return_value = policies
    client.get_address_objects.return_value = addr_objects or []
    client.get_address_groups.return_value = addr_groups or []
    client.get_service_objects.return_value = svc_objects or []
    client.get_service_groups.return_value = svc_groups or []
    client.get_pkg_scope_members.return_value = scope or [{"name": "FW01", "vdom": "root"}]
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    return client


def test_check_rule_log_usage_rule_not_found_raises():
    from app.log_hygiene import LogHygieneError, check_rule_log_usage
    client = _mock_client(policies=[{"policyid": 1, "name": "Other"}])
    with patch("app.log_hygiene.make_client", return_value=client):
        with pytest.raises(LogHygieneError, match="not found"):
            check_rule_log_usage("ADOM", "pkg", 999, 30)


def test_check_rule_log_usage_no_device_scope_raises():
    from app.log_hygiene import LogHygieneError, check_rule_log_usage
    client = _mock_client(policies=[{"policyid": 1, "name": "Rule1"}], scope=[])
    with patch("app.log_hygiene.make_client", return_value=client):
        with pytest.raises(LogHygieneError, match="not installed on any device"):
            check_rule_log_usage("ADOM", "pkg", 1, 30)


def test_check_rule_log_usage_days_clamped_high():
    from app.log_hygiene import check_rule_log_usage
    client = _mock_client(policies=[{"policyid": 1, "name": "Rule1", "srcaddr": [], "dstaddr": [], "service": []}])
    usage = {"srcips": [], "dstips": [], "dstports": [], "time_range": {}, "log_count": 0,
              "truncated": False, "devices_queried": ["FW01"], "devices_not_found": []}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage) as mock_get:
        check_rule_log_usage("ADOM", "pkg", 1, 999)
    assert mock_get.call_args.args[3] == 60


def test_check_rule_log_usage_days_clamped_low():
    from app.log_hygiene import check_rule_log_usage
    client = _mock_client(policies=[{"policyid": 1, "name": "Rule1", "srcaddr": [], "dstaddr": [], "service": []}])
    usage = {"srcips": [], "dstips": [], "dstports": [], "time_range": {}, "log_count": 0,
              "truncated": False, "devices_queried": ["FW01"], "devices_not_found": []}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage) as mock_get:
        check_rule_log_usage("ADOM", "pkg", 1, -5)
    assert mock_get.call_args.args[3] == 1


def test_check_rule_log_usage_full_diff():
    from app.log_hygiene import check_rule_log_usage
    policies = [{
        "policyid": 42, "name": "Allow-DC-to-App",
        "srcaddr": [{"name": "srv1"}, {"name": "srv2"}],
        "dstaddr": [{"name": "srv3"}],
        "service": [{"name": "svc-https"}],
    }]
    addr_objects = [
        {"name": "srv1", "subnet": "10.1.1.5 255.255.255.255"},
        {"name": "srv2", "subnet": "10.1.1.6 255.255.255.255"},
        {"name": "srv3", "subnet": "10.2.2.10 255.255.255.255"},
    ]
    svc_objects = [{"name": "svc-https", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}]
    client = _mock_client(policies=policies, addr_objects=addr_objects, svc_objects=svc_objects)
    usage = {
        "srcips": ["10.1.1.5"], "dstips": ["10.2.2.10"], "dstports": [443],
        "time_range": {"start": "a", "end": "b"}, "log_count": 10, "truncated": False,
        "devices_queried": ["FW01"], "devices_not_found": [],
    }
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage):
        result = check_rule_log_usage("ADOM", "pkg", 42, 30)

    assert result["rule"] == {"policy_id": 42, "name": "Allow-DC-to-App"}
    assert result["truncated"] is False
    assert result["log_count"] == 10
    src_by_name = {e["name"]: e["status"] for e in result["source"]["evaluated"]}
    assert src_by_name == {"srv1": "used", "srv2": "unused"}
    assert result["destination"]["evaluated"][0]["status"] == "used"
    assert result["service"]["evaluated"][0]["status"] == "used"


def test_check_rule_log_usage_propagates_truncated_flag():
    """truncated must reach the top-level result unchanged -- Review Focus item."""
    from app.log_hygiene import check_rule_log_usage
    policies = [{"policyid": 1, "name": "R", "srcaddr": [], "dstaddr": [], "service": []}]
    client = _mock_client(policies=policies)
    usage = {"srcips": [], "dstips": [], "dstports": [], "time_range": {}, "log_count": 5000,
              "truncated": True, "devices_queried": ["FW01"], "devices_not_found": ["FW02"]}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage):
        result = check_rule_log_usage("ADOM", "pkg", 1, 30)
    assert result["truncated"] is True
    assert result["devices_not_found"] == ["FW02"]


def test_check_rule_log_usage_log_usage_error_propagates():
    from app.log_hygiene import check_rule_log_usage
    from app.log_usage_client import LogUsageError
    policies = [{"policyid": 1, "name": "R", "srcaddr": [], "dstaddr": [], "service": []}]
    client = _mock_client(policies=policies)
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", side_effect=LogUsageError("unreachable")):
        with pytest.raises(LogUsageError, match="unreachable"):
            check_rule_log_usage("ADOM", "pkg", 1, 30)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_log_hygiene_check.py -v`
Expected: FAIL with `ImportError: cannot import name 'check_rule_log_usage'`

- [ ] **Step 3: Append `check_rule_log_usage` to `app/log_hygiene.py`**

```python
def _names(val) -> list[str]:
    if not val:
        return []
    if isinstance(val, str):
        return [val]
    return [(i.get("name", str(i)) if isinstance(i, dict) else str(i)) for i in val]


def check_rule_log_usage(adom: str, pkg: str, policy_id: int, days: int) -> dict:
    days = max(1, min(60, int(days)))

    with make_client() as client:
        policies = client.get_policies(adom, pkg)
        rule = next(
            (p for p in policies if isinstance(p, dict) and int(p.get("policyid", -1)) == policy_id),
            None,
        )
        if rule is None:
            raise LogHygieneError(
                f"Rule {policy_id} not found in package '{pkg}' -- it may have "
                "been renamed or removed since the package was last loaded"
            )

        addr_objects = client.get_address_objects(adom)
        addr_groups = client.get_address_groups(adom)
        svc_objects = client.get_service_objects(adom)
        svc_groups = client.get_service_groups(adom)
        scope = client.get_pkg_scope_members(adom, pkg)

    devices = sorted({
        m.get("name") for m in scope if isinstance(m, dict) and m.get("name")
    })
    if not devices:
        raise LogHygieneError("Policy package is not installed on any device -- no logs to check")

    src_eval, src_not_eval = _expand_addr_members(
        _names(rule.get("srcaddr") or rule.get("src_addr")), addr_objects, addr_groups
    )
    dst_eval, dst_not_eval = _expand_addr_members(
        _names(rule.get("dstaddr") or rule.get("dst_addr")), addr_objects, addr_groups
    )
    svc_eval, svc_not_eval = _expand_service_members(
        _names(rule.get("service") or rule.get("services")), svc_objects, svc_groups
    )

    usage = get_rule_log_usage(adom, devices, policy_id, days)

    observed_srcips = set(usage.get("srcips") or [])
    observed_dstips = set(usage.get("dstips") or [])
    observed_ports = set(usage.get("dstports") or [])

    def _mark(evaluated: list[dict], key: str, observed: set) -> list[dict]:
        return [
            {**m, "status": "used" if m[key] in observed else "unused"}
            for m in evaluated
        ]

    return {
        "rule": {"policy_id": policy_id, "name": rule.get("name") or ""},
        "days": days,
        "time_range": usage.get("time_range") or {},
        "log_count": usage.get("log_count", 0),
        "truncated": bool(usage.get("truncated")),
        "devices_queried": usage.get("devices_queried") or [],
        "devices_not_found": usage.get("devices_not_found") or [],
        "source": {
            "evaluated": _mark(src_eval, "value", observed_srcips),
            "not_evaluated": src_not_eval,
        },
        "destination": {
            "evaluated": _mark(dst_eval, "value", observed_dstips),
            "not_evaluated": dst_not_eval,
        },
        "service": {
            "evaluated": _mark(svc_eval, "port", observed_ports),
            "not_evaluated": svc_not_eval,
        },
    }
```

Note: `get_rule_log_usage` and `LogUsageError` were already imported at the top of `app/log_hygiene.py` in Task 3's Step 3 (`from app.log_usage_client import LogUsageError, get_rule_log_usage`) — no new import needed here.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_log_hygiene_check.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add app/log_hygiene.py tests/test_log_hygiene_check.py
git commit -m "$(cat <<'EOF'
feat: add check_rule_log_usage orchestration to log_hygiene

Fetches one rule from FMG, expands its address/service members, calls
4tlog for observed traffic, and diffs configured members against it.
Clamps days to [1, 60] and raises LogHygieneError for a stale rule or
a package with no device scope.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 5: Admin API — `/admin/api/log-source*` routes

**Files:**
- Modify: `app/routes/admin_routes.py`
- Test: `tests/test_admin_log_source_routes.py`

**Interfaces:**
- Consumes: `app.log_source.load_log_source_config` / `save_log_source_config` (Task 1); `app.log_usage_client.test_connection` (Task 2).
- Produces: `GET /admin/api/log-source`, `PUT /admin/api/log-source`, `POST /admin/api/log-source/test` — all `admin_required`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_admin_log_source_routes.py
import json
import time
from unittest.mock import patch

import pytest


@pytest.fixture
def app():
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


def _put(client, url, payload):
    return client.put(
        url, data=json.dumps(payload), content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )


def test_get_log_source_masks_token(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({
        "enabled": True, "base_url": "https://4tlog:5443",
        "token": "real-secret", "verify_ssl": True,
    })
    resp = client.get("/admin/api/log-source")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["token"] == "••••••"
    assert data["base_url"] == "https://4tlog:5443"


def test_get_log_source_empty_token_stays_empty(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    resp = client.get("/admin/api/log-source")
    assert resp.get_json()["token"] == ""


def test_put_log_source_saves_new_token(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    resp = _put(client, "/admin/api/log-source", {
        "enabled": True, "base_url": "https://4tlog:5443",
        "token": "brand-new-token", "verify_ssl": False,
    })
    assert resp.status_code == 200
    cfg = log_source.load_log_source_config()
    assert cfg["token"] == "brand-new-token"
    assert cfg["verify_ssl"] is False


def test_put_log_source_masked_placeholder_preserves_existing_token(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({
        "enabled": True, "base_url": "https://old:5443",
        "token": "original-token", "verify_ssl": True,
    })
    _put(client, "/admin/api/log-source", {
        "enabled": True, "base_url": "https://new:5443",
        "token": "••••••", "verify_ssl": True,
    })
    cfg = log_source.load_log_source_config()
    assert cfg["token"] == "original-token"
    assert cfg["base_url"] == "https://new:5443"


def test_log_source_test_connection_route(client):
    with patch("app.log_usage_client.test_connection", return_value={"ok": True, "error": None}):
        resp = client.post("/admin/api/log-source/test",
                            headers={"X-CSRF-Token": "test-csrf"})
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True, "error": None}


def test_log_source_routes_require_admin(app):
    non_admin_users = {"viewer": {"password_hash": "$2b$12$placeholder", "role": "viewer"}}
    with app.test_client() as c, patch("app.auth._load_users", return_value=non_admin_users):
        with c.session_transaction() as sess:
            sess["user"] = "viewer"
            sess["role"] = "viewer"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        resp = c.get("/admin/api/log-source")
    assert resp.status_code in (302, 403)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_admin_log_source_routes.py -v`
Expected: FAIL with 404s (routes don't exist yet)

- [ ] **Step 3: Add the routes to `app/routes/admin_routes.py`**

Add to the imports block near the top (alongside the existing `from app import smtp_client as _smtp`):

```python
from app import log_source as _log_source
from app.log_usage_client import test_connection as _log_usage_test_connection
```

Add near the SMTP routes (after the `# ── Config-Diff: SMTP ──` section):

```python
# ── Log Hygiene: 4tlog connection ──────────────────────────────────────────


@bp.route("/api/log-source")
@_admin_required
def admin_log_source_get():
    cfg = _log_source.load_log_source_config()
    cfg["token"] = "••••••" if cfg.get("token") else ""
    return jsonify(cfg)


@bp.route("/api/log-source", methods=["PUT"])
@_admin_required
def admin_log_source_put():
    data = request.get_json(force=True) or {}
    existing = _log_source.load_log_source_config()
    if data.get("token") == "••••••":
        data["token"] = existing.get("token", "")
    _log_source.save_log_source_config(data)
    app_log("INFO", "admin", "Log source config updated", by=session["user"])
    return jsonify({"ok": True})


@bp.route("/api/log-source/test", methods=["POST"])
@_admin_required
def admin_log_source_test():
    result = _log_usage_test_connection()
    return jsonify(result)
```

Also add the three routes to the module docstring's endpoint list, next to the SMTP section, matching the existing documentation convention in that file's header.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_admin_log_source_routes.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add app/routes/admin_routes.py tests/test_admin_log_source_routes.py
git commit -m "$(cat <<'EOF'
feat: add Admin API routes for 4tlog connection settings

GET/PUT /admin/api/log-source (token masked on read, preserved on a
masked-placeholder PUT, same convention as the SMTP password field)
and POST /admin/api/log-source/test for a reachability probe.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 6: Admin UI — Log Hygiene sub-tab

**Files:**
- Modify: `app/templates/admin.html`
- Modify: `app/static/js/admin.js`

**Interfaces:**
- Consumes: `GET/PUT /admin/api/log-source`, `POST /admin/api/log-source/test` (Task 5).

- [ ] **Step 1: Add the sub-tab button**

In `app/templates/admin.html`, in the `#adminTabs` block, add after the AI Assist button:

```html
  <button class="admin-tab" data-panel="log-hygiene">Log Hygiene</button>
```

- [ ] **Step 2: Add the panel markup**

In `app/templates/admin.html`, add a new panel after `panel-ai-assist`'s closing `</div>` (before the `<!-- CONFIG-DIFF PANEL -->` comment):

```html
<!-- ══════════════════════  LOG HYGIENE PANEL  ══════════════════════ -->
<div class="admin-panel" id="panel-log-hygiene">

  <div class="admin-panel-header">
    <div>
      <h3>Log Hygiene</h3>
      <p class="text-muted" style="font-size:.85rem;margin-top:.2rem">
        Connect to a 4tlog instance to power Audit Review's Log-Based Rule
        Review, which checks whether a rule's configured host members and
        service ports actually appeared in FortiAnalyzer traffic logs.
        Requires a bearer token created in 4tlog with its own External API
        enabled.
      </p>
    </div>
  </div>

  <div class="rr-form-grid" style="max-width:520px">
    <label for="logSourceBaseUrl">4tlog Base URL</label>
    <input type="text" id="logSourceBaseUrl" placeholder="https://4tlog.internal:5443">

    <label for="logSourceToken">API Token</label>
    <input type="password" id="logSourceToken" placeholder="Bearer token from 4tlog">

    <label for="logSourceVerifySsl">Verify SSL</label>
    <input type="checkbox" id="logSourceVerifySsl">

    <label for="logSourceEnabled">Enabled</label>
    <input type="checkbox" id="logSourceEnabled">
  </div>

  <div style="display:flex;align-items:center;gap:1rem;margin-top:1rem">
    <button class="btn btn-primary btn-sm" id="btnSaveLogSource">Save</button>
    <button class="btn btn-secondary btn-sm" id="btnTestLogSource">Test Connection</button>
    <span id="logSourceMsg" style="font-size:.83rem"></span>
  </div>
</div>
```

- [ ] **Step 3: Wire the sub-tab switch and load/save/test functions**

In `app/static/js/admin.js`, add to the sub-tab click handler (alongside the existing `if (btn.dataset.panel === 'ai-assist' ...)` line):

```javascript
      if (btn.dataset.panel === 'log-hygiene' && !_logHygieneLoaded) loadLogHygiene();
```

Add a module-level flag near the other `_xLoaded` flags (e.g. near `_aiAssistLoaded`):

```javascript
  let _logHygieneLoaded = false;
```

Add the load/save/test functions (place near `loadSMTP`/`saveSMTP` for proximity to the pattern they mirror):

```javascript
async function loadLogHygiene() {
  _logHygieneLoaded = true;
  const res = await fetch('/admin/api/log-source');
  if (res.status === 401) { location.href = '/login'; return; }
  const cfg = await res.json();
  document.getElementById('logSourceBaseUrl').value   = cfg.base_url || '';
  document.getElementById('logSourceToken').value     = cfg.token || '';
  document.getElementById('logSourceVerifySsl').checked = !!cfg.verify_ssl;
  document.getElementById('logSourceEnabled').checked   = !!cfg.enabled;
}

async function saveLogSource() {
  const msg = document.getElementById('logSourceMsg');
  const payload = {
    base_url:    document.getElementById('logSourceBaseUrl').value.trim(),
    token:       document.getElementById('logSourceToken').value,
    verify_ssl:  document.getElementById('logSourceVerifySsl').checked,
    enabled:     document.getElementById('logSourceEnabled').checked,
  };
  const res = await fetch('/admin/api/log-source', { method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken() },
    body: JSON.stringify(payload) });
  msg.textContent = res.ok ? 'Saved.' : 'Save failed.';
  msg.style.color = res.ok ? 'var(--success)' : 'var(--danger)';
}

async function testLogSource() {
  const msg = document.getElementById('logSourceMsg');
  msg.textContent = 'Testing…';
  msg.style.color = '';
  const res = await fetch('/admin/api/log-source/test', { method: 'POST',
    headers: { 'X-CSRF-Token': _csrfToken() } });
  const result = await res.json();
  msg.textContent = result.ok ? 'Connection OK.' : `Failed: ${result.error}`;
  msg.style.color = result.ok ? 'var(--success)' : 'var(--danger)';
}

document.getElementById('btnSaveLogSource')?.addEventListener('click', saveLogSource);
document.getElementById('btnTestLogSource')?.addEventListener('click', testLogSource);
```

Check `admin.js` for the existing CSRF-token accessor used by `saveSMTP`'s `fetch` call (look at the code immediately around the `admin_smtp_put`-calling fetch in `saveSMTP()`) and use that exact helper/expression in place of `_csrfToken()` above if the name differs — match whatever this file already uses everywhere else, don't introduce a second convention.

- [ ] **Step 4: Manually verify in the browser**

Run: `uv run python wsgi.py`, log in as an admin user, open Admin → Log Hygiene, enter a base URL and token, click Save, reload the page and confirm the token shows as masked dots, click Test Connection against an unreachable URL and confirm an error message appears (no 4tlog instance needs to be running yet — confirming the error path renders correctly is sufficient for this task).

- [ ] **Step 5: Commit**

```bash
git add app/templates/admin.html app/static/js/admin.js
git commit -m "$(cat <<'EOF'
feat: add Log Hygiene admin sub-tab for 4tlog connection settings

Base URL / token / verify-SSL / enabled fields plus a Test Connection
button, mirroring the SMTP settings panel's layout and JS pattern.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 7: Audit Review API — status + check routes

**Files:**
- Modify: `app/routes/audit_review_routes.py`
- Modify: `app/routes/hygiene_routes.py:44` (extend `hygiene_packages`' sibling `/api/hygiene/policies` route's tab gate)
- Test: `tests/test_audit_review_log_usage_routes.py`

**Interfaces:**
- Consumes: `app.log_hygiene.check_rule_log_usage`, `LogHygieneError` (Task 4); `app.log_usage_client.LogUsageError` (Task 2); `app.log_source.load_log_source_config` (Task 1).
- Produces: `GET /api/audit-review/log-usage-status`, `POST /api/audit-review/log-usage-check`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_audit_review_log_usage_routes.py
import json
import time
from unittest.mock import patch

import pytest


@pytest.fixture
def app():
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
    return client.post(
        url, data=json.dumps(payload), content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )


def test_log_usage_status_unavailable_by_default(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    resp = client.get("/api/audit-review/log-usage-status")
    assert resp.get_json() == {"available": False}


def test_log_usage_status_available_when_configured(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({
        "enabled": True, "base_url": "https://4tlog:5443", "token": "tok", "verify_ssl": True,
    })
    resp = client.get("/api/audit-review/log-usage-status")
    assert resp.get_json() == {"available": True}


def test_log_usage_check_disabled_returns_503(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    resp = _post(client, "/api/audit-review/log-usage-check",
                 {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 30})
    assert resp.status_code == 503


def test_log_usage_check_missing_fields_returns_400(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    resp = _post(client, "/api/audit-review/log-usage-check", {"adom": "ADOM"})
    assert resp.status_code == 400


def test_log_usage_check_clamps_days_out_of_range(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    with patch("app.log_hygiene.check_rule_log_usage", return_value={"ok": True}) as mock_check:
        _post(client, "/api/audit-review/log-usage-check",
              {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 9999})
    assert mock_check.call_args.args == ("ADOM", "pkg", 1, 60)


def test_log_usage_check_success(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    fake_result = {"rule": {"policy_id": 1, "name": "R"}, "days": 30}
    with patch("app.log_hygiene.check_rule_log_usage", return_value=fake_result):
        resp = _post(client, "/api/audit-review/log-usage-check",
                     {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 30})
    assert resp.status_code == 200
    assert resp.get_json() == fake_result


def test_log_usage_check_stale_rule_returns_400(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    from app.log_hygiene import LogHygieneError
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    with patch("app.log_hygiene.check_rule_log_usage", side_effect=LogHygieneError("Rule 1 not found")):
        resp = _post(client, "/api/audit-review/log-usage-check",
                     {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 30})
    assert resp.status_code == 400
    assert "not found" in resp.get_json()["error"]


def test_log_usage_check_upstream_failure_returns_502(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    from app.log_usage_client import LogUsageError
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    with patch("app.log_hygiene.check_rule_log_usage", side_effect=LogUsageError("unreachable")):
        resp = _post(client, "/api/audit-review/log-usage-check",
                     {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 30})
    assert resp.status_code == 502
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_audit_review_log_usage_routes.py -v`
Expected: FAIL with 404s (routes don't exist yet)

- [ ] **Step 3: Add the routes to `app/routes/audit_review_routes.py`**

Add near the end of the file (after the AI Summary section):

```python
# ── Log-Based Rule Review ────────────────────────────────────────────────


@bp.route("/api/audit-review/log-usage-status")
@tab_required("audit_review")
def log_usage_status():
    from app.log_source import load_log_source_config

    cfg = load_log_source_config()
    available = bool(cfg.get("enabled") and cfg.get("base_url") and cfg.get("token"))
    return jsonify({"available": available})


@bp.route("/api/audit-review/log-usage-check", methods=["POST"])
@tab_required("audit_review")
def log_usage_check():
    from app.log_hygiene import LogHygieneError, check_rule_log_usage
    from app.log_source import load_log_source_config
    from app.log_usage_client import LogUsageError

    cfg = load_log_source_config()
    if not (cfg.get("enabled") and cfg.get("base_url") and cfg.get("token")):
        return jsonify(
            {"error": "Log Hygiene is not enabled — configure it in Admin → Log Hygiene"}
        ), 503

    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    pkg = (data.get("pkg") or data.get("package") or "").strip()
    policy_id_raw = data.get("policy_id")
    days_raw = data.get("days")

    if not adom or not pkg or policy_id_raw is None:
        return jsonify({"error": "adom, pkg, and policy_id are required"}), 400
    if err := check_adom_access(adom):
        return err
    try:
        policy_id = int(policy_id_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "policy_id must be an integer"}), 400
    try:
        days = int(days_raw)
    except (TypeError, ValueError):
        days = 30
    days = max(1, min(60, days))

    try:
        result = check_rule_log_usage(adom, pkg, policy_id, days)
    except LogHygieneError as exc:
        return jsonify({"error": str(exc)}), 400
    except LogUsageError as exc:
        return jsonify({"error": str(exc)}), 502
    except FMGError as exc:
        return upstream_api_error("audit_review", exc)
    except Exception as exc:
        return internal_api_error("audit_review", exc)

    app_log(
        "INFO", "audit_review", "Log usage check completed",
        by=session["user"], adom=adom, pkg=pkg, policy_id=policy_id, days=days,
    )
    return jsonify(result)
```

Also add these two routes to the module docstring's endpoint list at the top of the file.

- [ ] **Step 4: Extend `/api/hygiene/policies`'s tab gate for the rule picker**

In `app/routes/hygiene_routes.py`, the `hygiene_policies` route (used by the new Audit Review section's rule picker to fetch rule names/IDs) is currently gated to `rule_hygiene` only, while its sibling `hygiene_packages` already allows both tabs. Change:

```python
@bp.route("/api/hygiene/policies", methods=["POST"])
@tab_required("rule_hygiene")
def hygiene_policies():
```

to:

```python
@bp.route("/api/hygiene/policies", methods=["POST"])
@tab_required("rule_hygiene", "audit_review")
def hygiene_policies():
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_audit_review_log_usage_routes.py -v`
Expected: PASS (8 tests)

- [ ] **Step 6: Run the full test suite to catch regressions from the tab-gate change**

Run: `uv run pytest tests/ -v -k "hygiene_policies or hygiene_routes"`
Expected: PASS, no existing test asserted `/api/hygiene/policies` rejects `audit_review`-tab users.

- [ ] **Step 7: Commit**

```bash
git add app/routes/audit_review_routes.py app/routes/hygiene_routes.py tests/test_audit_review_log_usage_routes.py
git commit -m "$(cat <<'EOF'
feat: add Audit Review log-usage-status and log-usage-check routes

Exposes check_rule_log_usage() over HTTP with the same never-500
error-mapping convention as every other AI/external integration in
this app. Also allows audit_review-tab users to call
/api/hygiene/policies (needed for the new section's rule picker),
matching the dual-tab gate already on /api/hygiene/.../packages.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 8: Audit Review UI — "Log-Based Rule Review" section

**Files:**
- Modify: `app/templates/audit_review.html`
- Modify: `app/static/js/audit_review.js`
- Modify: `app/static/css/style.css` (only if a needed class doesn't already exist — check before adding)

**Interfaces:**
- Consumes: `GET /api/audit-review/log-usage-status`, `POST /api/audit-review/log-usage-check` (Task 7); `GET /api/hygiene/adoms/<adom>/packages` (existing); `POST /api/hygiene/policies` (existing, now dual-gated by Task 7 Step 4).

- [ ] **Step 1: Add the section markup**

In `app/templates/audit_review.html`, add a new section after the Hygiene Analysis section's closing markup (find where that section's outermost `<div>` closes — locate it via its `rr-section-label` heading text "Hygiene Analysis" and insert immediately after that section's container ends):

```html
<!-- ═══════════════  LOG-BASED RULE REVIEW  ═══════════════ -->
<div class="rr-section-label" style="margin-top:2rem">Log-Based Rule Review</div>
<p class="admin-panel-desc" style="margin-bottom:1rem">
  Check whether a single rule's configured host members and service ports
  actually appeared in FortiAnalyzer traffic logs over a chosen day range.
</p>

<div id="logUsageDisabledNotice" class="text-muted" style="display:none;padding:.75rem 1rem;background:var(--surface-alt);border:1px solid var(--border);border-radius:6px;margin-bottom:1rem">
  Log Hygiene is not enabled. An admin can configure it under
  <strong>Admin &rarr; Log Hygiene</strong>.
</div>

<div class="rr-form-row" style="display:flex;gap:1rem;flex-wrap:wrap;align-items:end;margin-bottom:1rem">
  <div>
    <label for="logUsageAdom">ADOM</label>
    <select id="logUsageAdom"><option value="">&mdash; select ADOM &mdash;</option></select>
  </div>
  <div>
    <label for="logUsagePackage">Package</label>
    <select id="logUsagePackage" disabled><option value="">&mdash; select package &mdash;</option></select>
  </div>
  <div>
    <label for="logUsageRule">Rule</label>
    <select id="logUsageRule" disabled><option value="">&mdash; select rule &mdash;</option></select>
  </div>
  <div>
    <label for="logUsageDays">Days (1&ndash;60)</label>
    <input type="number" id="logUsageDays" min="1" max="60" value="30" style="width:80px">
  </div>
  <button class="btn btn-primary" id="logUsageRunBtn" disabled>Run</button>
</div>

<div id="logUsageRunning" style="display:none">Running log search&hellip; this can take up to a minute.</div>
<div id="logUsageError" class="text-danger" style="display:none"></div>

<div id="logUsageResults" style="display:none">
  <div id="logUsageHeader" style="margin-bottom:1rem"></div>
  <div id="logUsageWarnings" style="margin-bottom:1rem"></div>

  <h4>Source Members</h4>
  <table class="data-table"><thead><tr><th>Name</th><th>IP</th><th>Status</th></tr></thead>
    <tbody id="logUsageSrcBody"></tbody></table>
  <div id="logUsageSrcNotEval" class="text-muted" style="font-size:.82rem;margin:.5rem 0 1.5rem"></div>

  <h4>Destination Members</h4>
  <table class="data-table"><thead><tr><th>Name</th><th>IP</th><th>Status</th></tr></thead>
    <tbody id="logUsageDstBody"></tbody></table>
  <div id="logUsageDstNotEval" class="text-muted" style="font-size:.82rem;margin:.5rem 0 1.5rem"></div>

  <h4>Service Ports</h4>
  <table class="data-table"><thead><tr><th>Name</th><th>Port</th><th>Status</th></tr></thead>
    <tbody id="logUsageSvcBody"></tbody></table>
  <div id="logUsageSvcNotEval" class="text-muted" style="font-size:.82rem;margin:.5rem 0 1.5rem"></div>

  <button class="btn btn-secondary btn-sm" id="logUsageExportCsvBtn">Export CSV</button>
</div>
```

Check `app/static/css/style.css` for an existing `.data-table` class before relying on it (the Hygiene Analysis and other Audit Review tables already use a shared table class — find its exact name via `grep -n "class=\"data-table\|hygiene-table\|dr-table" app/templates/audit_review.html` and use whatever class name that file's other tables actually use, so the new tables inherit the same styling instead of introducing a second convention).

- [ ] **Step 2: Implement the JS logic**

In `app/static/js/audit_review.js`, add:

```javascript
/* ── Log-Based Rule Review ──────────────────────────────────────────────── */
let logUsagePkgPaths = {};
let logUsageRules = [];

async function checkLogUsageAvailability() {
  try {
    const resp = await fetch('/api/audit-review/log-usage-status');
    const data = await resp.json();
    const notice = document.getElementById('logUsageDisabledNotice');
    const runBtn = document.getElementById('logUsageRunBtn');
    if (!data.available) {
      notice.style.display = '';
      runBtn.disabled = true;
      runBtn.title = 'Log Hygiene is not enabled';
    } else {
      notice.style.display = 'none';
    }
  } catch (_) {}
}

async function loadLogUsageAdoms() {
  try {
    const resp = await fetch('/api/adoms');
    if (resp.status === 401) { location.href = '/login'; return; }
    const adoms = await resp.json();
    const sel = document.getElementById('logUsageAdom');
    if (!Array.isArray(adoms) || !sel) return;
    adoms.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.name; opt.textContent = a.name;
      sel.appendChild(opt);
    });
  } catch (_) {}
}

async function loadLogUsagePackages(adom) {
  const sel = document.getElementById('logUsagePackage');
  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;
  logUsagePkgPaths = {};
  resetLogUsageRulePicker();
  try {
    const resp = await fetch(`/api/hygiene/adoms/${encodeURIComponent(adom)}/packages`);
    const pkgs = await resp.json();
    sel.innerHTML = '<option value="">— select package —</option>';
    if (Array.isArray(pkgs)) {
      pkgs.forEach(p => {
        logUsagePkgPaths[p.name] = p.path || p.name;
        const opt = document.createElement('option');
        opt.value = p.name; opt.textContent = p.name;
        sel.appendChild(opt);
      });
    }
    sel.disabled = false;
  } catch (_) {
    sel.innerHTML = '<option value="">Failed to load packages</option>';
  }
}

function resetLogUsageRulePicker() {
  const sel = document.getElementById('logUsageRule');
  sel.innerHTML = '<option value="">— select rule —</option>';
  sel.disabled = true;
  document.getElementById('logUsageRunBtn').disabled = true;
  logUsageRules = [];
}

async function loadLogUsageRules(adom, pkg) {
  const sel = document.getElementById('logUsageRule');
  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;
  const path = logUsagePkgPaths[pkg] || pkg;
  try {
    const resp = await fetch('/api/hygiene/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ adom, package: path }),
    });
    const data = await resp.json();
    logUsageRules = (data.policies || []).filter(p => p.id && p.id !== 'implicit' && !p.policy_block);
    sel.innerHTML = '<option value="">— select rule —</option>';
    logUsageRules.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.id;
      opt.textContent = `${r.name || '(unnamed)'} (id: ${r.id})`;
      sel.appendChild(opt);
    });
    sel.disabled = false;
  } catch (_) {
    sel.innerHTML = '<option value="">Failed to load rules</option>';
  }
}

function _statusBadge(status) {
  const color = status === 'used' ? '#16a34a' : '#dc2626';
  return `<span class="hygiene-badge" style="background:${color}20;color:${color};border-color:${color}40">${status}</span>`;
}

function renderLogUsageResults(result) {
  document.getElementById('logUsageResults').style.display = '';
  document.getElementById('logUsageHeader').innerHTML =
    `<strong>${esc(result.rule.name)}</strong> (id: ${esc(String(result.rule.policy_id))}) &mdash; ` +
    `${result.days} days, ${result.log_count} log entries` +
    (result.time_range && result.time_range.start ? ` (${esc(result.time_range.start)} &ndash; ${esc(result.time_range.end)})` : '');

  const warnings = [];
  if (result.truncated) {
    warnings.push('<div class="text-danger">Log search hit its row limit &mdash; results may be incomplete.</div>');
  }
  if (result.devices_not_found && result.devices_not_found.length) {
    warnings.push(`<div class="text-danger">Devices not found in 4tlog: ${esc(result.devices_not_found.join(', '))}</div>`);
  }
  document.getElementById('logUsageWarnings').innerHTML = warnings.join('');

  const renderTable = (evaluated, bodyId, valueKey) => {
    document.getElementById(bodyId).innerHTML = evaluated.map(m =>
      `<tr><td>${esc(m.name)}</td><td>${esc(String(m[valueKey]))}</td><td>${_statusBadge(m.status)}</td></tr>`
    ).join('') || '<tr><td colspan="3" class="text-muted">None</td></tr>';
  };
  renderTable(result.source.evaluated, 'logUsageSrcBody', 'value');
  renderTable(result.destination.evaluated, 'logUsageDstBody', 'value');
  renderTable(result.service.evaluated, 'logUsageSvcBody', 'port');

  const renderNotEval = (notEvaluated, elId) => {
    document.getElementById(elId).textContent = notEvaluated.length
      ? `${notEvaluated.length} object(s) not evaluated: ${notEvaluated.map(o => `${o.name} (${o.type})`).join(', ')}`
      : '';
  };
  renderNotEval(result.source.not_evaluated, 'logUsageSrcNotEval');
  renderNotEval(result.destination.not_evaluated, 'logUsageDstNotEval');
  renderNotEval(result.service.not_evaluated, 'logUsageSvcNotEval');
}

async function runLogUsageCheck() {
  const adom = document.getElementById('logUsageAdom').value;
  const pkg = document.getElementById('logUsagePackage').value;
  const path = logUsagePkgPaths[pkg] || pkg;
  const policyId = document.getElementById('logUsageRule').value;
  const days = parseInt(document.getElementById('logUsageDays').value, 10) || 30;
  if (!adom || !pkg || !policyId) return;

  const errEl = document.getElementById('logUsageError');
  errEl.style.display = 'none';
  document.getElementById('logUsageResults').style.display = 'none';
  document.getElementById('logUsageRunBtn').disabled = true;
  document.getElementById('logUsageRunning').style.display = '';

  try {
    const resp = await fetch('/api/audit-review/log-usage-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ adom, pkg: path, policy_id: parseInt(policyId, 10), days }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      errEl.textContent = data.error || 'Log usage check failed.';
      errEl.style.display = '';
    } else {
      renderLogUsageResults(data);
    }
  } catch (_) {
    errEl.textContent = 'Log usage check failed.';
    errEl.style.display = '';
  } finally {
    document.getElementById('logUsageRunning').style.display = 'none';
    document.getElementById('logUsageRunBtn').disabled = false;
  }
}

document.addEventListener('DOMContentLoaded', function () {
  checkLogUsageAvailability();
  loadLogUsageAdoms();

  document.getElementById('logUsageAdom').addEventListener('change', function () {
    if (this.value) loadLogUsagePackages(this.value);
    else {
      document.getElementById('logUsagePackage').innerHTML = '<option value="">— select package —</option>';
      document.getElementById('logUsagePackage').disabled = true;
      resetLogUsageRulePicker();
    }
  });

  document.getElementById('logUsagePackage').addEventListener('change', function () {
    const adom = document.getElementById('logUsageAdom').value;
    if (this.value && adom) loadLogUsageRules(adom, this.value);
    else resetLogUsageRulePicker();
  });

  document.getElementById('logUsageRule').addEventListener('change', function () {
    document.getElementById('logUsageRunBtn').disabled = !this.value;
  });

  document.getElementById('logUsageRunBtn').addEventListener('click', runLogUsageCheck);
});
```

Confirm `esc()` is already a shared helper in `audit_review.js` (used elsewhere, e.g. Hygiene Analysis rendering) before relying on it here — if it lives in a different shared file, import/reference it the same way the rest of this file does.

- [ ] **Step 3: Add CSV export**

Add to the same `DOMContentLoaded` block:

```javascript
  document.getElementById('logUsageExportCsvBtn').addEventListener('click', exportLogUsageCsv);
```

Add the export function, following this app's existing "filter header block" export convention (package/ADOM/rule/days/timestamp header rows before the data):

```javascript
let _lastLogUsageResult = null;

function exportLogUsageCsv() {
  if (!_lastLogUsageResult) return;
  const r = _lastLogUsageResult;
  const lines = [
    `Rule,${r.rule.name},id:${r.rule.policy_id}`,
    `Days,${r.days}`,
    `Exported,${new Date().toISOString()}`,
    '',
    'Section,Name,Value,Status',
  ];
  const addRows = (section, evaluated, valueKey) => {
    evaluated.forEach(m => lines.push(`${section},${m.name},${m[valueKey]},${m.status}`));
  };
  addRows('Source', r.source.evaluated, 'value');
  addRows('Destination', r.destination.evaluated, 'value');
  addRows('Service', r.service.evaluated, 'port');
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `log-usage-${r.rule.policy_id}-${Date.now()}.csv`;
  a.click();
}
```

Update `renderLogUsageResults` to set `_lastLogUsageResult = result;` as its first line.

- [ ] **Step 4: Manually verify in the browser**

Run: `uv run python wsgi.py`, log in, open Audit Review, scroll to Log-Based Rule Review. With Log Hygiene disabled in Admin, confirm the disabled notice shows and Run stays disabled. Enable it in Admin with a dummy (unreachable) 4tlog URL, return to Audit Review, select an ADOM/package/rule, click Run, and confirm the error path renders a clear message (a real 4tlog instance isn't required to confirm this path works). Confirm the ADOM/package/rule cascading selects populate and reset correctly when changed.

- [ ] **Step 5: Commit**

```bash
git add app/templates/audit_review.html app/static/js/audit_review.js
git commit -m "$(cat <<'EOF'
feat: add Log-Based Rule Review section to Audit Review

ADOM/package/rule picker + day-range input, calls
/api/audit-review/log-usage-check and renders per-member Used/Unused
tables for source hosts, destination hosts, and service ports, with a
CSV export following this app's existing filter-header-block
convention.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 9: Documentation

**Files:**
- Modify: `CLAUDE.md`

**Interfaces:**
- Consumes: nothing (documentation-only task, references every prior task's output).

- [ ] **Step 1: Add a "Log-Based Rule Review" subsection to CLAUDE.md's Audit Review tab section**

Insert after the existing "Hygiene Analysis section" paragraph in the Audit Review tab section of `CLAUDE.md`, following the same documentation style/depth as the PSIRT Advisory Assessment subsection immediately below it:

```markdown
#### Log-Based Rule Review

New section on `/audit-review` (below Hygiene Analysis, above PSIRT
Advisory Assessment), single-rule scope: select ADOM + Policy Package +
one rule + a day range (1-60), and see which of that rule's configured
single-host address members and single-port service objects (including
members reached through address/service group expansion) actually
appeared in FortiAnalyzer traffic logs over that window. Subnets, IP
ranges, FQDN objects, `all`/`any`, and multi-port services are shown as
informational "not evaluated" entries — never flagged, since log IPs
can't meaningfully prove a subnet or range is unused.

Depends on a separate app, **4tlog** (`~/code/github/web/4tlog`), which
owns the FortiAnalyzer connection this feature needs. 4tlog exposes a
bearer-token-authenticated `POST /external/api/log-usage` endpoint
(same auth pattern as this app's own `/external/api/`) that runs a
`policyid`-scoped FAZ log search across the rule's package's device
scope and returns only the aggregated distinct source IPs, destination
IPs, and destination ports observed — never raw log rows. See
`docs/superpowers/specs/2026-09-23-log-usage-endpoint-design.md` for
that endpoint's contract (implemented in 4tlog's own repo, not here).

**Feature gate:** Admin → Log Hygiene — 4tlog base URL, bearer token,
and an `enabled` toggle, stored in `log_source_config.json` (gitignored;
copy `log_source_config.example.json`). Unlike `api_tokens.json` (which
hashes *inbound* tokens this app verifies), this token is stored
reversibly since this app sends it on every outbound call — same
convention as `infra_targets.json`'s per-device `"token"` field. A "Test
Connection" button probes 4tlog's existing `/external/api/executive/summary`
endpoint as a lightweight reachability/auth check.

**Check engine:** `app/log_hygiene.py::check_rule_log_usage(adom, pkg,
policy_id, days)` — fetches the rule from FMG, expands its
srcaddr/dstaddr/service fields via `app.hygiene._expand_group_members`
(BFS group expansion, same helper the Hygiene Analysis shadow/redundant/
unused-objects checks already use), classifies each resolved leaf as an
evaluable single host (`/32` address object) or single discrete TCP/UDP
port vs. an informational "not evaluated" object, resolves the
package's device scope via the existing `FMGClient.get_pkg_scope_members()`,
calls `app.log_usage_client.get_rule_log_usage()`, and diffs configured
members against the observed sets. `days` is always clamped server-side
to [1, 60]. Raises `LogHygieneError` for a stale/renamed rule id or a
package with no device scope; `app.log_usage_client.LogUsageError` for
any 4tlog-side failure (not configured, unreachable, unauthorized) — both
degrade to a clear JSON error, never a 500.

**API endpoints:**
- `GET  /api/audit-review/log-usage-status` — `{ available: bool }`,
  same contract shape as `ai-summary-status`
- `POST /api/audit-review/log-usage-check` — body
  `{ adom, pkg, policy_id, days }`, returns the diff result or a
  400/502/503 error object
```

- [ ] **Step 2: Run graphify update**

Run: `graphify update .`

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md graphify-out
git commit -m "$(cat <<'EOF'
docs: document Log-Based Rule Review feature in CLAUDE.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```
