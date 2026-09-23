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
