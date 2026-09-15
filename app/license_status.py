"""Shared FortiOS license-response parsing.

Used by both the live, single-device firewall detail panel
(app.routes.api_routes._assemble_health) and the fleet-wide daily sweep
(app.license_status_cache) so the "licensed / expired / unknown"
classification has one implementation.
Source: FortiOS's /api/v2/monitor/license/status response, proxied
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
