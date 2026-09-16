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

# FortiGuard subscription keys as returned alongside "forticare" in the same
# /api/v2/monitor/license/status results dict. Shared with the firewall
# detail panel's FortiGuard Subscriptions table (firewalls.js) and the
# Device Versions tab's FortiGuard grid (versions.js), which hardcode the
# same list client-side — keep the three in sync if FortiOS adds a new
# subscription type.
FORTIGUARD_SUBSCRIPTION_KEYS: tuple[str, ...] = (
    "antivirus",
    "ips",
    "web_filtering",
    "appctrl",
    "antispam",
    "outbreak_prevention",
    "firmware_updates",
    "forticloud_sandbox",
)


def _parse_subscriptions(results: dict, now: float) -> dict:
    """Classify each FortiGuard subscription entry in `results` into
    licensed/expired/none/unknown. Same "never guess, unknown covers every
    unexpected shape" convention as parse_license_payload's FortiCare
    parsing below. "none" means FortiOS explicitly reported no_license or
    free_license, not a fetch failure — kept distinct from "unknown" so the
    UI can tell "this device genuinely has no such subscription" apart from
    "we couldn't tell"."""
    subscriptions: dict[str, dict] = {}
    for key in FORTIGUARD_SUBSCRIPTION_KEYS:
        entry = results.get(key)
        if not isinstance(entry, dict):
            subscriptions[key] = {"status": "unknown", "expires": None}
            continue
        status = entry.get("status", "")
        expires_ts = entry.get("expires")
        is_real_number = isinstance(expires_ts, (int, float)) and not isinstance(
            expires_ts, bool
        )
        if status == "licensed":
            if is_real_number and expires_ts and expires_ts <= now:
                subscriptions[key] = {"status": "expired", "expires": None}
            elif is_real_number and expires_ts:
                exp_str = datetime.fromtimestamp(expires_ts, tz=UTC).strftime(
                    "%Y-%m-%d"
                )
                subscriptions[key] = {"status": "licensed", "expires": exp_str}
            else:
                subscriptions[key] = {"status": "licensed", "expires": None}
        elif status in ("no_license", "free_license"):
            subscriptions[key] = {"status": "none", "expires": None}
        else:
            subscriptions[key] = {"status": "unknown", "expires": None}
    return subscriptions


def parse_license_payload(raw_payload: dict | None) -> dict:
    """Classify a FortiOS license/status proxy payload.

    raw_payload is the already-unwrapped `results` dict FMGClient's
    _proxy() returns (i.e. `payload("license_status")` in api_routes.py,
    or the direct return of FMGClient.get_device_license_status()).

    Returns {"status": "licensed" | "expired" | "unknown", "expires":
    "YYYY-MM-DD" | None, "subscriptions": {key: {"status", "expires"},
    ...}}. "unknown" covers every failure mode for the FortiCare support
    status: missing/malformed forticare block, a non-"licensed" status
    string, or a "licensed" status with no expires timestamp — never
    fabricated. "subscriptions" is always present (each key defaults to
    "unknown" when its entry is missing/malformed) regardless of whether
    the FortiCare block itself parsed.
    """
    results = raw_payload if isinstance(raw_payload, dict) else {}
    now = time.time()
    subscriptions = _parse_subscriptions(results, now)

    forticare = results.get("forticare", {})
    if not isinstance(forticare, dict):
        return {"status": "unknown", "expires": None, "subscriptions": subscriptions}
    support = forticare.get("support", {})
    if not isinstance(support, dict):
        return {"status": "unknown", "expires": None, "subscriptions": subscriptions}
    enhanced = support.get("enhanced", {})
    if not isinstance(enhanced, dict):
        return {"status": "unknown", "expires": None, "subscriptions": subscriptions}
    status = enhanced.get("status", "")
    expires_ts = enhanced.get("expires")
    is_real_number = isinstance(expires_ts, (int, float)) and not isinstance(
        expires_ts, bool
    )
    if status == "licensed" and is_real_number and expires_ts:
        if expires_ts > now:
            exp_str = datetime.fromtimestamp(expires_ts, tz=UTC).strftime("%Y-%m-%d")
            return {
                "status": "licensed",
                "expires": exp_str,
                "subscriptions": subscriptions,
            }
        return {"status": "expired", "expires": None, "subscriptions": subscriptions}
    return {"status": "unknown", "expires": None, "subscriptions": subscriptions}
