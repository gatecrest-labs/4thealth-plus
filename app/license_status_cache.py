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

import logging
import threading
from pathlib import Path

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
