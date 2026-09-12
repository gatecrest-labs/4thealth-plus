"""Background cache for SNMPv3-polled CPU/memory of infra dashboard targets.

Polls FortiManager, FortiAnalyzer, and FortiAuthenticator entries from
Config.INFRA_TARGETS over SNMPv3 on a timer, storing results in an
in-memory dict keyed by host.  Mirrors the adom_cache.py pattern: a
BackgroundScheduler job feeds a lock-guarded dict, and callers get an
instant snapshot instead of blocking on a live device query.

FortiGate firewall CPU/mem (handled elsewhere, via the FMG proxy) is out
of scope here.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import threading

from flask import Flask
from pysnmp.hlapi.v3arch.asyncio import (
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC384_SHA512,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)

from app.config import Config

logger = logging.getLogger(__name__)

_lock = threading.RLock()
_cache: dict = {}

_SUPPORTED_TYPES = {"fortimanager", "fortianalyzer", "fortiauthenticator"}

# CPU/mem OIDs per device type.
#
# FortiManager OIDs below are confirmed against a real FMG-VM64-KVM
# (v7.6.7) under FORTINET-FORTIMANAGER-MIB's fmSystem group
# (1.3.6.1.4.1.12356.103.2.1.*), cross-checked against the FMG GUI's
# System Resources dashboard widget (Average CPU Usage / Memory Usage).
# Unlike FortiGate's fgSysMemUsage, FortiManager has no native memory
# percentage OID — mem is used-KB/total-KB and must be computed (see
# "mem_total" handling in _poll_target below).
#
# FortiAnalyzer OIDs confirmed against real FAZ hardware (v7.4.10) —
# same fmSystem group as FortiManager (1.3.6.1.4.1.12356.103.2.1.*),
# same used-KB/total-KB pattern for memory.
# FortiAuthenticator OIDs are still NOT confirmed against real hardware.
OID_MAP = {
    "fortimanager": {
        "cpu": "1.3.6.1.4.1.12356.103.2.1.1.0",
        "mem_used": "1.3.6.1.4.1.12356.103.2.1.2.0",
        "mem_total": "1.3.6.1.4.1.12356.103.2.1.3.0",
    },
    "fortianalyzer": {
        "cpu": "1.3.6.1.4.1.12356.103.2.1.1.0",
        "mem_used": "1.3.6.1.4.1.12356.103.2.1.2.0",
        "mem_total": "1.3.6.1.4.1.12356.103.2.1.3.0",
    },
    "fortiauthenticator": {
        "cpu": "1.3.6.1.4.1.12356.113.1.2.0",
        "mem": "1.3.6.1.4.1.12356.113.1.3.0",
    },
}

_AUTH_PROTOCOLS = {
    "SHA": USM_AUTH_HMAC96_SHA,
    "SHA256": USM_AUTH_HMAC192_SHA256,
    "SHA512": USM_AUTH_HMAC384_SHA512,
}
_PRIV_PROTOCOLS = {
    "AES": USM_PRIV_CFB128_AES,
    "AES192": USM_PRIV_CFB192_AES,
    "AES256": USM_PRIV_CFB256_AES,
}


class SnmpTimeout(Exception):
    """Raised when an SNMP GET does not receive a response before timeout."""


class SnmpQueryError(Exception):
    """Raised for any other SNMP failure (auth failure, bad OID, etc.)."""


def _resolve_snmp_creds(target: dict) -> dict:
    """Per-device snmp_* fields override the global Config.SNMP_* defaults."""
    return {
        "user": target.get("snmp_user", Config.SNMP_USER),
        "auth_key": target.get("snmp_auth_key", Config.SNMP_AUTH_KEY),
        "priv_key": target.get("snmp_priv_key", Config.SNMP_PRIV_KEY),
        "auth_protocol": target.get("snmp_auth_protocol", Config.SNMP_AUTH_PROTOCOL),
        "priv_protocol": target.get("snmp_priv_protocol", Config.SNMP_PRIV_PROTOCOL),
    }


async def _snmp_get(host: str, oids: list[str], creds: dict) -> list[float]:
    """Perform a single SNMPv3 GET for the given OIDs. Raises SnmpTimeout / SnmpQueryError."""
    engine = SnmpEngine()
    auth_data = UsmUserData(
        creds["user"],
        authKey=creds["auth_key"],
        privKey=creds["priv_key"],
        authProtocol=_AUTH_PROTOCOLS.get(creds["auth_protocol"], USM_AUTH_HMAC96_SHA),
        privProtocol=_PRIV_PROTOCOLS.get(creds["priv_protocol"], USM_PRIV_CFB128_AES),
    )
    target = await UdpTransportTarget.create(
        (host, Config.SNMP_PORT),
        timeout=Config.SNMP_TIMEOUT,
        retries=Config.SNMP_RETRIES,
    )
    error_indication, error_status, _error_index, var_binds = await get_cmd(
        engine,
        auth_data,
        target,
        ContextData(),
        *(ObjectType(ObjectIdentity(oid)) for oid in oids),
    )
    if error_indication:
        message = str(error_indication)
        if "timeout" in message.lower():
            raise SnmpTimeout(message)
        raise SnmpQueryError(message)
    if error_status:
        raise SnmpQueryError(str(error_status))
    return [float(var_bind[1]) for var_bind in var_binds]


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def _poll_target(target: dict) -> dict | None:
    """Poll a single target. Returns None if its type isn't SNMP-supported."""
    device_type = target.get("type", "").lower()
    oids = OID_MAP.get(device_type)
    if not oids:
        return None
    creds = _resolve_snmp_creds(target)
    try:
        if "mem_total" in oids:
            # Some device types (FortiManager) expose used/total KB rather
            # than a precomputed memory percentage — derive it here.
            cpu, mem_used, mem_total = asyncio.run(
                _snmp_get(
                    target["host"],
                    [oids["cpu"], oids["mem_used"], oids["mem_total"]],
                    creds,
                )
            )
            mem = (mem_used / mem_total * 100) if mem_total else 0.0
        else:
            cpu, mem = asyncio.run(
                _snmp_get(target["host"], [oids["cpu"], oids["mem"]], creds)
            )
        return {"cpu": cpu, "mem": mem, "snmp_status": "ok", "last_updated": _now()}
    except SnmpTimeout:
        return {
            "cpu": None,
            "mem": None,
            "snmp_status": "timeout",
            "last_updated": _now(),
        }
    except Exception:
        return {
            "cpu": None,
            "mem": None,
            "snmp_status": "error",
            "last_updated": _now(),
        }


def poll_all_targets() -> None:
    """Poll every SNMP-supported target in Config.INFRA_TARGETS and update the cache."""
    if not Config.SNMP_ENABLED:
        return
    from app import collector_store

    for target in Config.INFRA_TARGETS:
        if target.get("type", "").lower() not in _SUPPORTED_TYPES:
            continue
        host = target.get("host")
        if not host:
            continue
        result = _poll_target(target)
        if result is None:
            continue
        with _lock:
            _cache[host] = result
        try:
            collector_store.write_snapshot(
                f"infra_health:{host}", result, collected_at=result.get("last_updated")
            )
        except Exception as exc:
            logger.warning(
                "infra_health_cache: SQLite snapshot write failed for host %s "
                "(in-memory cache update still succeeded): %s",
                host,
                exc,
            )


def get_cached(host: str) -> dict | None:
    """Return a shallow copy of the cached entry for host, or None if not
    cached locally or in the collector's shared SQLite snapshot store."""
    with _lock:
        entry = _cache.get(host)
        if entry is not None:
            return dict(entry)

    from app import collector_store

    return collector_store.read_snapshot(f"infra_health:{host}")


def fetch_meta(target: dict) -> dict:
    """One-off live fetch of hostname/ha_role/disk_pct for a single infra
    target, via the same FMG get_system_status() call and field parsing
    /api/infrastructure already does per-request (app/routes/api_routes.py)
    — but NOT cached or scheduled here. The caller controls its own
    cadence; app.executive_summary_cache's device sweep calls this once
    per target on its own 15-minute-default interval, which is appropriate
    for fields (hostname, HA role, disk usage) that change slowly.

    Returns {hostname, ha_role, disk_pct, api_ok}. On any failure to reach
    the target, all three fields are None and api_ok is False — a
    genuinely unreachable target must never be reported as 0% disk or a
    blank-but-present hostname.
    """
    from app.config import Config
    from app.fmg_client import FMGClient

    try:
        client = FMGClient(
            host=target["host"],
            username=Config.FMG_USERNAME,
            password=Config.FMG_PASSWORD,
            token=target.get("token", Config.FMG_API_TOKEN),
            verify_ssl=Config.FMG_VERIFY_SSL,
            timeout=Config.FMG_TIMEOUT,
        )
        with client:
            sys_status = client.get_system_status()
    except Exception:
        return {"hostname": None, "ha_role": None, "disk_pct": None, "api_ok": False}

    if isinstance(sys_status, list) and sys_status:
        sys_status = sys_status[0]
    if not isinstance(sys_status, dict):
        sys_status = {}

    hostname = sys_status.get("Hostname") or sys_status.get("hostname") or None
    ha_role = (
        sys_status.get("HA Role")
        or sys_status.get("ha_role")
        or (sys_status.get("HA") or {}).get("Role")
        or None
    )

    disk_info = sys_status.get("disk info") or sys_status.get("Disk info") or {}
    disk_pct = None
    if isinstance(disk_info, dict):
        used = disk_info.get("used", disk_info.get("Used"))
        total = disk_info.get("total", disk_info.get("Total"))
        try:
            used_f, total_f = float(used), float(total)
            if total_f > 0:
                disk_pct = round(used_f / total_f * 100, 1)
        except (TypeError, ValueError):
            disk_pct = None

    return {
        "hostname": hostname,
        "ha_role": ha_role,
        "disk_pct": disk_pct,
        "api_ok": True,
    }


def poll_now() -> None:
    """Kick off a non-blocking poll of all targets in a daemon thread."""
    t = threading.Thread(
        target=poll_all_targets,
        name="infra_health_poll_now",
        daemon=True,
    )
    t.start()


def init_scheduler(app: Flask) -> None:
    """Register a recurring APScheduler job and run the first poll immediately."""
    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()  # initial poll at startup, non-blocking

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_all_targets,
        trigger="interval",
        seconds=Config.SNMP_POLL_INTERVAL,
        id="infra_health_snmp_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
