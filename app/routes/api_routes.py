"""Read-only JSON API routes — all FortiManager calls go through here."""

import json
import re

from flask import Blueprint, Response, jsonify, request, session, stream_with_context

from app.config import Config
from app.decorators import admin_required, check_adom_access, tab_required
from app.fmg_client import PROXY_ENDPOINTS, FMGClient, FMGError
from app.fmg_helpers import make_client as _make_client
from app.license_status import parse_license_payload
from app.security import internal_api_error, upstream_api_error

bp = Blueprint("api", __name__, url_prefix="/api")


def _health_status(cpu: float, mem: float) -> str:
    if cpu >= Config.CPU_CRIT or mem >= Config.MEM_CRIT:
        return "red"
    if cpu >= Config.CPU_WARN or mem >= Config.MEM_WARN:
        return "yellow"
    return "green"


_SNMP_POLLED_TYPES = {"fortimanager", "fortianalyzer", "fortiauthenticator"}


def _extract_percent(resource_payload, key: str) -> float:
    """Pull the current usage % from a resource/usage proxy payload."""
    if not resource_payload:
        return 0.0
    # payload shape: {"cpu": [{"current": 12, ...}]} or {"results": {"cpu": [...]}}
    bucket = resource_payload
    if isinstance(bucket, dict):
        inner = bucket.get(key, bucket.get("results", {}).get(key, []))
    else:
        inner = []
    if isinstance(inner, list) and inner:
        return float(inner[0].get("current", 0))
    return 0.0


def _parse_cpu(perf: dict, usage: dict, sys_status: dict) -> float:
    """Extract CPU % from whichever FMG endpoint returned data."""
    # Shape A — /sys/resource/performance: {"cpu": 12}  (plain int/float)
    # Shape B — /sys/resource/performance: {"cpu": {"current_val": 12}}
    # Shape C — /sys/resource/usage:       {"cpu": [{"current": 12}]}
    # Shape D — /sys/status:               {"CPU Load": "12%"} or {"cpu": 12}
    try:
        for src in (perf, usage):
            v = src.get("cpu")
            if v is None:
                v = src.get("CPU")
            if v is None:
                # Unwrap {"results": {"cpu": ...}} nesting used by some FMG versions
                results = src.get("results") or {}
                v = results.get("cpu") or results.get("CPU")
            if v is None:
                continue
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, dict):
                val = (
                    v.get("current_val")
                    or v.get("current")
                    or v.get("cpu")
                    or v.get("used")
                )
                if val is not None:
                    return float(val)
            if isinstance(v, list) and v:
                val = v[0].get("current") or v[0].get("current_val") or v[0].get("used")
                if val is not None:
                    return float(val)
        # Fall back to sys/status
        raw = (
            sys_status.get("CPU Load")
            or sys_status.get("cpu_load")
            or sys_status.get("CPU")
            or sys_status.get("cpu")
            or 0
        )
        raw_str = str(raw).strip().rstrip("%")
        return float(raw_str) if raw_str else 0.0
    except Exception:
        return 0.0


def _parse_mem(perf: dict, usage: dict, sys_status: dict) -> float:
    """Extract memory used % from whichever FMG endpoint returned data."""
    # Shape A — /sys/resource/performance: {"mem": 34}
    # Shape B — /sys/resource/performance: {"mem": {"used_percent": 34}} or {"used": X, "total": Y}
    # Shape C — /sys/resource/usage:       {"mem": [{"current": 34}]}
    # Shape D — /sys/status:               {"Memory Usage": "34%"} or {"Memory Usage": "3456 MB / 8192 MB"}
    try:
        for src in (perf, usage):
            v = src.get("mem")
            if v is None:
                v = src.get("memory") or src.get("Memory")
            if v is None:
                # Unwrap {"results": {"mem": ...}} nesting used by some FMG versions
                results = src.get("results") or {}
                v = results.get("mem") or results.get("memory") or results.get("Memory")
            if v is None:
                continue
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, dict):
                pct = (
                    v.get("used_percent")
                    or v.get("used_pct")
                    or v.get("percent")
                    or v.get("current")
                )
                if pct is not None:
                    return float(pct)
                total = float(v.get("total", 0) or 0)
                used = float(v.get("used", 0) or 0)
                if total > 0:
                    return round(used / total * 100, 1)
            if isinstance(v, list) and v:
                pct = (
                    v[0].get("current")
                    or v[0].get("used_percent")
                    or v[0].get("used_pct")
                )
                if pct is not None:
                    return float(pct)

        # Fall back to sys/status "Memory Usage" field
        # FMG may return "34%" or "3456 MB / 8192 MB"
        raw = sys_status.get("Memory Usage") or sys_status.get("memory_usage") or ""
        if raw:
            raw_str = str(raw).strip()
            if raw_str.endswith("%"):
                return float(raw_str.rstrip("%") or 0)
            if "/" in raw_str:
                # "used MB / total MB" format
                parts = raw_str.split("/")
                used = float(parts[0].strip().split()[0])
                total = float(parts[1].strip().split()[0])
                return round(used / total * 100, 1) if total else 0.0

        mem = sys_status.get("Memory") or sys_status.get("memory") or {}
        if isinstance(mem, dict):
            total = float(mem.get("total", 0) or 0)
            used = float(mem.get("used", 0) or 0)
            return round(used / total * 100, 1) if total else 0.0
        if isinstance(mem, (int, float)):
            return float(mem)
        return 0.0
    except Exception:
        return 0.0


# ── Managed firewall & rule summary (pre-computed by background job) ─────────


@bp.route("/summary")
@tab_required("dashboard")
def summary():
    from app.summary_job import get_summary

    return jsonify(get_summary())


@bp.route("/summary/history")
@tab_required("dashboard")
def summary_history():
    from app.summary_history import get_history

    return jsonify(get_history())


@bp.route("/summary/refresh", methods=["POST"])
@tab_required("dashboard")
def summary_refresh():
    """Kick off an immediate recalculation in the background."""
    import threading

    from flask import current_app

    from app import summary_job

    t = threading.Thread(
        target=summary_job._run_job,
        args=[current_app._get_current_object()],
        name="summary_job_manual",
        daemon=True,
    )
    t.start()
    return jsonify({"queued": True})


# ── Infrastructure health (home dashboard) ──────────────────────────────────


@bp.route("/infrastructure")
@tab_required("dashboard")
def infrastructure():
    from app import infra_health_cache

    devices = []
    for target in Config.INFRA_TARGETS:
        entry = {
            "label": target["label"],
            "host": target["host"],
            "type": target["type"],
            "status": "unknown",
            "version": "n/a",
            "hostname": "n/a",
            "serial": "n/a",
            "uptime": "n/a",
            "cpu": None,
            "mem": None,
            "snmp_status": None,
            "ha_mode": "n/a",
            "ha_role": "n/a",
            "disk_used": "n/a",
        }

        is_snmp_type = target.get("type", "").lower() in _SNMP_POLLED_TYPES

        try:
            # Per-device token takes priority, then global token, then username/password
            client = FMGClient(
                host=target["host"],
                username=Config.FMG_USERNAME,
                password=Config.FMG_PASSWORD,
                token=target.get("token", Config.FMG_API_TOKEN),
                verify_ssl=Config.FMG_VERIFY_SSL,
                timeout=Config.FMG_TIMEOUT,
            )
            perf, usage = {}, {}
            api_ok = False
            if is_snmp_type:
                # For SNMP-polled types (FortiManager/FortiAnalyzer/
                # FortiAuthenticator), CPU/mem/status come from the SNMP
                # cache below and must not depend on FMG JSON-RPC
                # reachability — only hostname/version/serial/etc (cosmetic
                # detail) come from FMG, so a connection failure here is
                # swallowed rather than failing the whole entry. api_ok
                # tracks whether the FMG API itself is reachable, so the
                # status color can fall back on it when SNMP is unavailable.
                try:
                    with client:
                        sys_status = client.get_system_status()
                    api_ok = True
                except Exception:
                    sys_status = {}
            else:
                # Legacy FMG JSON-RPC path (FortiCollector, etc.) — unchanged:
                # a connection failure here falls through to the outer
                # except and marks the entry red, exactly as before.
                with client:
                    sys_status = client.get_system_status()
                    perf = client.get_performance()
                    usage = client.get_resource_usage()

            # /sys/status may return a list or dict depending on FMG version
            if isinstance(sys_status, list) and sys_status:
                sys_status = sys_status[0]
            if not isinstance(sys_status, dict):
                sys_status = {}

            # ── Hostname ──────────────────────────────────────────────────
            entry["hostname"] = (
                sys_status.get("Hostname") or sys_status.get("hostname") or "n/a"
            )

            # ── Version — FMG returns "v7.4.0 build2778 260120 (GA)"
            #    Extract just the vX.Y.Z prefix
            raw_ver = sys_status.get("Version") or sys_status.get("version") or "n/a"
            m = re.match(r"(v?\d+\.\d+[\.\d]*)", str(raw_ver))
            entry["version"] = m.group(1) if m else raw_ver

            # ── Serial ────────────────────────────────────────────────────
            entry["serial"] = (
                sys_status.get("Serial Number")
                or sys_status.get("serial_number")
                or sys_status.get("serial")
                or "n/a"
            )

            # ── Uptime ────────────────────────────────────────────────────
            entry["uptime"] = (
                sys_status.get("System time") or sys_status.get("uptime") or "n/a"
            )

            # ── HA — FMG /sys/status returns flat keys "HA Mode" / "HA Role"
            #    (not a nested {"HA": {"Mode": ...}} dict)
            entry["ha_mode"] = (
                sys_status.get("HA Mode")
                or sys_status.get("ha_mode")
                or (sys_status.get("HA") or {}).get("Mode")
                or "n/a"
            )
            entry["ha_role"] = (
                sys_status.get("HA Role")
                or sys_status.get("ha_role")
                or (sys_status.get("HA") or {}).get("Role")
                or "n/a"
            )

            # ── Disk ──────────────────────────────────────────────────────
            disk_info = sys_status.get("disk info") or sys_status.get("Disk info") or {}
            if disk_info and isinstance(disk_info, dict):
                used = disk_info.get("used", disk_info.get("Used", "n/a"))
                total = disk_info.get("total", disk_info.get("Total", "n/a"))
                entry["disk_used"] = f"{used}/{total}" if used != "n/a" else "n/a"

            if is_snmp_type:
                # ── CPU & Memory — sourced from the SNMP background cache ──
                # Gray is reserved for "no signal at all" (both SNMP and the
                # FMG API are unreachable). If the FMG API is reachable but
                # SNMP CPU/mem isn't available (disabled, timing out, wrong
                # creds, etc.), the device is still up — show green rather
                # than gray, just without a CPU/mem reading.
                cached = infra_health_cache.get_cached(target["host"])
                if cached is not None and cached["snmp_status"] == "ok":
                    entry["cpu"] = round(cached["cpu"], 1)
                    entry["mem"] = round(cached["mem"], 1)
                    entry["snmp_status"] = "ok"
                    entry["status"] = _health_status(cached["cpu"], cached["mem"])
                else:
                    entry["snmp_status"] = (
                        cached["snmp_status"] if cached else "disabled"
                    )
                    entry["status"] = "green" if api_ok else "gray"
            else:
                # ── CPU & Memory — legacy FMG JSON-RPC path (FortiCollector, etc.) ──
                # perf/usage were already fetched above, inside the client's
                # session context.
                if isinstance(perf, list) and perf:
                    perf = perf[0]
                if not isinstance(perf, dict):
                    perf = {}
                if isinstance(usage, list) and usage:
                    usage = usage[0]
                if not isinstance(usage, dict):
                    usage = {}

                no_resource_data = not perf and not usage
                cpu_val = _parse_cpu(perf, usage, sys_status)
                mem_val = _parse_mem(perf, usage, sys_status)

                if no_resource_data and cpu_val == 0.0 and mem_val == 0.0:
                    entry["cpu"] = None
                    entry["mem"] = None
                else:
                    entry["cpu"] = round(cpu_val, 1)
                    entry["mem"] = round(mem_val, 1)
                entry["status"] = _health_status(cpu_val, mem_val)

        except Exception:
            entry["status"] = "red"
            entry["error"] = "Unable to query target"
        devices.append(entry)
    return jsonify(devices)


# ── Infrastructure raw debug ─────────────────────────────────────────────────


@bp.route("/infrastructure/raw")
@admin_required
def infrastructure_raw():
    """Return raw API responses from the primary FMG — use to diagnose field names."""
    try:
        with _make_client() as client:
            status = client.get_system_status()
            perf = client.get_performance()
            usage = client.get_resource_usage()
        return jsonify({"sys_status": status, "performance": perf, "usage": usage})
    except Exception as exc:
        return internal_api_error("api", exc)


# ── All devices (version data across every ADOM) — served from cache ─────────


@bp.route("/devices/all")
@tab_required("versions")
def all_devices():
    from app.versions_cache import get_cached

    cached = get_cached()
    # Include cache metadata so the frontend can show age + status
    return jsonify(
        {
            "devices": cached["devices"],
            "last_updated": cached["last_updated"],
            "status": cached["status"],
            "error": cached["error"],
        }
    )


@bp.route("/devices/all/refresh", methods=["POST"])
@tab_required("versions")
def all_devices_refresh():
    """Trigger a manual cache refresh (non-blocking — returns immediately)."""
    from flask import current_app

    from app.versions_cache import get_cached, refresh_now

    refresh_now(current_app._get_current_object())
    cached = get_cached()
    return jsonify({"status": cached["status"], "queued": True})


# ── License status (Device Versions tab → License Status section) ───────────
# Reuses app.license_status_cache's existing daily sweep (see that module's
# docstring) rather than running a second, more-frequent per-device sweep.


def _license_cache_status() -> str:
    from app import license_status_cache

    if license_status_cache.is_running():
        return "running"
    return "ok" if license_status_cache.get_latest() is not None else "pending"


@bp.route("/devices/all/license")
@tab_required("versions")
def all_devices_license():
    from app import license_status_cache
    from app.groups import get_allowed_adoms

    latest = license_status_cache.get_latest() or {}
    devices = latest.get("all_devices", [])
    allowed = get_allowed_adoms(
        session.get("user", ""),
        ad_groups=session.get("ad_groups", []),
        role=session.get("role"),
    )
    if allowed is not None:
        devices = [d for d in devices if d.get("adom") in allowed]
    return jsonify(
        {
            "devices": devices,
            "last_updated": latest.get("collected_at"),
            "status": _license_cache_status(),
        }
    )


@bp.route("/devices/all/license/refresh", methods=["POST"])
@tab_required("versions")
def all_devices_license_refresh():
    """Trigger a manual license sweep (non-blocking — returns immediately)."""
    from flask import current_app

    from app import license_status_cache

    license_status_cache.refresh_now(current_app._get_current_object())
    return jsonify({"status": "running", "queued": True})


@bp.route("/adoms/<adom>/license")
@tab_required("versions")
def adom_license(adom: str):
    from app import license_status_cache

    if err := check_adom_access(adom):
        return err
    latest = license_status_cache.get_latest() or {}
    devices = [d for d in latest.get("all_devices", []) if d.get("adom") == adom]
    return jsonify(
        {
            "devices": devices,
            "last_updated": latest.get("collected_at"),
            "status": _license_cache_status(),
        }
    )


# ── ADOM list ────────────────────────────────────────────────────────────────


@bp.route("/adoms")
@tab_required("firewalls")
def adoms():
    try:
        with _make_client() as client:
            raw = client.get_adoms()
        items = [
            {"name": a.get("name", a.get("adom", "")), "desc": a.get("desc", "")}
            for a in raw
            if isinstance(a, dict)
        ]
        items = [
            i for i in items if i["name"] and not i["name"].lower().startswith("forti")
        ]
        # Filter to ADOMs the current user is allowed to see
        from flask import session as _session

        from app.groups import get_allowed_adoms

        allowed = get_allowed_adoms(
            _session.get("user", ""), ad_groups=_session.get("ad_groups", [])
        )
        if allowed is not None:  # None means unrestricted
            items = [i for i in items if i["name"] in allowed]
        return jsonify(items)
    except FMGError as exc:
        return upstream_api_error("api", exc)
    except Exception as exc:
        return internal_api_error("api", exc)


# ── Device list for ADOM ─────────────────────────────────────────────────────


@bp.route("/adoms/<adom>/devices")
@tab_required("firewalls")
def devices(adom: str):
    if err := check_adom_access(adom):
        return err
    try:
        with _make_client() as client:
            raw = client.get_devices(adom)
        result = []
        for d in raw:
            if not isinstance(d, dict):
                continue
            name = d.get("name", "")
            ip = d.get("ip", d.get("mgmt_ip", "n/a"))
            serial = d.get("sn", d.get("serial", "n/a"))
            platform = d.get("platform_str", d.get("platform", "n/a"))
            # Firmware version assembly matching Ansible playbook logic
            os_ver = d.get("os_ver", 0)
            mr = d.get("mr")
            patch = d.get("patch")
            major = (
                int(os_ver) // 100
                if str(os_ver).isdigit() and int(os_ver) >= 100
                else os_ver
            )
            if mr is not None and patch is not None and int(patch) >= 0:
                version = f"v{major}.{mr}.{patch}"
            elif mr is not None:
                version = f"v{major}.{mr}"
            else:
                version = "n/a"

            conn_status = d.get("conn_status", d.get("connection_status", -1))
            # conn_status: 1 = connected, anything else = not reachable by FMG
            status = "green" if conn_status == 1 else "offline"

            result.append(
                {
                    "name": name,
                    "ip": ip,
                    "serial": serial,
                    "platform": platform,
                    "version": version,
                    "status": status,
                    "adom": adom,
                    "desc": d.get("desc", "").strip(),
                    "ha_mode": d.get("ha_mode", d.get("ha_group_name", "")),
                }
            )
        return jsonify(result)
    except FMGError as exc:
        return upstream_api_error("api", exc)
    except Exception as exc:
        return internal_api_error("api", exc)


# ── Device detail (proxied health) ───────────────────────────────────────────


def _assemble_health(
    adom: str,
    device_name: str,
    dev_rec: dict,
    vdoms_raw: list,
    raw: dict,
    policy_packages: list | None = None,
) -> dict:
    """Build the health response dict from pre-fetched dvmdb + proxy data."""
    # ── Inventory fields from dvmdb ───────────────────────────────────
    os_ver = dev_rec.get("os_ver", 0)
    mr = dev_rec.get("mr")
    patch = dev_rec.get("patch")
    major = (
        int(os_ver) // 100 if str(os_ver).isdigit() and int(os_ver) >= 100 else os_ver
    )
    if mr is not None and patch is not None and int(patch) >= 0:
        version = f"v{major}.{mr}.{patch}"
    elif mr is not None:
        version = f"v{major}.{mr}"
    else:
        version = "n/a"

    serial = dev_rec.get("sn", dev_rec.get("serial", "n/a"))
    hostname = dev_rec.get("hostname", dev_rec.get("name", device_name))
    platform = dev_rec.get("platform_str", dev_rec.get("platform", "n/a"))
    mgmt_ip = dev_rec.get("ip", dev_rec.get("mgmt_ip", "n/a"))
    desc = dev_rec.get("desc", "").strip()

    vdoms = []
    for v in vdoms_raw:
        if not isinstance(v, dict):
            continue
        vdoms.append(
            {
                "name": v.get("name", ""),
                "opmode": v.get("opmode", v.get("vdom_type", "")),
                "status": v.get("status", ""),
                "flags": v.get("flags", []),
            }
        )
    vdom_mode = len(vdoms) > 1 or (
        len(vdoms) == 1 and vdoms[0]["name"] not in ("root", "")
    )

    conn_status = dev_rec.get("conn_status", dev_rec.get("connection_status", -1))
    dot_status = "green" if conn_status == 1 else "offline"
    ha_mode_dvmdb = dev_rec.get("ha_mode", dev_rec.get("ha_group_name", ""))

    def payload(key):
        return raw.get(key, {}).get("payload", {})

    sys_status = payload("system_status")
    if isinstance(sys_status, list) and sys_status:
        sys_status = sys_status[0]
    if not isinstance(sys_status, dict):
        sys_status = {}

    cpu_val = _extract_percent(payload("cpu"), "cpu")
    mem_val = _extract_percent(payload("mem"), "mem")

    iface_cfg_raw = payload("interfaces_cfg")
    cfg_list = iface_cfg_raw if isinstance(iface_cfg_raw, list) else []
    iface_monitor_raw = payload("interfaces")
    monitor_map: dict = {}
    if isinstance(iface_monitor_raw, dict):
        # vdom=* returns {vdom_name: {iface_name: {link: bool, ...}, ...}, ...}
        # vdom=root (legacy) returns {iface_name: {link: bool, ...}, ...}
        # Distinguish by checking whether values are dicts-of-dicts (vdom=*) or plain dicts (vdom=root).
        first_val = (
            next(iter(iface_monitor_raw.values()), None) if iface_monitor_raw else None
        )
        if isinstance(first_val, dict) and any(
            isinstance(v, dict) for v in first_val.values()
        ):
            # Nested: {vdom: {iface_name: iface_dict}} — flatten across all VDOMs.
            # Structural check: nested format has dict values (interface objects);
            # flat format has primitive values (bool/int/str). The old field-presence
            # check (`not link and not rx_errors`) incorrectly triggered when the first
            # interface was physically down (link=False), emptying monitor_map.
            # The same physical interface can appear in multiple VDOM buckets; prefer
            # link=False (down) over link=True (up) so a stale up-state from one bucket
            # does not mask a genuine down-state reported by the interface's actual VDOM.
            for vdom_ifaces in iface_monitor_raw.values():
                if isinstance(vdom_ifaces, dict):
                    for iname, idata in vdom_ifaces.items():
                        if not isinstance(idata, dict):
                            continue
                        existing = monitor_map.get(iname)
                        if existing is None or (
                            idata.get("link") is False
                            and existing.get("link") is not False
                        ):
                            monitor_map[iname] = idata
        else:
            # Flat dict: {iface_name: iface_dict}
            for k, v in iface_monitor_raw.items():
                if isinstance(v, dict):
                    monitor_map[k] = v
    elif isinstance(iface_monitor_raw, list):
        for v in iface_monitor_raw:
            if isinstance(v, dict):
                n = v.get("name", v.get("q_origin_key", ""))
                if n:
                    monitor_map[n] = v

    interfaces = []
    for entry in cfg_list:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        raw_ip = entry.get("ip", "")
        if isinstance(raw_ip, str) and " " in raw_ip:
            ip_str = raw_ip.replace(" ", "/", 1)
        else:
            ip_str = str(raw_ip) if raw_ip else ""
        live = monitor_map.get(name, {})
        interfaces.append(
            {
                "name": name,
                "ip": ip_str,
                "vdom": entry.get("vdom", ""),
                "type": entry.get("type", ""),
                "status": entry.get("status", ""),
                "allowaccess": entry.get("allowaccess", ""),
                "speed": live.get("speed", entry.get("speed", "")),
                "link": live.get("link"),
                "rx_errors": live.get("rx_errors", live.get("rx_err", 0)),
                "tx_errors": live.get("tx_errors", live.get("tx_err", 0)),
            }
        )

    ha_raw = payload("ha_status")
    if isinstance(ha_raw, list) and ha_raw:
        ha_raw = ha_raw[0]
    if not isinstance(ha_raw, dict):
        ha_raw = {}
    if ha_mode_dvmdb and not ha_raw.get("mode"):
        ha_raw["mode"] = ha_mode_dvmdb

    perf_raw = payload("performance")
    if isinstance(perf_raw, list) and perf_raw:
        perf_raw = perf_raw[0]
    if not isinstance(perf_raw, dict):
        perf_raw = {}

    license_info = parse_license_payload(payload("license_status"))
    if license_info["status"] == "unknown" and conn_status != 1:
        license_info = {**license_info, "status": "offline"}

    def _parse_vdom_routes(r) -> dict:
        by_vdom = {}
        if isinstance(r, list):
            for item in r:
                if not isinstance(item, dict):
                    continue
                vname = item.get("vdom", "root")
                results = item.get("results", [])
                by_vdom[vname] = results if isinstance(results, list) else []
        return by_vdom

    routes_by_vdom = _parse_vdom_routes(payload("ipv4_routes"))
    routes6_by_vdom = _parse_vdom_routes(payload("ipv6_routes"))
    routes = [r for rs in routes_by_vdom.values() for r in rs]
    bgp_by_vdom = _parse_vdom_routes(payload("bgp_neighbors"))
    bgp_paths_by_vdom = _parse_vdom_routes(payload("bgp_paths"))
    ospf_by_vdom = _parse_vdom_routes(payload("ospf_neighbors"))
    bgp = [r for rs in bgp_by_vdom.values() for r in rs]
    bgp_paths = [r for rs in bgp_paths_by_vdom.values() for r in rs]
    ospf = [r for rs in ospf_by_vdom.values() for r in rs]

    ipsec_raw = payload("ipsec")
    ipsec = (
        ipsec_raw
        if isinstance(ipsec_raw, list)
        else ([ipsec_raw] if isinstance(ipsec_raw, dict) and ipsec_raw else [])
    )

    # Build display string; include vdom when it's non-root or there are multiple entries
    pkgs = policy_packages or []
    show_vdom = len(pkgs) > 1 or any(
        p.get("vdom", "root") not in ("root", "") for p in pkgs
    )
    policy_package = ", ".join(
        f"{p['name']} ({p['vdom']})" if show_vdom and p.get("vdom") else p["name"]
        for p in pkgs
    )

    return {
        "name": hostname,
        "adom": adom,
        "desc": desc,
        "dot_status": dot_status,
        "version": version,
        "serial": serial,
        "license": license_info,
        "platform": platform,
        "mgmt_ip": mgmt_ip,
        "cpu": cpu_val,
        "mem": mem_val,
        "status": _health_status(cpu_val, mem_val),
        "ha": ha_raw,
        "policy_package": policy_package,
        "vdom_mode": vdom_mode,
        "vdoms": vdoms,
        "interfaces": interfaces,
        "routes": routes,
        "routes_by_vdom": routes_by_vdom,
        "routes6_by_vdom": routes6_by_vdom,
        "bgp": bgp,
        "bgp_by_vdom": bgp_by_vdom,
        "bgp_paths": bgp_paths,
        "bgp_paths_by_vdom": bgp_paths_by_vdom,
        "ospf": ospf,
        "ospf_by_vdom": ospf_by_vdom,
        "ipsec": ipsec,
    }


@bp.route("/adoms/<adom>/devices/<device_name>/health")
@tab_required("firewalls")
def device_health(adom: str, device_name: str):
    if err := check_adom_access(adom):
        return err
    try:
        with _make_client() as client:
            dev_rec = client.get_device(adom, device_name)
            vdoms_raw = client.get_device_vdoms(adom, device_name)
            raw = client.get_device_health(adom, device_name)
            if not raw.get("license_status", {}).get("payload"):
                mgt_vdom = dev_rec.get("mgt_vdom", "").strip('"')
                if mgt_vdom and mgt_vdom.lower() != "root":
                    raw["license_status"] = {
                        "payload": client.get_device_license_status(
                            adom, device_name, vdom=mgt_vdom
                        )
                    }
            pkgs = client.get_device_policy_package(adom, device_name)
        return jsonify(
            _assemble_health(adom, device_name, dev_rec, vdoms_raw, raw, pkgs)
        )
    except FMGError as exc:
        return upstream_api_error("api", exc)
    except Exception as exc:
        return internal_api_error("api", exc)


@bp.route("/adoms/<adom>/devices/<device_name>/health/stream")
@tab_required("firewalls")
def device_health_stream(adom: str, device_name: str):
    """SSE endpoint — streams a progress event after each proxy call, then a done event."""
    if err := check_adom_access(adom):
        return err

    @stream_with_context
    def generate():
        try:
            with _make_client() as client:
                dev_rec = client.get_device(adom, device_name)
                vdoms_raw = client.get_device_vdoms(adom, device_name)
                pkgs = client.get_device_policy_package(adom, device_name)
                raw: dict = {}
                # Three inventory calls (device, vdoms, policy package) precede proxy calls
                inv_steps = 3
                total = inv_steps + len(PROXY_ENDPOINTS)
                yield f"data: {json.dumps({'done': inv_steps, 'total': total, 'label': 'Inventory'})}\n\n"
                for done_idx, _total, label, key, result in client.stream_device_health(
                    adom, device_name
                ):
                    raw[key] = result
                    yield f"data: {json.dumps({'done': inv_steps + done_idx, 'total': total, 'label': label})}\n\n"
                if not raw.get("license_status", {}).get("payload"):
                    mgt_vdom = dev_rec.get("mgt_vdom", "").strip('"')
                    if mgt_vdom and mgt_vdom.lower() != "root":
                        raw["license_status"] = {
                            "payload": client.get_device_license_status(
                                adom, device_name, vdom=mgt_vdom
                            )
                        }
            payload = _assemble_health(adom, device_name, dev_rec, vdoms_raw, raw, pkgs)
            yield f"event: done\ndata: {json.dumps(payload)}\n\n"
        except Exception as exc:
            yield f"event: error\ndata: {json.dumps({'error': str(exc)})}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Raw proxy debug (shows unwrapped payload for each endpoint) ──────────────


@bp.route("/adoms/<adom>/devices/<device_name>/raw")
@admin_required
def device_raw(adom: str, device_name: str):
    """Return the raw unwrapped payload for every proxy endpoint — useful for debugging field names."""
    if err := check_adom_access(adom):
        return err
    try:
        with _make_client() as client:
            raw = client.get_device_health(adom, device_name)
        out = {
            k: {
                "http_status": v.get("http_status"),
                "rpc_code": v.get("rpc_code"),
                "payload": v.get("payload"),
            }
            for k, v in raw.items()
        }
        return jsonify(out)
    except Exception as exc:
        return internal_api_error("api", exc)


# ── Search ───────────────────────────────────────────────────────────────────


@bp.route("/search")
@tab_required("firewalls")
def search():
    query = request.args.get("q", "").strip().lower()
    if not query:
        return jsonify([])
    try:
        from app.groups import get_allowed_adoms

        allowed = get_allowed_adoms(
            session.get("user", ""), ad_groups=session.get("ad_groups", [])
        )
        with _make_client() as client:
            adoms_raw = client.get_adoms()
            adom_names = [
                a.get("name", "")
                for a in adoms_raw
                if isinstance(a, dict) and a.get("name")
            ]
            # Filter to ADOMs the user is permitted to search
            if allowed is not None:
                adom_names = [a for a in adom_names if a in allowed]
            matches = []
            for adom in adom_names:
                devices_raw = client.get_devices(adom)
                for d in devices_raw:
                    if not isinstance(d, dict):
                        continue
                    name = d.get("name", "")
                    ip = d.get("ip", d.get("mgmt_ip", ""))
                    if query in name.lower() or query in ip.lower():
                        conn_status = d.get(
                            "conn_status", d.get("connection_status", -1)
                        )
                        status = "green" if conn_status == 1 else "offline"
                        matches.append(
                            {
                                "name": name,
                                "ip": ip,
                                "adom": adom,
                                "status": status,
                                "serial": d.get("sn", d.get("serial", "n/a")),
                                "platform": d.get(
                                    "platform_str", d.get("platform", "n/a")
                                ),
                            }
                        )
        return jsonify(matches)
    except Exception as exc:
        return internal_api_error("api", exc)
