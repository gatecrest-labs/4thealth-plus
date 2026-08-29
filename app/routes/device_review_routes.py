"""Device Review tab — read-only interface protocol and CIS hardening analysis.

Page:
  GET  /device-review

API (JSON, all read-only):
  GET  /api/device-review/adoms/<adom>/devices
       returns: [{name, ip, platform, version, serial, status}, ...]

  POST /api/device-review/run/device
       body: { adom, device, checks: [str, ...], check_params: {key: {…}} }
       Single-device run — used by the frontend to drive a per-device progress
       loop for large ADOMs.
       returns: { device, rows: [Row, ...] }

  POST /api/device-review/run
       body: { adom, devices: [str, ...], checks: [str, ...],
               check_params: {key: {…}} }
             devices: []  means all devices in the ADOM
             checks: absent/null means all registered checks
             check_params: optional per-check user-supplied values
               e.g. { "ntp_config":    { "expected_servers": ["10.1.1.1"] },
                      "syslog_config": { "expected_servers": ["10.2.2.1"] } }
       returns: { adom, run_at, devices_reviewed, device_count,
                  checks_run, total, rows: [Row, ...] }
"""

from __future__ import annotations

import datetime

from flask import Blueprint, jsonify, render_template, request, session

from app import registry
from app.app_logger import app_log
from app.decorators import check_adom_access, tab_required
from app.device_review import _CHECKS_BY_KEY, CHECKS_META, run_checks
from app.fmg_client import FMGError
from app.fmg_helpers import make_client
from app.security import internal_api_error, upstream_api_error

bp = Blueprint("device_review", __name__)

registry.register("device_review", "Device Review", "device_review.device_review_page")


# ── Page ──────────────────────────────────────────────────────────────────────


@bp.route("/device-review")
@tab_required("device_review")
def device_review_page():
    return render_template(
        "device_review.html",
        user=session["user"],
        checks=CHECKS_META,
    )


# ── API: list devices in an ADOM ──────────────────────────────────────────────


@bp.route("/api/device-review/adoms/<adom>/devices")
@tab_required("device_review")
def device_review_devices(adom: str):
    if err := check_adom_access(adom):
        return err
    try:
        with make_client() as client:
            raw = client.get_devices(adom)
        seen: set[str] = set()
        devices = []
        for d in raw:
            if not isinstance(d, dict):
                continue
            name = d.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)
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
                version = ""
            devices.append(
                {
                    "name": name,
                    "ip": d.get("ip", d.get("mgmt_ip", "")),
                    "platform": d.get("platform_str", d.get("platform", "")),
                    "version": version,
                    "serial": d.get("sn", d.get("serial", "")),
                    "status": d.get("conn_status", ""),
                }
            )
        return jsonify(devices)
    except FMGError as exc:
        return upstream_api_error("device_review", exc)
    except Exception as exc:
        return internal_api_error("device_review", exc)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _needed_data_keys(check_keys: list[str] | None) -> set[str]:
    """Return the union of data_keys for the selected checks."""
    keys = check_keys if check_keys is not None else [c["key"] for c in CHECKS_META]
    needed: set[str] = set()
    for key in keys:
        entry = _CHECKS_BY_KEY.get(key)
        if entry:
            needed.update(entry.get("data_keys", []))
    return needed


def _fetch_device_data(
    client, adom: str, device: str, data_keys: set[str], device_meta: dict | None = None
) -> dict:
    """Fetch only the device data blobs required by the selected checks."""
    data: dict = {}
    if "interfaces" in data_keys:
        try:
            data["interfaces"] = client.get_device_interfaces_all_vdoms(adom, device)
        except Exception:
            data["interfaces"] = []
    if "ntp" in data_keys:
        try:
            data["ntp"] = client.get_device_ntp(adom, device)
        except Exception:
            data["ntp"] = {}
    if "syslog" in data_keys:
        try:
            data["syslog"] = client.get_device_syslog(adom, device)
        except Exception:
            data["syslog"] = []
    if "admins" in data_keys:
        try:
            data["admins"] = client.get_device_admins(adom, device)
        except Exception:
            data["admins"] = []
    if "system_global" in data_keys:
        try:
            data["system_global"] = client.get_device_system_global(adom, device)
        except Exception:
            data["system_global"] = {}
    if "password_policy" in data_keys:
        try:
            data["password_policy"] = client.get_device_password_policy(adom, device)
        except Exception:
            data["password_policy"] = {}
    if "log_disk" in data_keys:
        try:
            data["log_disk"] = client.get_device_log_disk(adom, device)
        except Exception:
            data["log_disk"] = {}
    if "log_faz" in data_keys:
        try:
            data["log_faz"] = client.get_device_log_faz(adom, device)
        except Exception:
            data["log_faz"] = []
    if "dns" in data_keys:
        try:
            data["dns"] = client.get_device_dns(adom, device)
        except Exception:
            data["dns"] = {}
    if "snmp_community" in data_keys:
        try:
            data["snmp_community"] = client.get_device_snmp_community(adom, device)
        except Exception:
            data["snmp_community"] = []
    if "snmp_sysinfo" in data_keys:
        try:
            data["snmp_sysinfo"] = client.get_device_snmp_sysinfo(adom, device)
        except Exception:
            data["snmp_sysinfo"] = {}
    if "snmp_users" in data_keys:
        try:
            data["snmp_users"] = client.get_device_snmp_users(adom, device)
        except Exception:
            data["snmp_users"] = []
    if "ha_status" in data_keys:
        try:
            data["ha_status"] = client.get_device_ha_status(adom, device)
        except Exception:
            data["ha_status"] = {}
    if "ipsec_phase1" in data_keys:
        try:
            data["ipsec_phase1"] = client.get_device_ipsec_phase1(adom, device)
        except Exception:
            data["ipsec_phase1"] = []
    if "ipsec_phase2" in data_keys:
        try:
            data["ipsec_phase2"] = client.get_device_ipsec_phase2(adom, device)
        except Exception:
            data["ipsec_phase2"] = []
    # device_meta is passed in from the caller (already fetched from device list)
    if "device_meta" in data_keys:
        data["device_meta"] = device_meta or {}
    return data


# ── API: single-device run (used by the per-device progress loop) ─────────────


@bp.route("/api/device-review/run/device", methods=["POST"])
@tab_required("device_review")
def device_review_run_one():
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    device = (data.get("device") or "").strip()
    check_keys = data.get("checks")
    check_params = data.get("check_params") or {}

    if not adom or not device:
        return jsonify({"error": "adom and device are required"}), 400
    if err := check_adom_access(adom):
        return err

    valid_keys = {c["key"] for c in CHECKS_META}
    if check_keys is not None:
        check_keys = [k for k in check_keys if k in valid_keys]

    needed = _needed_data_keys(check_keys)

    try:
        with make_client() as client:
            # Fetch device meta when firmware check is selected
            device_meta: dict = {}
            if "device_meta" in needed:
                try:
                    device_meta = client.get_device(adom, device) or {}
                except Exception:
                    device_meta = {}
            device_data = _fetch_device_data(client, adom, device, needed, device_meta)
    except FMGError as exc:
        return upstream_api_error("device_review", exc)
    except Exception as exc:
        return internal_api_error("device_review", exc)

    rows = run_checks(device, device_data, check_keys, check_params)
    return jsonify({"device": device, "rows": rows})


# ── Scheduler entry point (session-free) ─────────────────────────────────────


def bulk_device_review_adom(
    adom: str,
    checks: list[str] | None,
    check_params: dict,
    max_workers: int = 4,
) -> list[dict]:
    """Run device review checks against all devices in an ADOM.

    Designed for the scheduler — no Flask request context required.
    Returns list of {device, ip, rows, error}.
    """
    import concurrent.futures

    valid_keys = {c["key"] for c in CHECKS_META}
    if checks:
        checks = [k for k in checks if k in valid_keys]
    needed = _needed_data_keys(checks if checks else None)

    try:
        with make_client() as client:
            all_devices = client.get_devices(adom)
    except Exception as exc:
        app_log(
            "ERROR",
            "device_review_routes",
            f"bulk_device_review_adom: get_devices failed for {adom}: {exc}",
        )
        return []

    def _run_one(dev: dict) -> dict:
        name = dev.get("name", "")
        ip = dev.get("ip", dev.get("mgmt_ip", ""))
        try:
            with make_client() as c:
                device_data = _fetch_device_data(c, adom, name, needed, dev)
            rows = run_checks(
                name, device_data, checks if checks else None, check_params
            )
            return {"device": name, "ip": ip, "rows": rows, "error": None}
        except Exception as exc:
            app_log(
                "ERROR",
                "device_review_routes",
                f"bulk_device_review_adom: check failed for {name}: {exc}",
            )
            return {"device": name, "ip": ip, "rows": [], "error": str(exc)}

    valid_devices = [d for d in all_devices if isinstance(d, dict) and d.get("name")]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_one, d): d for d in valid_devices}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return results


# ── API: bulk run checks ──────────────────────────────────────────────────────


@bp.route("/api/device-review/run", methods=["POST"])
@tab_required("device_review")
def device_review_run():
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    devices = data.get("devices") or []
    check_keys = data.get("checks")
    check_params = data.get("check_params") or {}

    if not adom:
        return jsonify({"error": "adom is required"}), 400
    if err := check_adom_access(adom):
        return err

    valid_keys = {c["key"] for c in CHECKS_META}
    if check_keys is not None:
        check_keys = [k for k in check_keys if k in valid_keys]
        if not check_keys:
            return jsonify({"error": "No valid check keys provided"}), 400

    needed = _needed_data_keys(check_keys)

    try:
        with make_client() as client:
            all_devices = client.get_devices(adom)
    except FMGError as exc:
        return upstream_api_error("device_review", exc)
    except Exception as exc:
        return internal_api_error("device_review", exc)

    if devices:
        device_set = {d.lower() for d in devices}
        all_devices = [
            d
            for d in all_devices
            if isinstance(d, dict) and d.get("name", "").lower() in device_set
        ]

    rows = []
    reviewed = []

    try:
        _client_ctx = make_client()
        client = _client_ctx.__enter__()
    except Exception:
        client = None
        _client_ctx = None

    try:
        for dev in all_devices:
            if not isinstance(dev, dict):
                continue
            name = dev.get("name", "")
            if not name:
                continue
            reviewed.append(name)
            try:
                device_data = (
                    _fetch_device_data(client, adom, name, needed, dev)
                    if client
                    else {}
                )
            except Exception:
                device_data = {}
            rows.extend(run_checks(name, device_data, check_keys, check_params))
    finally:
        if _client_ctx is not None:
            _client_ctx.__exit__(None, None, None)

    run_at = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    checks_run = (
        check_keys if check_keys is not None else [c["key"] for c in CHECKS_META]
    )

    return jsonify(
        {
            "adom": adom,
            "run_at": run_at,
            "devices_reviewed": reviewed,
            "device_count": len(reviewed),
            "checks_run": checks_run,
            "total": len(rows),
            "rows": rows,
        }
    )


# ── AI Summary ─────────────────────────────────────────────────────────────


@bp.route("/api/device-review/ai-summary-status")
@tab_required("device_review")
def dr_ai_summary_status():
    from app.app_settings import get_setting

    return jsonify({"available": get_setting("ai_assist_enabled", False)})


@bp.route("/api/device-review/ai-summary", methods=["POST"])
@tab_required("device_review")
def dr_ai_summary():
    """Narrate an already-computed Device Review run. The LLM never computes
    a finding — it only summarizes results the check engine already
    produced. Narration is best-effort: any failure degrades to
    narrative=None + narrative_error, never a 500."""
    from app.app_settings import get_setting

    if not get_setting("ai_assist_enabled", False):
        return jsonify({"error": "AI Assist is not enabled"}), 503

    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    results = data.get("results")
    checks = data.get("checks") or []

    if not results:
        return jsonify({"error": "results is required"}), 400
    if not isinstance(results, list) or not all(isinstance(d, dict) for d in results):
        return jsonify(
            {"error": "results must be a list of device result objects"}
        ), 400

    from app.device_review_ai import build_narrative
    from app.device_review_scheduler import _build_check_summary

    check_summary = _build_check_summary(results, checks)

    narrative = None
    narrative_error = None
    try:
        narrative = build_narrative(
            adom, check_summary, results, user=session.get("user")
        )
    except Exception as exc:
        narrative_error = str(exc)

    return jsonify({"narrative": narrative, "narrative_error": narrative_error})
