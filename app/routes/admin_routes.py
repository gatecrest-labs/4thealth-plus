"""Admin-only routes.

Page:  GET  /admin
Groups API (JSON):
  GET    /admin/api/groups
  POST   /admin/api/groups           {"name": str, "members": [...], "allowed_tabs": [...],
                                      "adom_restrict": bool, "allowed_adoms": [...]}
  PUT    /admin/api/groups/<name>    {"members": [...], "allowed_tabs": [...],
                                      "adom_restrict": bool, "allowed_adoms": [...]}
  DELETE /admin/api/groups/<name>
  GET    /admin/api/users            list of {username, role} for member picker

ADOM cache (JSON):
  GET    /admin/api/adoms            known ADOM names from the background cache

Map regions (JSON):
  GET    /admin/api/map-regions      current region config (names, states, colors)
  PUT    /admin/api/map-regions      update region colors only
                                     {"region_colors": {"Upper Midwest": "#hex", ...},
                                      "other_color": "#hex"}

Logs API (JSON):
  GET    /admin/api/logs?level=INFO&component=auth&limit=500
  POST   /admin/api/logs/level       {"level": "DEBUG"}
  DELETE /admin/api/logs             clears the buffer

Tab registry:
  GET    /admin/api/tabs             known tab keys + display names

App settings (JSON):
  GET    /admin/api/settings         {"external_api_enabled": bool, "ai_assist_enabled": bool}
  PUT    /admin/api/settings         {"external_api_enabled": bool, "ai_assist_enabled": bool}
  GET    /admin/api/ai-usage         bucketed AI Assist call/cost history (?range= or ?start=&end=)
  GET    /admin/api/host-metrics     bucketed host CPU/mem/disk history (?range=1h|4h|12h|1d|7d|14d)

External API tokens (JSON):
  GET    /admin/api/tokens           list tokens (hashes never returned)
  POST   /admin/api/tokens           {"name": str} — create token; plaintext returned once
  DELETE /admin/api/tokens/<id>      revoke token
"""

import os
import re

from flask import Blueprint, jsonify, render_template, request, session

from app import config_diff_scheduler as _sched
from app import device_review_scheduler as _dr_sched
from app import registry
from app import rule_hygiene_scheduler as _rh_sched
from app import smtp_client as _smtp
from app.api_tokens import create_token, list_tokens, revoke_token
from app.app_logger import (
    app_log,
    clear_log_entries,
    get_log_entries,
    get_log_level,
    get_log_levels,
    set_log_level,
)
from app.app_settings import get_all as get_all_settings
from app.app_settings import set_setting
from app.auth import list_users
from app.decorators import admin_required as _admin_required
from app.device_review import CHECKS_META as _DR_CHECKS_META
from app.groups import create_group, delete_group, get_group, list_groups, update_group

bp = Blueprint("admin", __name__, url_prefix="/admin")


# ── Page ─────────────────────────────────────────────────────────────────────


@bp.route("/")
@_admin_required
def admin_page():
    app_log("DEBUG", "admin", "Admin page accessed", username=session["user"])
    return render_template(
        "admin.html",
        user=session["user"],
        checks_meta=_DR_CHECKS_META,
        in_docker=os.path.exists("/.dockerenv"),
    )


# ── Groups API ────────────────────────────────────────────────────────────────


@bp.route("/api/groups")
@_admin_required
def api_groups_list():
    return jsonify(list_groups())


@bp.route("/api/groups", methods=["POST"])
@_admin_required
def api_groups_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    members = data.get("members", [])
    ad_groups = data.get("ad_groups", [])
    allowed_tabs = data.get("allowed_tabs", [])
    adom_restrict = bool(data.get("adom_restrict", False))
    allowed_adoms = data.get("allowed_adoms", [])
    try:
        ok = create_group(
            name, members, ad_groups, allowed_tabs, adom_restrict, allowed_adoms
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not ok:
        return jsonify({"error": f"Group '{name}' already exists"}), 409
    app_log("INFO", "admin", "Group created", by=session["user"], group=name)
    return jsonify(get_group(name)), 201


@bp.route("/api/groups/<name>", methods=["PUT"])
@_admin_required
def api_groups_update(name: str):
    data = request.get_json(silent=True) or {}
    members = data.get("members", [])
    ad_groups = data.get("ad_groups", [])
    allowed_tabs = data.get("allowed_tabs", [])
    adom_restrict = bool(data.get("adom_restrict", False))
    allowed_adoms = data.get("allowed_adoms", [])
    if not update_group(
        name, members, allowed_tabs, adom_restrict, allowed_adoms, ad_groups=ad_groups
    ):
        return jsonify({"error": f"Group '{name}' not found"}), 404
    app_log("INFO", "admin", "Group updated", by=session["user"], group=name)
    return jsonify(get_group(name))


@bp.route("/api/groups/<name>", methods=["DELETE"])
@_admin_required
def api_groups_delete(name: str):
    if not delete_group(name):
        return jsonify({"error": f"Group '{name}' not found"}), 404
    app_log("INFO", "admin", "Group deleted", by=session["user"], group=name)
    return jsonify({"deleted": name})


# ── ADOM cache (for ADOM access picker) ──────────────────────────────────────


@bp.route("/api/adoms")
@_admin_required
def api_adoms_list():
    """Return the cached list of known ADOMs (used by the group editor)."""
    from app.adom_cache import get_cached

    cached = get_cached()
    return jsonify(
        {
            "adoms": cached["adoms"],
            "last_updated": cached["last_updated"],
            "status": cached["status"],
        }
    )


# ── Users API (for member picker) ─────────────────────────────────────────────


@bp.route("/api/users")
@_admin_required
def api_users_list():
    return jsonify(list_users())


# ── Tabs registry ─────────────────────────────────────────────────────────────


@bp.route("/api/tabs")
@_admin_required
def api_tabs_list():
    return jsonify([{"key": k, "name": v} for k, v in registry.known_tabs().items()])


# ── Map Regions API ───────────────────────────────────────────────────────────


@bp.route("/api/map-regions")
@_admin_required
def api_map_regions_get():
    """Return current region config (names, states, colors)."""
    from app.map_regions import load

    return jsonify(load())


@bp.route("/api/map-regions", methods=["PUT"])
@_admin_required
def api_map_regions_put():
    """Update region colours and state assignments."""
    from app.map_regions import is_valid_color, load, save, validate_regions

    data = request.get_json(silent=True) or {}
    current = load()

    if "regions" in data:
        err = validate_regions(data["regions"])
        if err:
            return jsonify({"error": err}), 400
        current["regions"] = [
            {
                "name": r["name"].strip(),
                "color": r["color"],
                "states": r.get("states", []),
            }
            for r in data["regions"]
        ]

    if "other_color" in data:
        color = data["other_color"]
        if not is_valid_color(color):
            return jsonify({"error": f"Invalid hex color: {color}"}), 400
        current["other_color"] = color

    save(current)
    app_log("INFO", "admin", "Map region config updated", by=session["user"])
    return jsonify(load())


# ── Logs API ──────────────────────────────────────────────────────────────────


@bp.route("/api/logs")
@_admin_required
def api_logs_get():
    level = request.args.get("level") or None
    component = request.args.get("component") or None
    try:
        limit = int(request.args.get("limit", 500))
    except ValueError:
        limit = 500
    entries = get_log_entries(level=level, component=component, limit=limit)
    return jsonify(
        {
            "current_level": get_log_level(),
            "levels": get_log_levels(),
            "count": len(entries),
            "entries": entries,
        }
    )


@bp.route("/api/logs/level", methods=["POST"])
@_admin_required
def api_logs_set_level():
    data = request.get_json(silent=True) or {}
    level = (data.get("level") or "").upper()
    try:
        set_log_level(level)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    app_log("INFO", "admin", "Log level changed", by=session["user"], new_level=level)
    return jsonify({"current_level": get_log_level()})


@bp.route("/api/logs", methods=["DELETE"])
@_admin_required
def api_logs_clear():
    clear_log_entries()
    app_log("INFO", "admin", "Log buffer cleared", by=session["user"])
    return jsonify({"cleared": True})


# ── App settings API ──────────────────────────────────────────────────────────


@bp.route("/api/settings")
@_admin_required
def api_settings_get():
    return jsonify(get_all_settings())


@bp.route("/api/settings", methods=["PUT"])
@_admin_required
def api_settings_put():
    data = request.get_json(silent=True) or {}
    if "external_api_enabled" in data:
        enabled = bool(data["external_api_enabled"])
        set_setting("external_api_enabled", enabled)
        app_log(
            "INFO", "admin", "External API toggled", by=session["user"], enabled=enabled
        )
    if "ai_assist_enabled" in data:
        enabled = bool(data["ai_assist_enabled"])
        set_setting("ai_assist_enabled", enabled)
        app_log(
            "INFO", "admin", "AI Assist toggled", by=session["user"], enabled=enabled
        )
    if "executive_compliant_versions" in data:
        versions = data["executive_compliant_versions"]
        if isinstance(versions, str):
            versions = [v.strip() for v in re.split(r"[\n,]+", versions) if v.strip()]
        elif isinstance(versions, list):
            versions = [str(v).strip() for v in versions if str(v).strip()]
        else:
            versions = []
        set_setting("executive_compliant_versions", versions)
        app_log(
            "INFO",
            "admin",
            "Executive compliant versions updated",
            by=session["user"],
            count=len(versions),
        )
    return jsonify(get_all_settings())


# ── AI Assist usage/cost ────────────────────────────────────────────────────

_AI_USAGE_RANGE_HOURS = {"1h": 1, "4h": 4, "12h": 12, "1d": 24, "7d": 24 * 7}


@bp.route("/api/ai-usage")
@_admin_required
def api_ai_usage():
    """Bucketed AI Assist call/cost history. ?range=1h|4h|12h|1d|7d
    (default 1d), or ?start=<iso>&end=<iso> for a custom window."""
    import datetime as dt

    from app.ai_usage import usage_summary

    start_param = request.args.get("start", "")
    end_param = request.args.get("end", "")

    if start_param and end_param:
        try:
            start = dt.datetime.fromisoformat(start_param)
            end = dt.datetime.fromisoformat(end_param)
        except ValueError:
            return jsonify({"error": "start/end must be ISO 8601 datetimes"}), 400
        if start.tzinfo is None:
            start = start.replace(tzinfo=dt.UTC)
        if end.tzinfo is None:
            end = end.replace(tzinfo=dt.UTC)
    else:
        hours = _AI_USAGE_RANGE_HOURS.get(request.args.get("range", "1d"), 24)
        end = dt.datetime.now(dt.UTC)
        start = end - dt.timedelta(hours=hours)

    if end <= start:
        return jsonify({"error": "end must be after start"}), 400

    summary = usage_summary(start, end)
    summary["start"] = start.isoformat()
    summary["end"] = end.isoformat()
    return jsonify(summary)


@bp.route("/api/host-metrics")
@_admin_required
def api_host_metrics():
    """Bucketed CPU/mem/disk history for the host running this app.
    ?range=1h|4h|12h|1d|7d|14d (default 1h)."""
    from app.host_metrics import get_metrics

    return jsonify(get_metrics(request.args.get("range", "1h")))


@bp.route("/api/host-metrics/ai-summary")
@_admin_required
def api_host_metrics_ai_summary():
    """Deterministic 7-day trend stats for CPU/mem/disk plus AI usage,
    narrated by the configured LLM provider. Trend math is plain Python —
    the LLM only explains numbers already computed here. Best-effort:
    narration failure degrades to narrative=None, never a 500."""
    from app.app_settings import get_setting

    if not get_setting("ai_assist_enabled", False):
        return jsonify({"error": "AI Assist is not enabled"}), 503

    import datetime as _dt

    from app.ai_usage import usage_summary
    from app.host_metrics import get_metrics
    from app.host_metrics_ai import build_trend_narrative, compute_trend

    series = get_metrics("7d")
    trends = {
        "cpu": compute_trend(series["cpu"]),
        "mem": compute_trend(series["mem"]),
        "disk": compute_trend(series["disk"]),
    }

    end = _dt.datetime.now(_dt.UTC)
    start = end - _dt.timedelta(days=7)
    ai_usage = usage_summary(start, end)

    narrative = None
    narrative_error = None
    try:
        narrative = build_trend_narrative(trends, ai_usage, user=session.get("user"))
    except Exception as exc:
        narrative_error = str(exc)

    return jsonify(
        {"trends": trends, "narrative": narrative, "narrative_error": narrative_error}
    )


# ── External API tokens ───────────────────────────────────────────────────────


@bp.route("/api/tokens")
@_admin_required
def api_tokens_list():
    return jsonify(list_tokens())


@bp.route("/api/tokens", methods=["POST"])
@_admin_required
def api_tokens_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    raw, record = create_token(name, created_by=session["user"])
    app_log(
        "INFO",
        "admin",
        "API token created",
        by=session["user"],
        token_name=name,
        token_id=record["id"],
    )
    return jsonify({"token": raw, **record}), 201


@bp.route("/api/tokens/<token_id>", methods=["DELETE"])
@_admin_required
def api_tokens_revoke(token_id: str):
    if not revoke_token(token_id):
        return jsonify({"error": "Token not found"}), 404
    app_log("INFO", "admin", "API token revoked", by=session["user"], token_id=token_id)
    return jsonify({"revoked": token_id})


# ── Config-Diff: SMTP ─────────────────────────────────────────────────────────


@bp.route("/api/smtp")
@_admin_required
def admin_smtp_get():
    cfg = _smtp.load_smtp_config()
    cfg["password"] = "••••••" if cfg.get("password") else ""
    return jsonify(cfg)


@bp.route("/api/smtp", methods=["PUT"])
@_admin_required
def admin_smtp_put():
    data = request.get_json(force=True) or {}
    existing = _smtp.load_smtp_config()
    # Preserve saved password if the masked placeholder was submitted back
    if data.get("password") == "••••••":
        data["password"] = existing.get("password", "")
    _smtp.save_smtp_config(data)
    return jsonify({"ok": True})


@bp.route("/api/smtp/test", methods=["POST"])
@_admin_required
def admin_smtp_test():
    data = request.get_json(force=True) or {}
    to = (data.get("to") or "").strip()
    if not to:
        return jsonify({"ok": False, "error": "No recipient address provided"}), 400
    result = _smtp.test_connection(to)
    return jsonify(result)


# ── Config-Diff: Jobs ─────────────────────────────────────────────────────────


@bp.route("/api/config-diff/jobs")
@_admin_required
def admin_cdiff_jobs_list():
    return jsonify(_sched.get_all_jobs())


@bp.route("/api/config-diff/jobs", methods=["POST"])
@_admin_required
def admin_cdiff_jobs_create():
    data = request.get_json(force=True) or {}
    try:
        job = _sched.create_job(data)
    except (KeyError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(job), 201


@bp.route("/api/config-diff/jobs/<job_id>", methods=["PUT"])
@_admin_required
def admin_cdiff_jobs_update(job_id: str):
    data = request.get_json(force=True) or {}
    try:
        job = _sched.update_job(job_id, data)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(job)


@bp.route("/api/config-diff/jobs/<job_id>", methods=["DELETE"])
@_admin_required
def admin_cdiff_jobs_delete(job_id: str):
    try:
        _sched.delete_job(job_id)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"ok": True})


@bp.route("/api/config-diff/jobs/<job_id>/run", methods=["POST"])
@_admin_required
def admin_cdiff_jobs_run(job_id: str):
    jobs = _sched.get_all_jobs()
    if not any(j["id"] == job_id for j in jobs):
        return jsonify({"error": "Job not found"}), 404
    _sched.run_job_now(job_id)
    return jsonify({"ok": True, "message": "Job started"}), 202


@bp.route("/api/config-diff/jobs/<job_id>/status")
@_admin_required
def admin_cdiff_jobs_status(job_id: str):
    jobs = _sched.get_all_jobs()
    job = next((j for j in jobs if j["id"] == job_id), None)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    last_run = job["runs"][0] if job.get("runs") else None
    return jsonify({"running": _sched.is_job_running(job_id), "last_run": last_run})


# ── Device Review: Scheduled Jobs ─────────────────────────────────────────────


@bp.route("/api/device-review/jobs")
@_admin_required
def admin_dr_jobs_list():
    return jsonify(_dr_sched.get_all_jobs())


@bp.route("/api/device-review/jobs", methods=["POST"])
@_admin_required
def admin_dr_jobs_create():
    data = request.get_json(force=True) or {}
    try:
        job = _dr_sched.create_job(data)
    except (KeyError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(job), 201


@bp.route("/api/device-review/jobs/<job_id>", methods=["PUT"])
@_admin_required
def admin_dr_jobs_update(job_id: str):
    data = request.get_json(force=True) or {}
    try:
        job = _dr_sched.update_job(job_id, data)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(job)


@bp.route("/api/device-review/jobs/<job_id>", methods=["DELETE"])
@_admin_required
def admin_dr_jobs_delete(job_id: str):
    try:
        _dr_sched.delete_job(job_id)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"ok": True})


@bp.route("/api/device-review/jobs/<job_id>/run", methods=["POST"])
@_admin_required
def admin_dr_jobs_run(job_id: str):
    jobs = _dr_sched.get_all_jobs()
    if not any(j["id"] == job_id for j in jobs):
        return jsonify({"error": "Job not found"}), 404
    _dr_sched.run_job_now(job_id)
    return jsonify({"ok": True, "message": "Job started"}), 202


@bp.route("/api/device-review/jobs/<job_id>/status")
@_admin_required
def admin_dr_jobs_status(job_id: str):
    jobs = _dr_sched.get_all_jobs()
    job = next((j for j in jobs if j["id"] == job_id), None)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    last_run = job["runs"][0] if job.get("runs") else None
    return jsonify({"running": _dr_sched.is_job_running(job_id), "last_run": last_run})


# ── Rule Hygiene Scheduled Jobs API ──────────────────────────────────────────


@bp.route("/api/rule-hygiene/jobs")
@_admin_required
def admin_rh_jobs_list():
    return jsonify(_rh_sched.get_all_jobs())


@bp.route("/api/rule-hygiene/jobs", methods=["POST"])
@_admin_required
def admin_rh_jobs_create():
    data = request.get_json(force=True) or {}
    try:
        job = _rh_sched.create_job(data)
    except (KeyError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(job), 201


@bp.route("/api/rule-hygiene/jobs/<job_id>", methods=["PUT"])
@_admin_required
def admin_rh_jobs_update(job_id: str):
    data = request.get_json(force=True) or {}
    try:
        job = _rh_sched.update_job(job_id, data)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(job)


@bp.route("/api/rule-hygiene/jobs/<job_id>", methods=["DELETE"])
@_admin_required
def admin_rh_jobs_delete(job_id: str):
    try:
        _rh_sched.delete_job(job_id)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"ok": True})


@bp.route("/api/rule-hygiene/jobs/<job_id>/run", methods=["POST"])
@_admin_required
def admin_rh_jobs_run(job_id: str):
    jobs = _rh_sched.get_all_jobs()
    if not any(j["id"] == job_id for j in jobs):
        return jsonify({"error": "Job not found"}), 404
    _rh_sched.run_job_now(job_id)
    return jsonify({"ok": True, "message": "Job started"}), 202


@bp.route("/api/rule-hygiene/jobs/<job_id>/status")
@_admin_required
def admin_rh_jobs_status(job_id: str):
    jobs = _rh_sched.get_all_jobs()
    job = next((j for j in jobs if j["id"] == job_id), None)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    last_run = job["runs"][0] if job.get("runs") else None
    return jsonify({"running": _rh_sched.is_job_running(job_id), "last_run": last_run})
