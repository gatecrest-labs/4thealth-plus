"""External API — bearer-token-authenticated zone policy endpoints for FW-Analyst.

All routes live under /external/api/.  No browser session is required.

Authentication
--------------
  Authorization: Bearer <token>

Tokens are created in Admin → External API and stored (hashed) in api_tokens.json.

Feature gate
------------
The external API can be disabled entirely from Admin → External API.
When disabled every route returns 503 with {"error": "External API is disabled"}.

Endpoints
---------
  POST /external/api/zone/query     Query src→dst flows against zone policy DB
  GET  /external/api/zone/zones     List all zones + subnets
  GET  /external/api/zone/policies  List all segmentation policies
  GET  /external/api/executive/summary  Fleet-wide metrics for the 4tExecutive dashboard
"""

import re

from flask import Blueprint, jsonify, request

import app.zone_db as zdb
from app.api_tokens import validate_token
from app.app_logger import app_log
from app.app_settings import get_setting
from app.security import internal_api_error

bp = Blueprint("external_api", __name__, url_prefix="/external/api")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _feature_enabled():
    return get_setting("external_api_enabled", False)


def _authenticate():
    """Return the validated token record or None."""
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    raw = auth[7:].strip()
    return validate_token(raw)


def _gate():
    """Return an error response tuple if the request should be rejected, else None."""
    if not _feature_enabled():
        return jsonify({"error": "External API is disabled"}), 503
    token = _authenticate()
    if token is None:
        return jsonify({"error": "Unauthorized — valid Bearer token required"}), 401
    return None


def _parse_endpoints(raw: str) -> list:
    items = re.split(r"[\n,\s]+", raw.strip())
    return [i.strip() for i in items if i.strip()]


_MAX_EOL_DEVICES = 50


def _version_sort_key(version: str) -> tuple[int, int, int, int]:
    """Parse "vMAJOR.MR.PATCH" for ascending (oldest-first) sort.

    Returns (1, 0, 0, 0) for anything unparseable (e.g. "n/a") so it always
    sorts after every real version — being unable to determine a device's
    version is not the same as it being the oldest one.
    """
    m = re.match(r"^v(\d+)\.(\d+)(?:\.(\d+))?$", version or "")
    if not m:
        return (1, 0, 0, 0)
    major, mr, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    return (0, major, mr, patch)


def _version_breakdown() -> dict:
    """Firmware version -> {count, eol}, from the all-ADOM versions cache.

    "eol_devices" is a reserved key in this dict (not a version string): a
    capped, oldest-first list of every device running an EOL version, for
    the drill-down details view. See docs/api-reference.md for the cap and
    ordering.
    """
    from collections import Counter

    from app import versions_cache
    from app.version_eol import is_eol

    devices = versions_cache.get_cached().get("devices") or []
    counts = Counter(d.get("version", "n/a") for d in devices)
    breakdown = {
        version: {"count": count, "eol": is_eol(version)}
        for version, count in counts.items()
    }

    eol_devices = [
        {
            "device": d.get("name", ""),
            "adom": d.get("adom", ""),
            "version": d.get("version", "n/a"),
        }
        for d in devices
        if is_eol(d.get("version", "n/a"))
    ]
    eol_devices.sort(key=lambda d: (_version_sort_key(d["version"]), d["device"]))
    breakdown["eol_devices"] = eol_devices[:_MAX_EOL_DEVICES]
    return breakdown


def _last_backup_status() -> str | None:
    """Status of the most recently completed scheduled backup run, across all jobs."""
    from app import backup_scheduler

    latest_run = None
    for job in backup_scheduler.get_all_jobs():
        runs = job.get("runs") or []
        if runs and (
            latest_run is None or runs[0]["started_at"] > latest_run["started_at"]
        ):
            latest_run = runs[0]
    if latest_run is None:
        return None
    status = latest_run.get("status")
    return "ok" if status == "success" else status


def _ai_usage_24h() -> tuple[dict, dict]:
    """AI Assist totals and the per-feature breakdown over the trailing 24h.

    Both come from one usage_summary() call so the payload costs a single
    query rather than two scans of the same 24h window.
    """
    import datetime as dt

    from app.ai_usage import usage_summary

    now = dt.datetime.now(dt.UTC)
    usage = usage_summary(
        now - dt.timedelta(hours=24), now, num_buckets=1, by_feature=True
    )
    totals = {
        "ai_connection_count_24h": usage["total_calls"],
        "ai_estimated_cost_24h_usd": round(usage["total_cost_usd"], 2),
    }
    return totals, usage.get("by_feature", {})


def _device_review_rollup() -> dict | None:
    """Latest device review rollup, or None if no rollup has run yet.

    "details" is a capped, most-severe-first per-device drill-down — see
    app.device_review_rollup.build_details() for the exact cap/ordering.
    Older persisted records (written before this field existed) fall back
    to [] rather than a missing key, so old history entries still validate
    against the current schema.
    """
    from app.device_review_rollup import get_latest

    latest = get_latest()
    if latest is None:
        return None
    return {
        "devices_reviewed": latest["devices_reviewed"],
        "devices_with_failures": latest["devices_with_failures"],
        "findings_by_severity": latest["findings_by_severity"],
        "top_failing_checks": latest["top_failing_checks"],
        "collected_at": latest["ran_at"],
        "details": latest.get("details", []),
    }


def _change_control(summary: dict) -> dict:
    """Change-control metrics.

    devices_out_of_sync comes from the device sweep already read into
    `summary` by the caller (freshness: summary["device_sweep_collected_at"]).
    admin_changes_24h/admin_changes_by_user come from the separate hourly
    audit-log sweep in app.change_control_cache, which has its own
    collected_at — used as this object's own collected_at, since the
    devices_out_of_sync half is already covered by the top-level
    device_sweep_collected_at field.

    oldest_pending_change_days is intentionally omitted: see the docstring
    at the top of app/executive_summary_cache.py for why no per-device
    modification timestamp is currently available from FortiManager's
    dvmdb device object in this codebase's confirmed API knowledge.
    """
    from app.change_control_cache import get_latest as get_change_control_latest

    latest = get_change_control_latest()
    return {
        "devices_out_of_sync": summary.get("devices_out_of_sync"),
        "admin_changes_24h": latest["admin_changes_24h"] if latest else None,
        "admin_changes_by_user": latest["admin_changes_by_user"] if latest else [],
        "collected_at": latest["collected_at"] if latest else None,
    }


def _lifecycle(summary: dict) -> dict:
    """Hardware end-of-support exposure, sourced from the device sweep's
    lifecycle counts (app.executive_summary_cache._lifecycle_counts(),
    matched against app.model_eos). Shares device_sweep_collected_at as
    its own collected_at since both come from the same sweep."""
    return {
        "devices_hw_eos": summary.get("devices_hw_eos"),
        "devices_hw_eos_12m": summary.get("devices_hw_eos_12m"),
        "models_unknown": summary.get("models_unknown") or [],
        "collected_at": summary.get("device_sweep_collected_at"),
    }


def _silent_devices(summary: dict) -> dict:
    """Devices FortiManager reports as not connected — see
    app.executive_summary_cache._build_silent_devices() and
    docs/superpowers/specs/2026-09-12-silent-devices-proxy-spike.md for
    why last_log_at is always None in this release."""
    return {
        "devices_silent": summary.get("devices_silent"),
        "details": summary.get("silent_devices_details") or [],
        "collected_at": summary.get("device_sweep_collected_at"),
    }


def _freshness(payload: dict, summary: dict) -> dict:
    """When each rollup's underlying data was actually collected — the
    preferred way to check staleness as of schema_version 3. Every v1/v2
    per-object "collected_at" (or "ran_at"-derived "collected_at") field
    is kept for backward compatibility; this map is just a single place
    to check all of them without knowing which nested object each one
    lives in.
    """
    from app.pending_status_cache import get_cache_status

    device_review = payload.get("device_review") or {}
    rule_hygiene = payload.get("rule_hygiene") or {}
    psirt = payload.get("psirt") or {}
    change_control = payload.get("change_control") or {}
    lifecycle = payload.get("lifecycle") or {}

    return {
        "device_review": device_review.get("collected_at"),
        "rule_hygiene": rule_hygiene.get("collected_at"),
        "version_breakdown": summary.get("device_sweep_collected_at"),
        "silent_devices": summary.get("device_sweep_collected_at"),
        "psirt": psirt.get("collected_at"),
        "change_control": change_control.get("collected_at"),
        "lifecycle": lifecycle.get("collected_at"),
        "infra": summary.get("device_sweep_collected_at"),
        "pending_status": get_cache_status().get("last_updated"),
    }


def _device_backup() -> dict:
    """Device configuration backup age, from the daily
    app.device_backup_cache sweep — see that module and
    app.fmg_client.FMGClient.get_adom_revisions() for the confirmed FMG
    revision-history endpoint. None counts (never swept yet) rather than 0,
    same "unknown never renders as a false negative" convention as
    app.model_eos."""
    from app.device_backup_cache import get_latest

    latest = get_latest()
    if latest is None:
        return {
            "devices_backup_ok": None,
            "devices_backup_stale_7d": None,
            "devices_backup_never": None,
            "collected_at": None,
        }
    return {
        "devices_backup_ok": latest.get("devices_backup_ok"),
        "devices_backup_stale_7d": latest.get("devices_backup_stale_7d"),
        "devices_backup_never": latest.get("devices_backup_never"),
        "collected_at": latest.get("collected_at"),
    }


def _psirt_rollup() -> dict:
    """Fleet PSIRT exposure — see app.psirt_store.compute_psirt_rollup()
    for how open_advisories/devices_*/kev_exposed_devices/top_advisory/
    mean_days_to_remediate_90d are derived from psirt.db."""
    from app import psirt_store

    return psirt_store.compute_psirt_rollup()


def _hygiene_rollup() -> dict | None:
    """Latest persisted rule-hygiene rollup, in the in-memory field shape.

    Used as a cold-start fallback: the in-memory cache is empty after a
    restart until the next hourly hygiene sweep completes, but the persisted
    rollup survives.  Translates the record's ``ran_at`` to ``collected_at``,
    the same way _device_review_rollup() does.
    """
    from app.hygiene_rollup import get_latest

    latest = get_latest()
    if latest is None:
        return None
    return {
        "rule_findings_total": latest["rule_findings_total"],
        "rule_findings_by_type": latest["rule_findings_by_type"],
        "collected_at": latest["ran_at"],
        "details": latest.get("details", []),
    }


# ── Zone query ────────────────────────────────────────────────────────────────


@bp.route("/zone/query", methods=["POST"])
def ext_zone_query():
    err = _gate()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    src_raw = data.get("src", "")
    dst_raw = data.get("dst", "")
    service = data.get("service", "")
    verbose = bool(data.get("verbose", True))

    src_list = _parse_endpoints(src_raw) if isinstance(src_raw, str) else src_raw
    dst_list = _parse_endpoints(dst_raw) if isinstance(dst_raw, str) else dst_raw

    if not src_list or not dst_list:
        return jsonify({"error": "src and dst are required"}), 400

    if not zdb.db_available():
        return jsonify({"error": "policy_db.json not found"}), 503

    try:
        token = _authenticate()
        app_log(
            "DEBUG",
            "external_api",
            "Zone query",
            token_name=token.get("name") if token else "?",
            src=src_list[:3],
            dst=dst_list[:3],
        )
        results = zdb.run_query(src_list, dst_list, service or None, verbose=verbose)
        return jsonify(results)
    except Exception as exc:
        return internal_api_error("external_api", exc)


# ── Zone list ─────────────────────────────────────────────────────────────────


@bp.route("/zone/zones")
def ext_zone_zones():
    err = _gate()
    if err:
        return err

    if not zdb.db_available():
        return jsonify({"error": "policy_db.json not found"}), 503

    try:
        db = zdb.load_db()
        zones = db["zones"]
        total_subnets = sum(len(z.get("subnets", [])) for z in zones.values())
        zone_list = [
            {
                "name": name,
                "domain": z.get("domain", ""),
                "is_shared": z.get("is_shared", False),
                "description": z.get("description", ""),
                "subnets": z.get("subnets", []),
                "children": z.get("children", []),
                "parents": z.get("parents", []),
            }
            for name, z in sorted(zones.items())
        ]
        return jsonify({"zones": zone_list, "total_subnets": total_subnets})
    except Exception as exc:
        return internal_api_error("external_api", exc)


# ── Policy list ───────────────────────────────────────────────────────────────


@bp.route("/zone/policies")
def ext_zone_policies():
    err = _gate()
    if err:
        return err

    if not zdb.db_available():
        return jsonify({"error": "policy_db.json not found"}), 503

    try:
        db = zdb.load_db()
        rows = [{"index": i, **p} for i, p in enumerate(db["policies"])]
        return jsonify(rows)
    except Exception as exc:
        return internal_api_error("external_api", exc)


# ── Executive summary ────────────────────────────────────────────────────────


@bp.route("/executive/summary")
def ext_executive_summary():
    err = _gate()
    if err:
        return err

    from app.executive_summary_cache import get_summary

    summary = get_summary()
    payload = {
        "hygiene_score": summary.get("hygiene_score"),
        "version_compliance_pct": summary.get("version_compliance_pct"),
        "pending_config_diff_count": summary.get("pending_config_diff_count"),
        "firewall_online_count": summary.get("firewall_online_count"),
        "firewalls_total": summary.get("firewalls_total"),
        "firewall_managed_count": summary.get("firewalls_total"),
        "adom_count": summary.get("adom_count"),
        "rule_count_total": summary.get("rule_count_total"),
        "version_breakdown": _version_breakdown(),
        "last_backup_status": _last_backup_status(),
        "status": summary.get("status"),
        "last_updated": summary.get("last_updated"),
        "schema_version": 3,
        "device_sweep_status": summary.get("device_sweep_status"),
        "hygiene_sweep_status": summary.get("hygiene_sweep_status"),
        "device_sweep_collected_at": summary.get("device_sweep_collected_at"),
        "hygiene_sweep_collected_at": summary.get("hygiene_sweep_collected_at"),
        "rule_count_collected_at": summary.get("hygiene_sweep_collected_at"),
        "device_review": _device_review_rollup(),
        "rule_hygiene": summary.get("rule_hygiene") or _hygiene_rollup(),
        "psirt": _psirt_rollup(),
        "change_control": _change_control(summary),
        "lifecycle": _lifecycle(summary),
        "silent_devices": _silent_devices(summary),
        "device_backup": _device_backup(),
        "by_adom": summary.get("by_adom") or {},
        "infra": summary.get("infra") or [],
    }
    payload["freshness"] = _freshness(payload, summary)

    ai_enabled = get_setting("ai_assist_enabled", False)
    payload["ai_enabled"] = ai_enabled
    if ai_enabled:
        usage_24h, usage_by_feature = _ai_usage_24h()
        payload["ai_usage_24h"] = usage_24h
        payload["ai_usage_by_feature"] = usage_by_feature

    return jsonify(payload)
