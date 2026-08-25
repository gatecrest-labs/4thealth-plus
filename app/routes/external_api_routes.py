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
    return jsonify(
        {
            "hygiene_score": summary.get("hygiene_score"),
            "version_compliance_pct": summary.get("version_compliance_pct"),
            "pending_config_diff_count": summary.get("pending_config_diff_count"),
            "firewall_online_count": summary.get("firewall_online_count"),
            "firewalls_total": summary.get("firewalls_total"),
            "status": summary.get("status"),
            "last_updated": summary.get("last_updated"),
        }
    )
