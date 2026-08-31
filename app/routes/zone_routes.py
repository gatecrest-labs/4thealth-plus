"""Zone Policy tab — browser UI page + JSON API.

Page:
  GET  /zone-policy

API (all JSON):
  POST /api/zone/query            query src→dst flows
  GET  /api/zone/zones            list all zones + subnets
  GET  /api/zone/policies         list all policy rules
  GET  /api/zone/validate         run validation, return report
  GET  /api/zone/segmentation-report  segmentation effectiveness report
  POST /api/zone/zone/add         add a zone
  POST /api/zone/zone/remove      remove a zone
  POST /api/zone/zone/modify      modify a zone field
  POST /api/zone/subnet/add       add a subnet to a zone
  POST /api/zone/subnet/remove    remove a subnet from a zone
  POST /api/zone/policy/add       add a policy rule
  POST /api/zone/policy/remove    remove a policy rule by index
  POST /api/zone/policy/modify    modify a policy rule field
"""

import re
import shutil
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, session

import app.zone_db as zdb
from app import registry
from app.decorators import admin_required, tab_required
from app.security import internal_api_error

bp = Blueprint("zone_policy", __name__)

registry.register("zone_policy", "Zone Policy", "zone_policy.zone_policy_page")


# ── Page ──────────────────────────────────────────────────────────────────────


@bp.route("/zone-policy")
@tab_required("zone_policy")
def zone_policy_page():
    return render_template(
        "zone_policy.html",
        user=session["user"],
        db_available=zdb.db_available(),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _ok(message: str, **extra):
    return jsonify({"ok": True, "message": message, **extra})


def _err(message: str, code: int = 400):
    return jsonify({"ok": False, "error": message}), code


def _parse_endpoints(raw: str) -> list[str]:
    items = re.split(r"[\n,\s]+", raw.strip())
    return [i.strip() for i in items if i.strip()]


# ── Query ─────────────────────────────────────────────────────────────────────


@bp.route("/api/zone/query", methods=["POST"])
@tab_required("zone_policy")
def api_query():
    data = request.get_json(silent=True) or {}
    src_raw = data.get("src", "")
    dst_raw = data.get("dst", "")
    service = data.get("service", "")
    verbose = bool(data.get("verbose", True))

    src_list = _parse_endpoints(src_raw) if isinstance(src_raw, str) else src_raw
    dst_list = _parse_endpoints(dst_raw) if isinstance(dst_raw, str) else dst_raw

    if not src_list or not dst_list:
        return _err("src and dst are required")

    if not zdb.db_available():
        return _err("policy_db.json not found", 503)

    try:
        results = zdb.run_query(src_list, dst_list, service or None, verbose=verbose)
        return jsonify(results)
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


# ── Browse ────────────────────────────────────────────────────────────────────


@bp.route("/api/zone/zones")
@tab_required("zone_policy")
def api_zones():
    if not zdb.db_available():
        return _err("policy_db.json not found", 503)
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
        return internal_api_error("zone_policy", exc)


@bp.route("/api/zone/policies")
@tab_required("zone_policy")
def api_policies():
    if not zdb.db_available():
        return _err("policy_db.json not found", 503)
    try:
        db = zdb.load_db()
        rows = [{"index": i, **p} for i, p in enumerate(db["policies"])]
        return jsonify(rows)
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


# ── Validate ──────────────────────────────────────────────────────────────────


@bp.route("/api/zone/validate")
@tab_required("zone_policy")
def api_validate():
    if not zdb.db_available():
        return _err("policy_db.json not found", 503)
    try:
        db = zdb.load_db()
        return jsonify(zdb.validate_db(db))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


@bp.route("/api/zone/segmentation-report")
@tab_required("zone_policy")
def api_segmentation_report():
    if not zdb.db_available():
        return _err("policy_db.json not found", 503)
    try:
        db = zdb.load_db()
        return jsonify(zdb.compute_segmentation_report(db))
    except Exception as exc:
        return internal_api_error("segmentation report", exc)


# ── Backup ────────────────────────────────────────────────────────────────────


@bp.route("/api/zone/backup", methods=["POST"])
@admin_required
def api_backup():
    if not zdb.db_available():
        return _err("policy_db.json not found", 503)
    try:
        backup_dir = zdb.DB_PATH.parent / "backups"
        backup_dir.mkdir(exist_ok=True)
        today = datetime.now().astimezone().date().strftime("%Y%m%d")
        # find next slot 001-100, wrapping back to 001 at 101
        for n in range(1, 102):
            seq = ((n - 1) % 100) + 1
            name = f"policy_db_{today}_{seq:03d}.json"
            dest = backup_dir / name
            if not dest.exists():
                break
        shutil.copy2(zdb.DB_PATH, dest)
        return _ok(f"Backed up to backups/{name}", filename=name)
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


# ── Zone mutations (admin only) ───────────────────────────────────────────────


@bp.route("/api/zone/zone/add", methods=["POST"])
@admin_required
def api_zone_add():
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    if not name:
        return _err("name is required")
    try:
        db = zdb.load_db()
        msg = zdb.zone_add(
            db,
            name,
            domain=d.get("domain", "Default"),
            description=d.get("description", ""),
            is_shared=bool(d.get("is_shared", False)),
        )
        return _ok(msg)
    except (ValueError, KeyError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


@bp.route("/api/zone/zone/remove", methods=["POST"])
@admin_required
def api_zone_remove():
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    if not name:
        return _err("name is required")
    try:
        db = zdb.load_db()
        msg = zdb.zone_remove(db, name)
        return _ok(msg)
    except (KeyError, ValueError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


@bp.route("/api/zone/zone/modify", methods=["POST"])
@admin_required
def api_zone_modify():
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    field = (d.get("field") or "").strip()
    value = str(d.get("value", "")).strip()
    if not name or not field:
        return _err("name and field are required")
    try:
        db = zdb.load_db()
        msg = zdb.zone_modify(db, name, field, value)
        return _ok(msg)
    except (KeyError, ValueError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


@bp.route("/api/zone/subnet/add", methods=["POST"])
@admin_required
def api_subnet_add():
    d = request.get_json(silent=True) or {}
    zone = (d.get("zone") or "").strip()
    subnet = (d.get("subnet") or "").strip()
    desc = (d.get("description") or "").strip()
    if not zone or not subnet:
        return _err("zone and subnet are required")
    try:
        db = zdb.load_db()
        msg = zdb.subnet_add(db, zone, subnet, desc)
        return _ok(msg)
    except (KeyError, ValueError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


@bp.route("/api/zone/subnet/remove", methods=["POST"])
@admin_required
def api_subnet_remove():
    d = request.get_json(silent=True) or {}
    zone = (d.get("zone") or "").strip()
    subnet = (d.get("subnet") or "").strip()
    if not zone or not subnet:
        return _err("zone and subnet are required")
    try:
        db = zdb.load_db()
        msg = zdb.subnet_remove(db, zone, subnet)
        return _ok(msg)
    except (KeyError, ValueError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


# ── Policy mutations (admin only) ─────────────────────────────────────────────


@bp.route("/api/zone/policy/add", methods=["POST"])
@admin_required
def api_policy_add():
    d = request.get_json(silent=True) or {}
    required = ("policy_set", "from_zone", "to_zone", "access_type")
    missing = [k for k in required if not (d.get(k) or "").strip()]
    if missing:
        return _err(f"Missing fields: {', '.join(missing)}")
    raw_svc = d.get("services", "")
    svc_list = zdb.normalize_service_list(
        [s.strip() for s in raw_svc.split(",") if s.strip()]
        if isinstance(raw_svc, str)
        else raw_svc
    )
    try:
        db = zdb.load_db()
        msg = zdb.policy_add(
            db,
            policy_set=d["policy_set"].strip(),
            from_zone=d["from_zone"].strip(),
            to_zone=d["to_zone"].strip(),
            access_type=d["access_type"].strip(),
            severity=d.get("severity", "high"),
            services=svc_list,
            description=d.get("description", ""),
        )
        return _ok(msg)
    except (ValueError, IndexError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


@bp.route("/api/zone/policy/remove", methods=["POST"])
@admin_required
def api_policy_remove():
    d = request.get_json(silent=True) or {}
    try:
        idx = int(d.get("index", -1))
    except (TypeError, ValueError):
        return _err("index must be an integer")
    try:
        db = zdb.load_db()
        msg = zdb.policy_remove(db, idx)
        return _ok(msg)
    except (IndexError, ValueError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)


@bp.route("/api/zone/policy/modify", methods=["POST"])
@admin_required
def api_policy_modify():
    d = request.get_json(silent=True) or {}
    field = (d.get("field") or "").strip()
    value = str(d.get("value", "")).strip()
    if not field:
        return _err("field is required")
    try:
        idx = int(d.get("index", -1))
    except (TypeError, ValueError):
        return _err("index must be an integer")
    try:
        db = zdb.load_db()
        msg = zdb.policy_modify(db, idx, field, value)
        return _ok(msg)
    except (IndexError, ValueError, KeyError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return internal_api_error("zone_policy", exc)
