"""Config-Delta tab — shows FortiManager install-pending diffs per device.

Page:
  GET  /pending-changes

API (JSON, all read-only):
  GET  /api/pending-changes/adoms
       returns: [{name, desc}, ...]

  GET  /api/pending-changes/adoms/<adom>/devices
       returns: [{name, ip, platform, version, conf_status, db_status, pkg_status, serial}, ...]
       Served from pending_status_cache (30-min background refresh); falls back to live
       FMG fetch on cold start.

  POST /api/pending-changes/adoms/<adom>/device/<device>/preview
       returns: {task_id: str}  — starts async FMG chain, poll GET /task/<task_id> for result

  GET  /api/pending-changes/task/<task_id>
       returns: {status: "running"|"done"|"error", step: str, result: dict|null, error: str|null}
       Task entries are evicted after 10 minutes.

  GET  /api/pending-changes/ai-summary-status
       returns: {available: bool} — reuses the ai_assist_enabled setting

  POST /api/pending-changes/adoms/<adom>/device/<device>/ai-summary
       body: {summary: dict, vdoms: list} — the parsed diff already held in
       memory from the preview task result
       returns: {narrative: str|null, narrative_error: str|null}
       503 if AI Assist is disabled, 400 if vdoms is missing or not a list

Task state is stored as per-task JSON files under a shared temp directory so
all gunicorn workers see the same state regardless of which worker handles the
POST vs the polling GETs.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, session

from app import registry
from app.decorators import check_adom_access, tab_required
from app.fmg_client import FMGError, parse_preview_diff
from app.fmg_helpers import make_client
from app.groups import get_allowed_adoms
from app.security import internal_api_error, upstream_api_error

bp = Blueprint("pending_changes", __name__)

registry.register(
    "pending_changes", "Config-Delta", "pending_changes.pending_changes_page"
)

# ── Async preview task store (file-based, shared across all gunicorn workers) ─
# Each task is a JSON file: <_TASK_DIR>/<task_id>.json
# Files are written atomically via a tmp-then-rename pattern so readers always
# see a complete JSON document.  created_at is a Unix wall-clock float so the
# TTL check works in any worker process.

_TASK_TTL_SECS = 600  # evict completed/failed entries after 10 minutes
# UID-scoped so each OS user gets their own directory — avoids permission
# collisions when CI (root/deploy) and the service account (4thealth) both
# create the directory on the same host.
_TASK_DIR: Path = Path(tempfile.gettempdir()) / f"4thealth_preview_tasks_{os.getuid()}"

_WRITE_LOCK = threading.Lock()  # serialise writes within a single worker only


def _ensure_task_dir() -> None:
    _TASK_DIR.mkdir(exist_ok=True)


def _task_path(task_id: str) -> Path:
    return _TASK_DIR / f"{task_id}.json"


def _write_task(task_id: str, data: dict) -> None:
    _ensure_task_dir()
    path = _task_path(task_id)
    tmp = path.with_suffix(".tmp")
    with _WRITE_LOCK:
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(path)


def _read_task(task_id: str) -> dict | None:
    path = _task_path(task_id)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _evict_old_tasks() -> None:
    _ensure_task_dir()
    now = time.time()
    for f in _TASK_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if now - data.get("created_at", 0) > _TASK_TTL_SECS:
                f.unlink(missing_ok=True)
        except Exception:
            pass


# ── Bulk preview helper (used by scheduler + browser export) ─────────────────


def bulk_preview_adom(adom: str, max_workers: int = 10) -> list[dict]:
    """Fetch install-preview diffs for every device in *adom* in parallel.

    Returns a list of result dicts — one per device — in the same shape the
    browser bulk-export uses:
      {"device", "ip", "status": "ok"|"no_changes"|"error",
       "summary", "vdoms", "raw", "error"}
    """
    from app.fmg_client import parse_preview_diff
    from app.fmg_helpers import make_client

    with make_client() as client:
        raw_devices = client.get_devices_with_sync_status(adom)

    seen: set[str] = set()
    devices = []
    for d in raw_devices:
        if not isinstance(d, dict):
            continue
        name = d.get("name", "")
        if not name or name in seen:
            continue
        seen.add(name)
        devices.append({"name": name, "ip": d.get("ip", d.get("mgmt_ip", ""))})

    def _preview_one(dev: dict) -> dict:
        try:
            with make_client() as client:
                raw = client.get_install_preview(adom, dev["name"])
                vdoms = client.get_device_vdoms(adom, dev["name"])
                vdom_names = (
                    [
                        v.get("name", "root")
                        for v in vdoms
                        if isinstance(v, dict) and v.get("name")
                    ]
                    if vdoms
                    else ["root"]
                )
                pkg_status = client.get_device_pkg_status(adom, dev["name"], vdom_names)
            parsed = parse_preview_diff(raw)
            has_changes = any(v.get("changes") for v in parsed.get("vdoms", []))
            if has_changes:
                status = "ok"
            elif pkg_status == "modified":
                # FMG package is marked modified but install-preview produced no
                # CLI diff — changes may be metadata-only or already on the device.
                status = "pkg_pending_no_diff"
            else:
                status = "no_changes"
            return {
                "device": dev["name"],
                "ip": dev["ip"],
                "status": status,
                "pkg_status": pkg_status,
                "summary": parsed["summary"] if has_changes else {},
                "vdoms": parsed["vdoms"] if has_changes else [],
                "raw": parsed["raw"] if has_changes else "",
                "error": None,
            }
        except Exception as exc:
            return {
                "device": dev["name"],
                "ip": dev["ip"],
                "status": "error",
                "pkg_status": "",
                "summary": {},
                "vdoms": [],
                "raw": "",
                "error": str(exc),
            }

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_preview_one, d): d for d in devices}
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ── Page ──────────────────────────────────────────────────────────────────────


@bp.route("/pending-changes")
@tab_required("pending_changes")
def pending_changes_page():
    return render_template("pending_changes.html", user=session["user"])


# ── API: ADOM list ────────────────────────────────────────────────────────────


@bp.route("/api/pending-changes/adoms")
@tab_required("pending_changes")
def pending_changes_adoms():
    try:
        with make_client() as client:
            raw = client.get_adoms()
        items = [
            {"name": a.get("name", a.get("adom", "")), "desc": a.get("desc", "")}
            for a in raw
            if isinstance(a, dict)
        ]
        items = [
            i for i in items if i["name"] and not i["name"].lower().startswith("forti")
        ]
        allowed = get_allowed_adoms(
            session.get("user", ""), ad_groups=session.get("ad_groups", [])
        )
        if allowed is not None:
            items = [i for i in items if i["name"] in allowed]
        return jsonify(items)
    except FMGError as exc:
        return upstream_api_error("pending_changes", exc)
    except Exception as exc:
        return internal_api_error("pending_changes", exc)


# ── API: device list with sync status ─────────────────────────────────────────


@bp.route("/api/pending-changes/adoms/<adom>/devices")
@tab_required("pending_changes")
def pending_changes_devices(adom: str):
    if err := check_adom_access(adom):
        return err
    try:
        from app.pending_status_cache import get_cached_devices

        cached = get_cached_devices(adom)
        if cached is not None:
            return jsonify(cached)

        # Cache cold (first startup) — fall back to live fetch
        with make_client() as client:
            raw = client.get_devices_with_sync_status(adom)

            seen: set[str] = set()
            base_devices = []
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
                if mr is not None and patch is not None:
                    version = f"v{major}.{mr}.{patch}"
                elif mr is not None:
                    version = f"v{major}.{mr}"
                else:
                    version = "n/a"
                embedded_vdoms = d.get("vdom") or []
                vdom_list = (
                    [
                        v.get("name", "root")
                        for v in embedded_vdoms
                        if isinstance(v, dict) and v.get("name")
                    ]
                    if embedded_vdoms
                    else ["root"]
                )
                base_devices.append(
                    {
                        "name": name,
                        "ip": d.get("ip", d.get("mgmt_ip", "")),
                        "platform": d.get("platform_str", d.get("platform", "")),
                        "version": version,
                        "conf_status": d.get("conf_status", "unknown"),
                        "db_status": d.get("db_status", "unknown"),
                        "serial": d.get("sn", d.get("serial", "")),
                        "_vdom_list": vdom_list,
                    }
                )

            def _fetch_pkg(entry: dict) -> tuple[str, str]:
                try:
                    return entry["name"], client.get_device_pkg_status(
                        adom, entry["name"], entry["_vdom_list"]
                    )
                except Exception:
                    return entry["name"], ""

            pkg_map: dict[str, str] = {}
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {pool.submit(_fetch_pkg, e): e["name"] for e in base_devices}
                for fut in as_completed(futures):
                    name, status = fut.result()
                    pkg_map[name] = status

        devices = [
            {k: v for k, v in d.items() if k != "_vdom_list"}
            | {"pkg_status": pkg_map.get(d["name"], "")}
            for d in base_devices
        ]
        return jsonify(devices)
    except FMGError as exc:
        return upstream_api_error("pending_changes", exc)
    except Exception as exc:
        return internal_api_error("pending_changes", exc)


# ── API: install preview ───────────────────────────────────────────────────────


@bp.route("/api/pending-changes/adoms/<adom>/device/<device>/preview", methods=["POST"])
@tab_required("pending_changes")
def pending_changes_preview(adom: str, device: str):
    if err := check_adom_access(adom):
        return err

    _evict_old_tasks()
    task_id = str(uuid.uuid4())
    _write_task(
        task_id,
        {
            "status": "running",
            "step": "Starting…",
            "result": None,
            "error": None,
            "created_at": time.time(),
        },
    )

    def _run(task_id=task_id, adom=adom, device=device):
        def _set_step(msg: str) -> None:
            data = _read_task(task_id)
            if data is not None:
                data["step"] = msg
                _write_task(task_id, data)

        try:
            _set_step("Fetching device info…")
            with make_client() as client:
                raw_devices = client.get_devices_with_sync_status(adom)
                device_meta = next(
                    (
                        d
                        for d in raw_devices
                        if d.get("name", "").lower() == device.lower()
                    ),
                    {},
                )
                _set_step("Checking package status…")
                pkg_status = client.get_package_status(adom, device)
                _set_step("Staging policy package…")
                raw = client.get_install_preview(adom, device)

            _set_step("Parsing diff…")
            parsed = parse_preview_diff(raw)
            result = {
                "device": device,
                "ip": device_meta.get("ip", device_meta.get("mgmt_ip", "")),
                "conf_status": device_meta.get("conf_status", "unknown"),
                "db_status": device_meta.get("db_status", "unknown"),
                "pkg_status": pkg_status,
                "summary": parsed["summary"],
                "vdoms": parsed["vdoms"],
                "raw": parsed["raw"],
            }
            data = _read_task(task_id)
            if data is not None:
                data.update({"status": "done", "step": "Done", "result": result})
                _write_task(task_id, data)
        except Exception as exc:
            data = _read_task(task_id)
            if data is not None:
                data.update({"status": "error", "step": "Failed", "error": str(exc)})
                _write_task(task_id, data)

    t = threading.Thread(target=_run, name=f"preview_{task_id[:8]}", daemon=True)
    t.start()
    return jsonify({"task_id": task_id})


# ── AI Summary ─────────────────────────────────────────────────────────────


@bp.route("/api/pending-changes/ai-summary-status")
@tab_required("pending_changes")
def pc_ai_summary_status():
    from app.app_settings import get_setting

    return jsonify({"available": get_setting("ai_assist_enabled", False)})


@bp.route(
    "/api/pending-changes/adoms/<adom>/device/<device>/ai-summary", methods=["POST"]
)
@tab_required("pending_changes")
def pc_ai_summary(adom: str, device: str):
    """Narrate an already-parsed install-preview diff for one device. The LLM
    never alters a diff line — it only summarizes what parse_preview_diff()
    already produced. Best-effort: any failure degrades to narrative=None."""
    if err := check_adom_access(adom):
        return err

    from app.app_settings import get_setting

    if not get_setting("ai_assist_enabled", False):
        return jsonify({"error": "AI Assist is not enabled"}), 503

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "body must be a JSON object"}), 400
    vdoms = data.get("vdoms")
    if not vdoms:
        return jsonify({"error": "vdoms is required"}), 400
    if not isinstance(vdoms, list):
        return jsonify({"error": "vdoms must be a list"}), 400

    from app.pending_changes_ai import build_diff_narrative

    devices = [{"device": device, "summary": data.get("summary", {}), "vdoms": vdoms}]

    narrative = None
    narrative_error = None
    try:
        narrative = build_diff_narrative(adom, devices, user=session.get("user"))
    except Exception as exc:
        narrative_error = str(exc)

    return jsonify({"narrative": narrative, "narrative_error": narrative_error})


@bp.route("/api/pending-changes/task/<task_id>")
@tab_required("pending_changes")
def pending_changes_task_status(task_id: str):
    _evict_old_tasks()
    entry = _read_task(task_id)
    if entry is None:
        return jsonify({"error": "Task not found or expired"}), 404
    return jsonify(
        {
            "status": entry["status"],
            "step": entry["step"],
            "result": entry["result"],
            "error": entry["error"],
        }
    )
