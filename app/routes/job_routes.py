"""Server-side jobs for long actions (F6): enqueue, list, read, cancel.

``/api/jobs`` — all endpoints need the ``audit_review`` tab (the kinds shipped so
far live there) and ``JOB_QUEUE`` on (503 otherwise). A user sees and cancels only
their own jobs, admin sees all; a job whose ADOM the user can no longer access, or
that belongs to someone else, is a 404 (never confirms the id exists). Job rows
hold parameters only; results are returned solely by ``GET /api/jobs/<id>``.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request, session

from app import job_handlers, job_store
from app.config import Config
from app.decorators import check_adom_access, tab_required
from app.security import internal_api_error

bp = Blueprint("jobs", __name__, url_prefix="/api/jobs")

_DISABLED = ({"error": "Job queue is not enabled"}, 503)


def _is_admin() -> bool:
    return session.get("role") == "admin"


def _visible(job: dict | None) -> bool:
    if job is None:
        return False
    if not _is_admin() and job["owner"] != session.get("user", ""):
        return False
    return check_adom_access(job["adom"]) is None


@bp.route("", methods=["POST"])
@tab_required("audit_review")
def create_job():
    if not Config.JOB_QUEUE:
        return jsonify(_DISABLED[0]), _DISABLED[1]
    data = request.get_json(silent=True) or {}
    kind = str(data.get("kind") or "")
    try:
        adom, req = job_handlers.prepare(kind, data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if err := check_adom_access(adom):
        return err
    try:
        jid = job_store.enqueue(kind, session.get("user", ""), adom, req)
    except job_store.JobLimitError:
        return jsonify({"error": "Too many queued jobs; wait for one to finish"}), 429
    except Exception as exc:
        return internal_api_error("jobs", exc)
    return jsonify({"id": jid, "status": "queued"}), 202


@bp.route("", methods=["GET"])
@tab_required("audit_review")
def list_jobs():
    if not Config.JOB_QUEUE:
        return jsonify(_DISABLED[0]), _DISABLED[1]
    try:
        rows = job_store.list_for(None if _is_admin() else session.get("user", ""))
    except Exception as exc:
        return internal_api_error("jobs", exc)
    return jsonify({"jobs": [r for r in rows if _visible(r)]})


@bp.route("/<job_id>", methods=["GET"])
@tab_required("audit_review")
def get_job(job_id: str):
    if not Config.JOB_QUEUE:
        return jsonify(_DISABLED[0]), _DISABLED[1]
    try:
        job = job_store.get(job_id)
    except Exception as exc:
        return internal_api_error("jobs", exc)
    if not _visible(job):
        return jsonify({"error": "Job not found"}), 404
    job.pop("request", None)
    return jsonify(job)


@bp.route("/<job_id>/cancel", methods=["POST"])
@tab_required("audit_review")
def cancel_job(job_id: str):
    if not Config.JOB_QUEUE:
        return jsonify(_DISABLED[0]), _DISABLED[1]
    try:
        job = job_store.get(job_id)
        if not _visible(job):
            return jsonify({"error": "Job not found"}), 404
        state = job_store.request_cancel(job_id)
    except Exception as exc:
        return internal_api_error("jobs", exc)
    return jsonify({"id": job_id, "state": state})
