"""Scheduled Config-Delta email export engine.

Jobs and run history are persisted in config_diff_jobs.json (project root).
Each enabled job is registered as an APScheduler CronTrigger at startup.
"""

from __future__ import annotations

import datetime
import fcntl
import json
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from app.app_logger import app_log
from app.atomic_io import atomic_write_json

_JOBS_PATH = Path(__file__).parent.parent / "config_diff_jobs.json"
_lock = threading.Lock()
_scheduler = None  # BackgroundScheduler instance, set by init_scheduler
_running_jobs: set[str] = set()  # job IDs currently executing (for status polling)

_VALID_DAYS = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}


def _validate_job_fields(data: dict) -> None:
    days = data.get("days_of_week")
    if not isinstance(days, list) or not days:
        raise ValueError("days_of_week must be a non-empty list")
    invalid = [d for d in days if d not in _VALID_DAYS]
    if invalid:
        raise ValueError(
            f"days_of_week contains invalid codes: {invalid}. Must be from {sorted(_VALID_DAYS)}"
        )
    time_str = data.get("time", "")
    parts = time_str.split(":")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise ValueError("time must be HH:MM format")
    if not (0 <= int(parts[0]) <= 23 and 0 <= int(parts[1]) <= 59):
        raise ValueError("time HH must be 0-23, MM must be 0-59")


# ── Persistence ───────────────────────────────────────────────────────────────


def _load() -> list[dict]:
    if not _JOBS_PATH.exists():
        return []
    try:
        with open(_JOBS_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save(jobs: list[dict]) -> None:
    atomic_write_json(_JOBS_PATH, jobs)


# ── Public CRUD ───────────────────────────────────────────────────────────────


def get_all_jobs() -> list[dict]:
    with _lock:
        return _load()


def create_job(data: dict) -> dict:
    _validate_job_fields(data)
    job: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "adom": data["adom"],
        "days_of_week": data["days_of_week"],
        "time": data["time"],
        "format": data.get("format", "pdf"),
        "email": data["email"],
        "enabled": bool(data.get("enabled", True)),
        "ai_summary_enabled": bool(data.get("ai_summary_enabled", True)),
        "created_at": datetime.datetime.now(datetime.UTC)
        .replace(tzinfo=None)
        .isoformat()
        + "Z",
        "runs": [],
    }
    with _lock:
        jobs = _load()
        jobs.append(job)
        _save(jobs)
    if job["enabled"] and _scheduler is not None:
        _register(job)
    return job


def update_job(job_id: str, data: dict) -> dict:
    _validate_job_fields(data)
    with _lock:
        jobs = _load()
        for i, j in enumerate(jobs):
            if j["id"] == job_id:
                jobs[i] = {
                    **j,
                    "adom": data["adom"],
                    "days_of_week": data["days_of_week"],
                    "time": data["time"],
                    "format": data.get("format", "pdf"),
                    "email": data["email"],
                    "enabled": bool(data.get("enabled", True)),
                    "ai_summary_enabled": bool(
                        data.get("ai_summary_enabled", j.get("ai_summary_enabled", True))
                    ),
                }
                _save(jobs)
                updated = jobs[i]
                break
        else:
            raise KeyError(f"Job {job_id} not found")
    if _scheduler is not None:
        _unregister(job_id)
        if updated["enabled"]:
            _register(updated)
    return updated


def delete_job(job_id: str) -> None:
    with _lock:
        jobs = _load()
        jobs = [j for j in jobs if j["id"] != job_id]
        _save(jobs)
    if _scheduler is not None:
        _unregister(job_id)


def run_job_now(job_id: str) -> None:
    """Fire the job in a daemon thread; returns immediately."""
    t = threading.Thread(
        target=_execute_job,
        args=(job_id,),
        name=f"config_diff_{job_id[:8]}",
        daemon=True,
    )
    t.start()


# ── Run history ───────────────────────────────────────────────────────────────


def _prune_runs(job_id: str, retention_days: int | None = None) -> None:
    from app.smtp_client import load_smtp_config

    days = (
        retention_days
        if retention_days is not None
        else load_smtp_config().get("run_history_days", 30)
    )
    cutoff = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=None
    ) - datetime.timedelta(days=days)
    with _lock:
        jobs = _load()
        for j in jobs:
            if j["id"] == job_id:
                j["runs"] = [
                    r
                    for r in j.get("runs", [])
                    if datetime.datetime.fromisoformat(r["ran_at"].rstrip("Z"))
                    >= cutoff
                ]
        _save(jobs)


def _append_run(job_id: str, record: dict) -> None:
    with _lock:
        jobs = _load()
        for j in jobs:
            if j["id"] == job_id:
                j.setdefault("runs", []).insert(0, record)
        _save(jobs)


# ── Job execution ─────────────────────────────────────────────────────────────


def _try_acquire_job_lock(job_id: str):
    """Return an open file object with an exclusive lock, or None if already locked."""
    lock_path = Path(tempfile.gettempdir()) / f"4thealth_cdiff_{job_id}.lock"
    try:
        fh = open(lock_path, "w")  # noqa: SIM115 -- intentionally returned open as an advisory lock handle for the caller to close
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh
    except OSError:
        try:
            fh.close()
        except Exception:
            pass
        return None


def _execute_job(job_id: str) -> None:
    lock_fh = _try_acquire_job_lock(job_id)
    if lock_fh is None:
        app_log(
            "INFO",
            "config_diff_scheduler",
            f"Job {job_id} already running in another worker — skipping",
        )
        return
    _running_jobs.add(job_id)
    try:
        with _lock:
            jobs = _load()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if not job:
            app_log("ERROR", "config_diff_scheduler", f"Job {job_id} not found")
            return

        adom = job["adom"]
        fmt = job.get("format", "pdf")
        email = job["email"]

        app_log(
            "INFO",
            "config_diff_scheduler",
            f"Running scheduled Config-Delta export: adom={adom} format={fmt} to={email}",
        )

        from app.routes.pending_changes_routes import bulk_preview_adom

        # Sequential (max_workers=1): FMG's install-preview staging locks are
        # ADOM-scoped — any concurrency causes one device's cancel/install to
        # wipe another's staging lock, producing empty diffs in the email.
        # The interactive tab clicks devices one at a time; this matches that.
        results = bulk_preview_adom(adom, max_workers=1)

        ok_count = sum(1 for r in results if r["status"] == "ok")
        record: dict[str, Any] = {
            "ran_at": datetime.datetime.now(datetime.UTC)
            .replace(tzinfo=None)
            .isoformat()
            + "Z",
            "status": "ok",
            "devices_total": len(results),
            "devices_with_changes": ok_count,
        }

        ai_narrative_html, ai_narrative_error = _build_ai_narrative_html(
            adom, results, job.get("ai_summary_enabled", True)
        )
        if ai_narrative_error:
            record["ai_narrative_error"] = ai_narrative_error

        generated_at = (
            datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        )
        subject = f"4THealth+ Config-Delta — {adom} — {generated_at[:10]}"
        body_html = _build_summary_html(adom, results, ai_narrative_html)
        attachment = _build_attachment(
            adom, fmt, results, generated_at, ai_narrative_html
        )

        from app.smtp_client import send_email

        send_email(email, subject, body_html, [attachment])

        _append_run(job_id, record)
        _prune_runs(job_id)
        app_log(
            "INFO",
            "config_diff_scheduler",
            f"Config-Delta export sent: adom={adom} devices={len(results)} changes={ok_count} to={email}",
        )

    except Exception as exc:
        record = {
            "ran_at": datetime.datetime.now(datetime.UTC)
            .replace(tzinfo=None)
            .isoformat()
            + "Z",
            "status": "error",
            "error": str(exc),
        }
        _append_run(job_id, record)
        app_log(
            "ERROR",
            "config_diff_scheduler",
            f"Config-Delta scheduled export failed for job {job_id}: {exc}",
        )
    finally:
        _running_jobs.discard(job_id)
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
            lock_fh.close()
        except Exception:
            pass


def _status_color(status: str) -> str:
    return {
        "ok": "#166534",
        "error": "#b91c1c",
        "pkg_pending_no_diff": "#92400e",
    }.get(status, "#6b7280")


def _esc(s) -> str:
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_ai_narrative_html(
    adom: str, results: list[dict], ai_summary_enabled: bool = True
) -> tuple[str, str | None]:
    """Return (html, error) for the AI narrative section.

    html is '' if disabled/unavailable, there are no changes to summarize, or
    narration failed; error is the failure message when narration was
    attempted but raised, else None. Never raises — narration failure must
    not break export generation."""
    from app.app_settings import get_setting

    if not ai_summary_enabled or not get_setting("ai_assist_enabled", False):
        return "", None

    has_changes = any(v.get("changes") for r in results for v in (r.get("vdoms") or []))
    if not has_changes:
        return "", None

    try:
        from app.pending_changes_ai import build_diff_narrative

        text = build_diff_narrative(adom, results)
    except Exception as exc:
        app_log(
            "WARNING",
            "config_diff_scheduler",
            f"AI narrative generation failed for {adom}: {exc}",
        )
        return "", str(exc)
    return f"<h3>AI Summary</h3><p style='white-space:pre-wrap'>{_esc(text)}</p>", None


def _build_summary_html(
    adom: str, results: list[dict], ai_narrative_html: str = ""
) -> str:
    ok = [r for r in results if r["status"] == "ok"]
    none_ = [r for r in results if r["status"] == "no_changes"]
    pkg_pending = [r for r in results if r["status"] == "pkg_pending_no_diff"]
    err = [r for r in results if r["status"] == "error"]
    _status_label = {
        "ok": "has_changes",
        "no_changes": "no_changes",
        "pkg_pending_no_diff": "pkg_pending_no_diff",
        "error": "error",
    }
    rows = "".join(
        f"<tr><td>{r['device']}</td><td>{r.get('ip', '')}</td>"
        f'<td style="color:{_status_color(r["status"])}">'
        f"{_status_label.get(r['status'], r['status'])}</td></tr>"
        for r in results
    )
    pkg_pending_note = (
        f" | <strong>{len(pkg_pending)}</strong> pkg pending (no diff)"
        if pkg_pending
        else ""
    )
    return (
        f"<h2>Config-Delta Export — {adom}</h2>"
        f"{ai_narrative_html}"
        f"<p><strong>{len(results)}</strong> devices scanned | "
        f"<strong>{len(ok)}</strong> with changes | "
        f"<strong>{len(none_)}</strong> in sync"
        f"{pkg_pending_note} | "
        f"<strong>{len(err)}</strong> errors</p>"
        f"<table border='1' cellpadding='4' cellspacing='0'>"
        f"<thead><tr><th>Device</th><th>IP</th><th>Status</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        f"<p>Full diff is attached.</p>"
    )


def _build_attachment(
    adom: str,
    fmt: str,
    results: list[dict],
    generated_at: str,
    ai_narrative_html: str = "",
) -> dict:
    import csv
    import io

    date = generated_at[:10]  # "YYYY-MM-DD" from ISO string
    if fmt == "json":
        data = json.dumps(
            {
                "adom": adom,
                "exported_at": generated_at,
                "results": results,
            },
            indent=2,
        ).encode()
        return {
            "filename": f"config-delta-{adom}-{date}.json",
            "data": data,
            "mimetype": "application/json",
        }
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        ts_display = generated_at.replace("T", " ").rstrip("Z") + " UTC"
        w.writerow(["# Config-Delta Export"])
        w.writerow([f"# ADOM: {adom}"])
        w.writerow([f"# Generated (UTC): {ts_display}"])
        w.writerow(["# Generated by: 4THealth+ Config-Delta Scheduler"])
        w.writerow([])
        w.writerow(["device", "ip", "status", "vdom", "type", "line"])
        for r in results:
            if r["status"] == "ok":
                for v in r.get("vdoms", []):
                    for c in v.get("changes", []):
                        w.writerow(
                            [
                                r["device"],
                                r.get("ip", ""),
                                r["status"],
                                v["name"],
                                c["type"],
                                c["line"],
                            ]
                        )
            else:
                w.writerow(
                    [
                        r["device"],
                        r.get("ip", ""),
                        r["status"],
                        "",
                        "",
                        r.get("error", ""),
                    ]
                )
        return {
            "filename": f"config-delta-{adom}-{date}.csv",
            "data": buf.getvalue().encode(),
            "mimetype": "text/csv",
        }
    # default: html attachment
    body = _build_pdf_html(adom, results, generated_at, ai_narrative_html)
    return {
        "filename": f"config-delta-{adom}-{date}.html",
        "data": body.encode(),
        "mimetype": "text/html",
    }


def _build_pdf_html(
    adom: str,
    results: list[dict],
    generated_at: str,
    ai_narrative_html: str = "",
) -> str:
    ok_count = sum(1 for r in results if r["status"] == "ok")
    no_changes_count = sum(1 for r in results if r["status"] == "no_changes")
    pkg_pending_count = sum(1 for r in results if r["status"] == "pkg_pending_no_diff")
    err_count = sum(1 for r in results if r["status"] == "error")

    ts_display = generated_at.replace("T", " ").rstrip("Z") + " UTC"

    pkg_pending_row = (
        f"<tr><td style='padding:2px 12px 2px 0;color:#6b7280'>Package pending (no diff)</td>"
        f"<td>{pkg_pending_count}</td></tr>"
        if pkg_pending_count > 0
        else ""
    )

    header_block = (
        f'<div style="border:1px solid #d1d5db;border-radius:4px;padding:12px 16px;'
        f'margin-bottom:24px;background:#f9fafb;">'
        f'<h1 style="font-size:16px;margin:0 0 10px 0;color:#111827">Config-Delta Export</h1>'
        f'<table style="border-collapse:collapse;font-size:11px;width:100%">'
        f'<tr><td style="padding:2px 12px 2px 0;color:#6b7280;width:180px">ADOM</td>'
        f'<td style="font-weight:600">{_esc(adom)}</td></tr>'
        f'<tr><td style="padding:2px 12px 2px 0;color:#6b7280">Generated (UTC)</td>'
        f"<td>{_esc(ts_display)}</td></tr>"
        f'<tr><td style="padding:2px 12px 2px 0;color:#6b7280">Devices scanned</td>'
        f"<td>{len(results)}</td></tr>"
        f'<tr><td style="padding:2px 12px 2px 0;color:#6b7280">With changes</td>'
        f'<td style="color:#166534;font-weight:600">{ok_count}</td></tr>'
        f'<tr><td style="padding:2px 12px 2px 0;color:#6b7280">In sync</td>'
        f"<td>{no_changes_count}</td></tr>"
        f"{pkg_pending_row}"
        f'<tr><td style="padding:2px 12px 2px 0;color:#6b7280">Errors</td>'
        f'<td style="color:{"#b91c1c" if err_count > 0 else "inherit"}">{err_count}</td></tr>'
        f'<tr><td style="padding:2px 12px 2px 0;color:#6b7280">Generated by</td>'
        f"<td>4THealth+ Config-Delta Scheduler</td></tr>"
        f"</table></div>"
        f"{ai_narrative_html}"
    )

    sections = []
    for i, r in enumerate(results):
        pb = "page-break-before:always;" if i > 0 else ""
        if r["status"] == "no_changes":
            body = '<p style="color:#6b7280;font-style:italic">No pending changes.</p>'
        elif r["status"] == "pkg_pending_no_diff":
            body = '<p style="color:#92400e;font-style:italic">Package marked as pending in FMG but install-preview produced no CLI diff (changes may be metadata-only).</p>'
        elif r["status"] == "error":
            body = f'<p style="color:#b91c1c">Error: {_esc(r.get("error", ""))}</p>'
        else:
            vdom_blocks = ""
            for v in r.get("vdoms", []):
                lines = "".join(
                    f'<span style="color:{"#166534" if c["type"] == "add" else "#b91c1c" if c["type"] == "remove" else "#92400e"};display:block">'
                    f"{_esc(('+' if c['type'] == 'add' else '-' if c['type'] == 'remove' else '~') + ' ' + c['line'])}</span>"
                    for c in v.get("changes", [])
                )
                vdom_blocks += f'<strong>vdom: {_esc(v["name"])}</strong><pre style="background:#f8f9fa;padding:8px;font-size:9px;white-space:pre-wrap">{lines}</pre>'
            body = (
                vdom_blocks
                or '<p style="color:#6b7280;font-style:italic">No changes.</p>'
            )
        sections.append(
            f'<div style="{pb}padding-top:1cm"><h2>{_esc(r["device"])}</h2>'
            f'<div style="color:#6b7280;font-size:10px">{_esc(r.get("ip", ""))}</div>{body}</div>'
        )
    return (
        f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Config-Delta — {_esc(adom)}</title>'
        f"<style>body{{font-family:Arial,sans-serif;font-size:11px;margin:1.5cm}}"
        f"h2{{font-size:14px}}@media print{{@page{{margin:1.2cm}}}}</style></head>"
        f"<body>{header_block}{''.join(sections)}</body></html>"
    )


# ── APScheduler integration ───────────────────────────────────────────────────


def _apscheduler_id(job_id: str) -> str:
    return f"config_diff_{job_id}"


def _register(job: dict) -> None:
    if _scheduler is None:
        return
    from apscheduler.triggers.cron import CronTrigger

    day_map = {
        "SUN": "sun",
        "MON": "mon",
        "TUE": "tue",
        "WED": "wed",
        "THU": "thu",
        "FRI": "fri",
        "SAT": "sat",
    }
    h, m = job["time"].split(":")
    day_str = ",".join(day_map[d] for d in job["days_of_week"])
    _scheduler.add_job(
        _execute_job,
        CronTrigger(day_of_week=day_str, hour=int(h), minute=int(m)),
        args=[job["id"]],
        id=_apscheduler_id(job["id"]),
        replace_existing=True,
    )


def _unregister(job_id: str) -> None:
    if _scheduler is None:
        return
    try:
        _scheduler.remove_job(_apscheduler_id(job_id))
    except Exception:
        pass


def is_job_running(job_id: str) -> bool:
    return job_id in _running_jobs


def init_scheduler(app) -> None:
    global _scheduler
    from apscheduler.schedulers.background import BackgroundScheduler

    _scheduler = BackgroundScheduler(daemon=True)
    jobs = _load()
    for job in jobs:
        if job.get("enabled"):
            try:
                _register(job)
            except Exception as exc:
                app_log(
                    "ERROR",
                    "config_diff_scheduler",
                    f"Failed to register job {job.get('id', '?')} ({job.get('adom', '?')}): {exc}",
                )
    _scheduler.start()
    app_log(
        "INFO",
        "config_diff_scheduler",
        f"Config-Diff scheduler started with {sum(1 for j in jobs if j.get('enabled'))} active jobs",
    )
