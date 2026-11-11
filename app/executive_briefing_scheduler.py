"""Weekly Executive Briefing email.

Config, the last sent KPI snapshot and run history live in
executive_briefing.json (project root, gitignored):

    {enabled, day, time, email, last_payload, last_sent_at, runs}

Runs in the same process as the other email schedulers (the collector in
the split deployment; see app/__init__.py::start_all_schedulers). The web
admin UI writes the file, so the collector re-reads it on a short interval
and re-registers its cron trigger when it changes.

The email always carries the deterministic KPI table + week-over-week
deltas; the AI narrative is best-effort and omitted when AI Assist is off
or narration fails. ``last_payload`` (the allow-listed KPI snapshot, never
device names) is written only after a successful send.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import html
import json
import tempfile
import threading
from pathlib import Path

from app.ai_narrate import ai_enabled
from app.app_logger import app_log
from app.atomic_io import atomic_write_json
from app.executive_briefing import (
    KPIS,
    SECTIONS,
    briefing_payload,
    build_briefing,
    compute_deltas,
    stale_sections,
)

_CONFIG_PATH = Path(__file__).parent.parent / "executive_briefing.json"
_LOCK_PATH = Path(tempfile.gettempdir()) / "4thealth_exec_briefing.lock"
_lock = threading.Lock()
_scheduler = None
_config_mtime: float | None = None

_JOB_ID = "executive_briefing"
_RECONCILE_SECS = 300
_MAX_RUNS = 20

VALID_DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")

DEFAULT_CONFIG = {
    "enabled": False,
    "day": "MON",
    "time": "07:00",
    "email": "",
    "last_payload": None,
    "last_sent_at": None,
    "runs": [],
}


# ── Indirection points (monkeypatched in tests) ───────────────────────────────


def _build_payload() -> dict:
    from app.routes.external_api_routes import build_executive_payload

    return build_executive_payload()


def _send_email(to, subject, body_html, attachments):
    from app.smtp_client import send_email

    send_email(to, subject, body_html, attachments)


# ── Persistence ───────────────────────────────────────────────────────────────


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cfg["runs"] = []
    try:
        with open(_CONFIG_PATH) as f:
            data = json.load(f)
    except Exception:
        return cfg
    if isinstance(data, dict):
        cfg.update(data)
    if not isinstance(cfg.get("runs"), list):
        cfg["runs"] = []
    return cfg


def save_config(cfg: dict) -> None:
    atomic_write_json(_CONFIG_PATH, cfg)


def public_config() -> dict:
    """Config for the admin UI (without the stored KPI snapshot)."""
    with _lock:
        cfg = load_config()
    return {
        "enabled": bool(cfg.get("enabled")),
        "day": cfg.get("day"),
        "time": cfg.get("time"),
        "email": cfg.get("email") or "",
        "last_sent_at": cfg.get("last_sent_at"),
        "runs": cfg.get("runs", [])[:10],
    }


def _validate(data) -> dict:
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")  # noqa: TRY004 - mapped to HTTP 400
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be true or false")  # noqa: TRY004 - mapped to HTTP 400
    day = data.get("day")
    if not isinstance(day, str) or day not in VALID_DAYS:
        raise ValueError(f"day must be one of {list(VALID_DAYS)}")
    time_str = data.get("time")
    parts = time_str.split(":") if isinstance(time_str, str) else []
    if (
        len(parts) != 2
        or not all(p.isdigit() and len(p) == 2 for p in parts)
        or not (0 <= int(parts[0]) <= 23 and 0 <= int(parts[1]) <= 59)
    ):
        raise ValueError("time must be HH:MM (00:00-23:59)")
    email = data.get("email", "")
    if not isinstance(email, str):
        raise ValueError("email must be a string")  # noqa: TRY004 - mapped to HTTP 400
    return {"enabled": enabled, "day": day, "time": time_str, "email": email.strip()}


def update_config(data) -> dict:
    clean = _validate(data)
    with _lock:
        cfg = load_config()
        cfg.update(clean)
        save_config(cfg)
    reload()
    return public_config()


def _append_run(record: dict, last_payload: dict | None = None) -> None:
    with _lock:
        cfg = load_config()
        cfg["runs"] = [record, *cfg.get("runs", [])][:_MAX_RUNS]
        if last_payload is not None:
            cfg["last_payload"] = last_payload
            cfg["last_sent_at"] = record["ran_at"]
        save_config(cfg)


# ── Email ─────────────────────────────────────────────────────────────────────


def _fmt(value) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _fmt_delta(delta) -> str:
    if delta is None:
        return "&mdash;"
    if delta > 0:
        return f"+{_fmt(delta)}"
    return _fmt(delta)


def build_email_html(
    slim: dict, deltas: dict, generated_at: str, narrative: str | None
) -> str:
    section_of = {key: sec for key, _label, sec in KPIS}
    stale = set(stale_sections(slim))
    rows = []
    for key, label, _sec in KPIS:
        d = deltas.get(key) or {}
        flag = " (stale)" if section_of[key] in stale else ""
        rows.append(
            "<tr>"
            f"<td style='padding:4px 10px'>{html.escape(label)}{flag}</td>"
            f"<td style='padding:4px 10px;text-align:right'>{html.escape(_fmt(d.get('current')))}</td>"
            f"<td style='padding:4px 10px;text-align:right'>{html.escape(_fmt(d.get('previous')))}</td>"
            f"<td style='padding:4px 10px;text-align:right'>{_fmt_delta(d.get('delta'))}</td>"
            "</tr>"
        )
    fresh_rows = []
    for sec in SECTIONS:
        info = (slim.get("freshness") or {}).get(sec) or {}
        status = "STALE" if info.get("stale") else "fresh"
        fresh_rows.append(
            f"<tr><td style='padding:2px 10px'>{html.escape(sec)}</td>"
            f"<td style='padding:2px 10px'>{html.escape(_fmt(info.get('collected_at')))}</td>"
            f"<td style='padding:2px 10px'>{status}</td></tr>"
        )
    ai_html = ""
    if narrative:
        paras = "".join(
            f"<p>{html.escape(p.strip())}</p>"
            for p in narrative.split("\n")
            if p.strip()
        )
        ai_html = (
            "<h3>AI Summary</h3>"
            "<p style='color:#6b7280;font-size:12px'>AI-generated narration of the "
            "figures above; the table is authoritative.</p>"
            f"{paras}"
        )
    return (
        "<html><body style='font-family:Arial,sans-serif;font-size:14px'>"
        "<h2>4THealth+ Executive Briefing</h2>"
        f"<p>Generated {html.escape(generated_at)} UTC. Change is versus the "
        "previous briefing sent.</p>"
        "<table border='1' cellspacing='0' style='border-collapse:collapse'>"
        "<thead><tr><th>KPI</th><th>Current</th><th>Previous</th><th>Change</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        "<h3>Data freshness</h3>"
        "<table border='1' cellspacing='0' style='border-collapse:collapse'>"
        "<thead><tr><th>Section</th><th>Collected at</th><th>Status</th></tr></thead>"
        f"<tbody>{''.join(fresh_rows)}</tbody></table>"
        f"{ai_html}"
        "</body></html>"
    )


# ── Core execution ────────────────────────────────────────────────────────────


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None).isoformat() + "Z"


def _try_lock():
    try:
        fh = open(_LOCK_PATH, "w")  # noqa: SIM115 -- returned as an advisory lock handle
    except OSError:
        return None
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh
    except OSError:
        fh.close()
        return None


def generate_preview(user: str | None = None) -> dict:
    """On-demand narration (no email, nothing persisted)."""
    with _lock:
        previous = load_config().get("last_payload")
    payload = _build_payload()
    slim = briefing_payload(payload)
    deltas = compute_deltas(slim, previous)
    narrative, error = build_briefing(payload, previous, user=user)
    return {
        "narrative": narrative,
        "narrative_error": error,
        "deltas": deltas,
        "stale_sections": stale_sections(slim),
    }


def run_briefing(user: str | None = None) -> dict:
    """Build and send the briefing email. Never raises; returns the run record."""
    lock_fh = _try_lock()
    if lock_fh is None:
        return {"ran_at": _utcnow_iso(), "status": "error", "error": "already running"}
    record: dict = {"ran_at": _utcnow_iso()}
    try:
        with _lock:
            cfg = load_config()
        email = cfg.get("email")
        if not isinstance(email, str) or not email.strip():
            raise RuntimeError("No recipients configured")
        previous = cfg.get("last_payload")
        payload = _build_payload()
        slim = briefing_payload(payload)
        deltas = compute_deltas(slim, previous)
        narrative = None
        if ai_enabled():
            narrative, err = build_briefing(payload, previous, user=user)
            if err:
                record["ai_narrative_error"] = err
        body = build_email_html(slim, deltas, record["ran_at"], narrative)
        subject = f"4THealth+ Executive Briefing — {record['ran_at'][:10]}"
        _send_email(email, subject, body, [])
        record["status"] = "ok"
        _append_run(record, last_payload=slim)
        app_log("INFO", "executive_briefing", f"Executive briefing sent to={email}")
    except Exception as exc:
        record["status"] = "error"
        record["error"] = str(exc)
        try:
            _append_run(record)
        except Exception:
            pass
        app_log("ERROR", "executive_briefing", f"Executive briefing failed: {exc}")
    finally:
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
            lock_fh.close()
        except Exception:
            pass
    return record


def _scheduled_run() -> None:
    with _lock:
        cfg = load_config()
    if not cfg.get("enabled"):
        return
    run_briefing()


# ── APScheduler integration ───────────────────────────────────────────────────


def reload() -> None:
    """(Re-)register the cron trigger from the config file."""
    global _config_mtime
    if _scheduler is None:
        return
    try:
        _config_mtime = _CONFIG_PATH.stat().st_mtime
    except OSError:
        _config_mtime = None
    try:
        _scheduler.remove_job(_JOB_ID)
    except Exception:
        pass
    with _lock:
        cfg = load_config()
    if not cfg.get("enabled"):
        return
    try:
        clean = _validate({k: cfg.get(k) for k in ("enabled", "day", "time", "email")})
    except ValueError as exc:
        app_log("ERROR", "executive_briefing", f"Invalid config, not scheduled: {exc}")
        return
    from apscheduler.triggers.cron import CronTrigger

    h, m = clean["time"].split(":")
    _scheduler.add_job(
        _scheduled_run,
        CronTrigger(day_of_week=clean["day"].lower(), hour=int(h), minute=int(m)),
        id=_JOB_ID,
        replace_existing=True,
    )


def _reconcile() -> None:
    """Pick up edits the web process made to the config file."""
    try:
        mtime = _CONFIG_PATH.stat().st_mtime
    except OSError:
        mtime = None
    if mtime != _config_mtime:
        reload()


def init_scheduler(app=None) -> None:
    global _scheduler
    from apscheduler.schedulers.background import BackgroundScheduler

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        _reconcile,
        "interval",
        seconds=_RECONCILE_SECS,
        id="executive_briefing_reconcile",
    )
    _scheduler.start()
    reload()
    app_log("INFO", "executive_briefing", "Executive briefing scheduler started")


start = init_scheduler
