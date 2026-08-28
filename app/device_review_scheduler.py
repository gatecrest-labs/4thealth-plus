"""Scheduled Device Review email export engine.

Jobs and run history are persisted in device_review_jobs.json (project root).
Each enabled job is registered as an APScheduler CronTrigger at startup.
"""

from __future__ import annotations

import csv
import datetime
import fcntl
import io
import json
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from app.app_logger import app_log
from app.atomic_io import atomic_write_json

_JOBS_PATH = Path(__file__).parent.parent / "device_review_jobs.json"
_lock = threading.Lock()
_scheduler = None  # BackgroundScheduler instance, set by init_scheduler
_running_jobs: set[str] = set()

_VALID_DAYS = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}


# ── Indirection points (monkeypatched in tests) ───────────────────────────────


def _bulk_device_review_adom(adom, checks, check_params, max_workers=4):
    from app.routes.device_review_routes import bulk_device_review_adom

    return bulk_device_review_adom(adom, checks, check_params, max_workers)


def _send_email(to, subject, body_html, attachments):
    from app.smtp_client import send_email

    send_email(to, subject, body_html, attachments)


# ── Validation ────────────────────────────────────────────────────────────────


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
        "name": data.get("name", "").strip(),
        "adom": data.get("adom", ""),
        "days_of_week": data["days_of_week"],
        "time": data["time"],
        "checks": data.get("checks") or [],
        "check_params": data.get("check_params") or {},
        "format": data.get("format", "pdf"),
        "email": data.get("email", ""),
        "enabled": bool(data.get("enabled", True)),
        "runs": [],
    }
    with _lock:
        jobs = _load()
        jobs.append(job)
        _save(jobs)
    if job["enabled"]:
        _register(job)
    return job


def update_job(job_id: str, data: dict) -> dict:
    _validate_job_fields(data)
    with _lock:
        jobs = _load()
        idx = next((i for i, j in enumerate(jobs) if j["id"] == job_id), None)
        if idx is None:
            raise KeyError(f"Job {job_id} not found")
        existing = jobs[idx]
        existing.update(
            {
                "name": data.get("name", existing.get("name", "")).strip(),
                "adom": data.get("adom", existing["adom"]),
                "days_of_week": data["days_of_week"],
                "time": data["time"],
                "checks": data.get("checks") or [],
                "check_params": data.get("check_params") or {},
                "format": data.get("format", existing.get("format", "pdf")),
                "email": data.get("email", existing["email"]),
                "enabled": bool(data.get("enabled", True)),
            }
        )
        jobs[idx] = existing
        _save(jobs)
    _unregister(job_id)
    if existing["enabled"]:
        _register(existing)
    return existing


def delete_job(job_id: str) -> None:
    with _lock:
        jobs = _load()
        new_jobs = [j for j in jobs if j["id"] != job_id]
        if len(new_jobs) == len(jobs):
            raise KeyError(f"Job {job_id} not found")
        _save(new_jobs)
    _unregister(job_id)


def run_job_now(job_id: str) -> None:
    t = threading.Thread(target=_execute_job, args=[job_id], daemon=True)
    t.start()


def is_job_running(job_id: str) -> bool:
    return job_id in _running_jobs


# ── Run history ───────────────────────────────────────────────────────────────


def _prune_runs(job_id: str, retention_days: int = 30) -> None:
    cutoff = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=None
    ) - datetime.timedelta(days=retention_days)
    with _lock:
        jobs = _load()
        for job in jobs:
            if job["id"] != job_id:
                continue
            job["runs"] = [
                r
                for r in job.get("runs", [])
                if datetime.datetime.fromisoformat(r["ran_at"].rstrip("Z")) >= cutoff
            ]
        _save(jobs)


def _append_run(job_id: str, record: dict) -> None:
    with _lock:
        jobs = _load()
        for job in jobs:
            if job["id"] == job_id:
                job.setdefault("runs", []).insert(0, record)
        _save(jobs)


# ── Lock helper ───────────────────────────────────────────────────────────────


def _try_acquire_job_lock(job_id: str):
    lock_path = Path(tempfile.gettempdir()) / f"4thealth_dr_{job_id}.lock"
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


# ── Core execution ────────────────────────────────────────────────────────────


def _execute_job(job_id: str) -> None:
    lock_fh = _try_acquire_job_lock(job_id)
    if lock_fh is None:
        app_log(
            "INFO",
            "device_review_scheduler",
            f"Job {job_id} already running — skipping",
        )
        return
    _running_jobs.add(job_id)
    try:
        with _lock:
            jobs = _load()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if not job:
            app_log("ERROR", "device_review_scheduler", f"Job {job_id} not found")
            return

        adom = job["adom"]
        fmt = job.get("format", "pdf")
        email = job["email"]
        checks = job.get("checks") or []
        check_params = job.get("check_params") or {}

        app_log(
            "INFO",
            "device_review_scheduler",
            f"Running scheduled Device Review: adom={adom} format={fmt} to={email}",
        )

        results = _bulk_device_review_adom(adom, checks, check_params, max_workers=4)

        from app.device_review_rollup import (
            append_run as _append_dr_rollup,
        )
        from app.device_review_rollup import (
            build_rollup as _build_dr_rollup,
        )

        dr_rollup_record = {
            "ran_at": datetime.datetime.now(datetime.UTC)
            .replace(tzinfo=None)
            .isoformat()
            + "Z",
            **_build_dr_rollup(results),
        }
        _append_dr_rollup(dr_rollup_record)

        all_rows = [r for dev in results for r in dev.get("rows", [])]
        fail_count = sum(1 for r in all_rows if r.get("result") in ("FAIL", "INSECURE"))

        record: dict[str, Any] = {
            "ran_at": datetime.datetime.now(datetime.UTC)
            .replace(tzinfo=None)
            .isoformat()
            + "Z",
            "status": "ok",
            "devices_total": len(results),
            "devices_reviewed": sum(1 for d in results if not d.get("error")),
            "total_findings": len(all_rows),
            "fail_count": fail_count,
        }

        generated_at = record["ran_at"]
        subject = f"4THealth+ Device Review — {adom} — {generated_at[:10]}"
        check_summary = _build_check_summary(results, checks)
        ai_narrative_html, ai_narrative_error = _build_ai_narrative_html(
            adom, check_summary, results
        )
        body_html = _build_summary_html(
            adom, results, generated_at, check_summary, ai_narrative_html
        )
        attachment = _build_attachment_dr(
            adom, fmt, results, generated_at, check_summary, ai_narrative_html
        )

        if ai_narrative_error:
            record["ai_narrative_error"] = ai_narrative_error

        _send_email(email, subject, body_html, [attachment])
        _append_run(job_id, record)
        from app.smtp_client import load_smtp_config as _load_smtp_cfg

        retention = _load_smtp_cfg().get("run_history_days", 30)
        _prune_runs(job_id, retention_days=retention)
        app_log(
            "INFO",
            "device_review_scheduler",
            f"Device Review report sent: adom={adom} devices={len(results)} "
            f"findings={len(all_rows)} fails={fail_count} to={email}",
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
            "device_review_scheduler",
            f"Device Review scheduled job {job_id} failed: {exc}",
        )
    finally:
        _running_jobs.discard(job_id)
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
            lock_fh.close()
        except Exception:
            pass


# ── Email builders ────────────────────────────────────────────────────────────


def _fmt_detail(row: dict) -> str:
    """Return display text for the Detail column.

    Most checks populate `detail` directly. Interface Protocols leaves `detail`
    empty and puts protocol info in the `protocols` list instead — fall back to
    formatting that list so the report is not blank for those rows.
    """
    detail = row.get("detail", "")
    if detail:
        return detail
    protocols = row.get("protocols") or []
    if not protocols:
        return ""
    parts = []
    for p in protocols:
        name = p.get("name", "")
        secure = p.get("secure")
        if secure is False:
            parts.append(f"{name} (insecure)")
        else:
            parts.append(name)
    return ", ".join(parts)


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


_RESULT_COLOR = {
    "PASS": "#166534",
    "FAIL": "#991b1b",
    "INSECURE": "#991b1b",
    "WARN": "#92400e",
    "CONFIG_MISSING": "#92400e",
    "INFO": "#1e40af",
}

_SUMMARY_RESULTS = ("PASS", "FAIL", "INSECURE", "WARN", "CONFIG_MISSING", "INFO")

_CHECKS_META = None  # populated lazily; tests may monkeypatch this directly


def _get_checks_meta():
    from app.device_review import CHECKS_META

    return CHECKS_META


_CHECK_SUMMARY_RESULTS = ("PASS", "INFO", "WARN", "CONFIG_MISSING", "FAIL", "INSECURE")

_REPORT_CSS = """
#dr-filter-bar {
  position: sticky;
  top: 0;
  background: #fff;
  z-index: 10;
  padding: 8px 0 10px 0;
  border-bottom: 1px solid #e5e7eb;
  margin-bottom: 12px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.dr-result-btn {
  border: 1px solid #d1d5db;
  background: #f9fafb;
  border-radius: 4px;
  padding: 3px 10px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  color: #374151;
}
.dr-result-btn.active {
  border-color: #6b7280;
  background: #e5e7eb;
  color: #111827;
}
.dr-result-btn[data-result="FAIL"].active,
.dr-result-btn[data-result="INSECURE"].active { background:#fee2e2; border-color:#991b1b; color:#991b1b; }
.dr-result-btn[data-result="WARN"].active,
.dr-result-btn[data-result="CONFIG_MISSING"].active { background:#fef3c7; border-color:#92400e; color:#92400e; }
.dr-result-btn[data-result="PASS"].active { background:#dcfce7; border-color:#166534; color:#166534; }
.dr-result-btn[data-result="INFO"].active { background:#dbeafe; border-color:#1e40af; color:#1e40af; }
#dr-host-select {
  border: 1px solid #d1d5db;
  border-radius: 4px;
  padding: 3px 8px;
  font-size: 11px;
  background: #f9fafb;
  color: #374151;
  cursor: pointer;
}
#dr-row-count {
  font-size: 11px;
  color: #6b7280;
  margin-left: 8px;
}
"""

_REPORT_JS = """
(function() {
  var activeResult = 'ALL';

  function filterFindings() {
    var hostSelect = document.getElementById('dr-host-select');
    var activeHost = hostSelect ? hostSelect.value : 'ALL';
    var rows = document.querySelectorAll('#dr-findings-tbody tr');
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var resultMatch = (activeResult === 'ALL') || (r.getAttribute('data-result') === activeResult);
      var hostMatch = (activeHost === 'ALL') || (r.getAttribute('data-device') === activeHost);
      if (resultMatch && hostMatch) {
        r.style.display = '';
        shown++;
      } else {
        r.style.display = 'none';
      }
    }
    var counter = document.getElementById('dr-row-count');
    if (counter) {
      counter.textContent = 'Showing ' + shown + ' of ' + rows.length + ' findings';
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    var buttons = document.querySelectorAll('.dr-result-btn');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener('click', function() {
        for (var j = 0; j < buttons.length; j++) {
          buttons[j].classList.remove('active');
        }
        this.classList.add('active');
        activeResult = this.getAttribute('data-result');
        var hostSelect = document.getElementById('dr-host-select');
        if (hostSelect) hostSelect.value = 'ALL';
        filterFindings();
      });
    }
    var hostSelect = document.getElementById('dr-host-select');
    if (hostSelect) {
      hostSelect.addEventListener('change', filterFindings);
    }
    filterFindings();
  });
})();
"""


def _build_check_summary(results: list[dict], checks_ran: list[str]) -> list[dict]:
    """Return per-check result counts ordered by CHECKS_META declaration order.

    checks_ran: list of check keys that were run; empty means all checks.
    Each entry: {key, name, description, PASS, INFO, WARN, CONFIG_MISSING, FAIL, INSECURE}
    """
    checks_meta = _CHECKS_META if _CHECKS_META is not None else _get_checks_meta()
    active_keys = set(checks_ran) if checks_ran else {c["key"] for c in checks_meta}
    # Build name→key lookup for matching row["check"] (display name) back to key
    name_to_key = {c["name"]: c["key"] for c in checks_meta}
    # Aggregate by check key
    by_key: dict[str, dict] = {}
    for dev in results:
        for row in dev.get("rows", []):
            check_name = row.get("check", "")
            key = name_to_key.get(check_name)
            if key is None or key not in active_keys:
                continue
            if key not in by_key:
                by_key[key] = {r: 0 for r in _CHECK_SUMMARY_RESULTS}
            result = row.get("result", "")
            if result in by_key[key]:
                by_key[key][result] += 1
    # Build output in CHECKS_META order, filtered to active_keys
    output = []
    for c in checks_meta:
        if c["key"] not in active_keys:
            continue
        counts = by_key.get(c["key"], {r: 0 for r in _CHECK_SUMMARY_RESULTS})
        output.append(
            {
                "key": c["key"],
                "name": c["name"],
                "description": c.get("description", ""),
                **counts,
            }
        )
    return output


def _build_host_summary_html(results: list[dict]) -> str:
    """Return an HTML table with one row per device showing per-result counts."""
    totals = {r: 0 for r in _SUMMARY_RESULTS}
    rows_html = ""
    for dev in sorted(results, key=lambda d: d.get("device", "")):
        device = dev.get("device", "unknown")
        counts = {r: 0 for r in _SUMMARY_RESULTS}
        for row in dev.get("rows", []):
            res = row.get("result", "")
            if res in counts:
                counts[res] += 1
                totals[res] += 1
        total = sum(counts.values())
        has_fail = counts["FAIL"] + counts["INSECURE"] > 0
        has_warn = counts["WARN"] + counts["CONFIG_MISSING"] > 0
        if has_fail:
            row_style = "background:#fee2e2"
        elif has_warn:
            row_style = "background:#fef3c7"
        else:
            row_style = ""
        error_suffix = (
            " <span style='color:#991b1b'>(error)</span>" if dev.get("error") else ""
        )
        cells = "".join(
            "<td style='padding:4px 8px;text-align:center;color:{c}'>{v}</td>".format(
                c=_RESULT_COLOR.get(r, "#374151"), v=counts[r]
            )
            for r in _SUMMARY_RESULTS
        )
        rows_html += (
            f"<tr style='{row_style}'>"
            f"<td style='padding:4px 8px'>{_esc(device)}{error_suffix}</td>"
            f"{cells}"
            f"<td style='padding:4px 8px;text-align:center'>{total}</td>"
            f"</tr>\n"
        )
    # Totals footer
    total_all = sum(totals.values())
    total_cells = "".join(
        "<td style='padding:4px 8px;text-align:center;font-weight:600;"
        "color:{c}'>{v}</td>".format(c=_RESULT_COLOR.get(r, "#374151"), v=totals[r])
        for r in _SUMMARY_RESULTS
    )
    rows_html += (
        f"<tr style='background:#f3f4f6;font-weight:600'>"
        f"<td style='padding:4px 8px'>Totals</td>"
        f"{total_cells}"
        f"<td style='padding:4px 8px;text-align:center;font-weight:600'>{total_all}</td>"
        f"</tr>\n"
    )
    header_cells = "".join(
        f"<th style='padding:4px 8px'>{r}</th>" for r in _SUMMARY_RESULTS
    )
    return (
        f"<h3 style='font-family:sans-serif;margin-top:24px'>Host Summary</h3>"
        f"<table style='border-collapse:collapse;font-family:sans-serif;font-size:13px'>"
        f"<thead><tr style='background:#f3f4f6'>"
        f"<th style='padding:4px 8px;text-align:left'>Device</th>"
        f"{header_cells}"
        f"<th style='padding:4px 8px'>Total</th>"
        f"</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        f"</table>"
    )


def _build_ai_narrative_html(
    adom: str, check_summary: list[dict], results: list[dict]
) -> tuple[str, str | None]:
    """Return (html, error) for the AI narrative section.

    html is '' if disabled/unavailable or narration failed; error is the
    failure message when narration was attempted but raised, else None.
    Never raises — narration failure must not break report generation.
    """
    from app.app_settings import get_setting

    if not get_setting("ai_assist_enabled", False):
        return "", None
    try:
        from app.device_review_ai import build_narrative

        text = build_narrative(adom, check_summary, results)
    except Exception as exc:
        app_log(
            "WARNING",
            "device_review_scheduler",
            f"AI narrative generation failed for {adom}: {exc}",
        )
        return "", str(exc)
    html = (
        f"<h3 style='font-family:sans-serif;margin-top:24px'>AI Summary</h3>"
        f"<p style='font-family:sans-serif;font-size:13px;white-space:pre-wrap'>{_esc(text)}</p>"
    )
    return html, None


def _build_summary_html(
    adom: str,
    results: list[dict],
    generated_at: str,
    check_summary: list[dict],
    ai_narrative_html: str = "",
) -> str:
    errors = [d.get("device", "unknown") for d in results if d.get("error")]
    error_note = ""
    if errors:
        error_note = (
            f"<p style='font-family:sans-serif;color:#991b1b'>"
            f"Errors on devices: {', '.join(_esc(e) for e in errors)}</p>"
        )

    # ── Check Summary table ───────────────────────────────────────────────────
    check_rows_html = ""
    for entry in check_summary:
        cells = "".join(
            "<td style='padding:4px 8px;text-align:center;color:{c}'>{v}</td>".format(
                c=_RESULT_COLOR.get(r, "#374151"), v=entry[r]
            )
            for r in _CHECK_SUMMARY_RESULTS
        )
        check_rows_html += (
            f"<tr>"
            f"<td style='padding:4px 8px'>{_esc(entry['name'])}</td>"
            f"<td style='padding:4px 8px;color:#6b7280;font-size:12px'>{_esc(entry['description'])}</td>"
            f"{cells}"
            f"</tr>\n"
        )
    check_header_cells = "".join(
        f"<th style='padding:4px 8px'>{r}</th>" for r in _CHECK_SUMMARY_RESULTS
    )
    check_summary_html = (
        f"<h3 style='font-family:sans-serif;margin-top:24px'>Check Summary</h3>"
        f"<table style='border-collapse:collapse;font-family:sans-serif;font-size:13px'>"
        f"<thead><tr style='background:#f3f4f6'>"
        f"<th style='padding:4px 8px;text-align:left'>Check</th>"
        f"<th style='padding:4px 8px;text-align:left'>Description</th>"
        f"{check_header_cells}"
        f"</tr></thead>"
        f"<tbody>{check_rows_html}</tbody>"
        f"</table>"
    )

    host_summary_html = _build_host_summary_html(results)

    return f"""
<h2 style="font-family:sans-serif">4THealth+ Device Review — {_esc(adom)}</h2>
<p style="font-family:sans-serif;color:#6b7280">Generated: {generated_at}</p>
<p style="font-family:sans-serif">Devices scanned: {len(results)}</p>
{error_note}
{ai_narrative_html}
{check_summary_html}
{host_summary_html}
<p style="font-family:sans-serif;font-size:11px;color:#9ca3af;margin-top:16px">
  See attached report for full findings detail.
</p>"""


def _build_attachment_dr(
    adom: str,
    fmt: str,
    results: list[dict],
    generated_at: str,
    check_summary: list[dict],
    ai_narrative_html: str = "",
) -> dict:
    all_rows = [r for dev in results for r in dev.get("rows", [])]
    safe_adom = adom.replace(" ", "_")
    date_str = generated_at[:10]

    if fmt == "json":
        host_summary = []
        for dev in sorted(results, key=lambda d: d.get("device", "")):
            counts = {r: 0 for r in _SUMMARY_RESULTS}
            for row in dev.get("rows", []):
                res = row.get("result", "")
                if res in counts:
                    counts[res] += 1
            host_summary.append(
                {
                    "device": dev.get("device", ""),
                    "counts": counts,
                    "total": sum(counts.values()),
                }
            )
        payload = json.dumps(
            {
                "report_type": "device_review",
                "adom": adom,
                "exported_at": generated_at,
                "check_summary": [
                    {
                        "name": e["name"],
                        "description": e["description"],
                        **{r: e[r] for r in _CHECK_SUMMARY_RESULTS},
                    }
                    for e in check_summary
                ],
                "host_summary": host_summary,
                "rows": all_rows,
            },
            indent=2,
        ).encode()
        return {
            "filename": f"device_review_{safe_adom}_{date_str}.json",
            "data": payload,
            "mimetype": "application/json",
        }

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["# 4THealth+ Device Review"])
        w.writerow([f"# ADOM: {adom}"])
        w.writerow([f"# Generated: {generated_at}"])
        w.writerow([])
        w.writerow(["# Check Summary"])
        w.writerow(
            [
                "# Check",
                "Description",
                "PASS",
                "INFO",
                "WARN",
                "CONFIG_MISSING",
                "FAIL",
                "INSECURE",
            ]
        )
        for entry in check_summary:
            w.writerow(
                [
                    f"# {entry['name']}",
                    entry["description"],
                    entry["PASS"],
                    entry["INFO"],
                    entry["WARN"],
                    entry["CONFIG_MISSING"],
                    entry["FAIL"],
                    entry["INSECURE"],
                ]
            )
        w.writerow([])
        w.writerow(["# Host Summary"])
        w.writerow(
            [
                "# Device",
                "PASS",
                "FAIL",
                "INSECURE",
                "WARN",
                "CONFIG_MISSING",
                "INFO",
                "Total",
            ]
        )
        for dev in sorted(results, key=lambda d: d.get("device", "")):
            counts = {r: 0 for r in _SUMMARY_RESULTS}
            for row in dev.get("rows", []):
                res = row.get("result", "")
                if res in counts:
                    counts[res] += 1
            w.writerow(
                [
                    "# {}".format(dev.get("device", "")),
                    counts["PASS"],
                    counts["FAIL"],
                    counts["INSECURE"],
                    counts["WARN"],
                    counts["CONFIG_MISSING"],
                    counts["INFO"],
                    sum(counts.values()),
                ]
            )
        w.writerow([])
        w.writerow(["Device", "Check", "Result", "Interface", "VDOM", "IP", "Detail"])
        for row in all_rows:
            w.writerow(
                [
                    row.get("device", ""),
                    row.get("check", ""),
                    row.get("result", ""),
                    row.get("interface", ""),
                    row.get("vdom", ""),
                    row.get("ip", ""),
                    _fmt_detail(row),
                ]
            )
        return {
            "filename": f"device_review_{safe_adom}_{date_str}.csv",
            "data": buf.getvalue().encode(),
            "mimetype": "text/csv",
        }

    # pdf → styled HTML
    html = _build_pdf_html_dr(
        adom, results, generated_at, check_summary, ai_narrative_html
    )
    return {
        "filename": f"device_review_{safe_adom}_{date_str}.html",
        "data": html.encode(),
        "mimetype": "text/html",
    }


def _build_pdf_html_dr(
    adom: str,
    results: list[dict],
    generated_at: str,
    check_summary: list[dict],
    ai_narrative_html: str = "",
) -> str:
    all_rows = [r for dev in results for r in dev.get("rows", [])]

    # Build sorted unique device list for host dropdown
    unique_devices = sorted(
        {row.get("device", "") for row in all_rows if row.get("device")}
    )
    host_options = '<option value="ALL">All Hosts</option>\n'
    for dev in unique_devices:
        host_options += f'<option value="{_esc(dev)}">{_esc(dev)}</option>\n'

    # Build result filter buttons
    result_buttons = (
        '<button class="dr-result-btn active" data-result="ALL">ALL</button>\n'
    )
    for res in ("FAIL", "INSECURE", "WARN", "CONFIG_MISSING", "PASS", "INFO"):
        result_buttons += (
            f'<button class="dr-result-btn" data-result="{res}">{res}</button>\n'
        )

    # ── Findings rows ─────────────────────────────────────────────────────────
    rows_html = ""
    for row in all_rows:
        color = _RESULT_COLOR.get(row.get("result", ""), "#374151")
        result_val = _esc(row.get("result", ""))
        device_val = _esc(row.get("device", ""))
        rows_html += (
            f'<tr data-result="{result_val}" data-device="{device_val}">'
            f"<td>{_esc(row.get('device', ''))}</td>"
            f"<td>{_esc(row.get('check', ''))}</td>"
            f"<td style='color:{color};font-weight:600'>{_esc(row.get('result', ''))}</td>"
            f"<td>{_esc(row.get('interface', ''))}</td>"
            f"<td>{_esc(row.get('vdom', ''))}</td>"
            f"<td>{_esc(row.get('ip', ''))}</td>"
            f"<td>{_esc(_fmt_detail(row))}</td>"
            f"</tr>\n"
        )

    # ── Check Summary table ───────────────────────────────────────────────────
    cs_header = "".join(
        f"<th style='background:#f3f4f6;padding:4px 8px'>{r}</th>"
        for r in _CHECK_SUMMARY_RESULTS
    )
    cs_rows = ""
    for entry in check_summary:
        cells = "".join(
            f"<td style='padding:4px 8px;text-align:center;color:{_RESULT_COLOR.get(r, '#374151')}'>{entry[r]}</td>"
            for r in _CHECK_SUMMARY_RESULTS
        )
        cs_rows += (
            f"<tr>"
            f"<td style='padding:4px 8px'>{_esc(entry['name'])}</td>"
            f"<td style='padding:4px 8px;color:#6b7280'>{_esc(entry['description'])}</td>"
            f"{cells}"
            f"</tr>\n"
        )

    # ── Host Summary table ────────────────────────────────────────────────────
    summary_header = "".join(
        f"<th style='background:#f3f4f6;padding:4px 8px'>{r}</th>"
        for r in _SUMMARY_RESULTS
    )
    summary_rows = ""
    totals = {r: 0 for r in _SUMMARY_RESULTS}
    for dev in sorted(results, key=lambda d: d.get("device", "")):
        counts = {r: 0 for r in _SUMMARY_RESULTS}
        for row in dev.get("rows", []):
            res = row.get("result", "")
            if res in counts:
                counts[res] += 1
                totals[res] += 1
        total = sum(counts.values())
        cells = "".join(
            f"<td style='padding:4px 8px;text-align:center;color:{_RESULT_COLOR.get(r, '#374151')}'>{counts[r]}</td>"
            for r in _SUMMARY_RESULTS
        )
        error_note = " (error)" if dev.get("error") else ""
        dev_name = _esc(dev.get("device", ""))
        summary_rows += (
            f"<tr><td style='padding:4px 8px'>{dev_name}{error_note}</td>"
            f"{cells}"
            f"<td style='padding:4px 8px;text-align:center'>{total}</td></tr>\n"
        )
    total_cells = "".join(
        f"<td style='padding:4px 8px;text-align:center;font-weight:600;color:{_RESULT_COLOR.get(r, '#374151')}'>{totals[r]}</td>"
        for r in _SUMMARY_RESULTS
    )
    grand_total = sum(totals.values())
    summary_rows += (
        f"<tr style='background:#f3f4f6;font-weight:600'>"
        f"<td style='padding:4px 8px'>Totals</td>{total_cells}"
        f"<td style='padding:4px 8px;text-align:center'>{grand_total}</td></tr>\n"
    )

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
  body{{font-family:sans-serif;font-size:12px;color:#111}}
  h1{{font-size:18px;margin-bottom:4px}}
  h2{{font-size:14px;margin-top:24px;margin-bottom:6px}}
  .meta{{color:#6b7280;margin-bottom:16px;font-size:11px}}
  table{{border-collapse:collapse;width:100%;margin-bottom:24px}}
  th,td{{border:1px solid #e5e7eb;padding:4px 8px;text-align:left}}
  th{{background:#f3f4f6;font-weight:600}}
  tr:nth-child(even){{background:#fafafa}}
  {_REPORT_CSS}
</style>
</head>
<body>
<h1>4THealth+ Device Review Scheduler</h1>
<div class="meta">
  ADOM: {_esc(adom)} &nbsp;|&nbsp;
  Devices scanned: {len(results)} &nbsp;|&nbsp;
  Total findings: {len(all_rows)} &nbsp;|&nbsp;
  Generated: {generated_at}
</div>
{ai_narrative_html}
<h2>Check Summary</h2>
<table>
  <thead>
    <tr>
      <th style='background:#f3f4f6;padding:4px 8px'>Check</th>
      <th style='background:#f3f4f6;padding:4px 8px'>Description</th>
      {cs_header}
    </tr>
  </thead>
  <tbody>{cs_rows}</tbody>
</table>
<h2>Host Summary</h2>
<table>
  <thead>
    <tr>
      <th style='background:#f3f4f6;padding:4px 8px'>Device</th>
      {summary_header}
      <th style='background:#f3f4f6;padding:4px 8px'>Total</th>
    </tr>
  </thead>
  <tbody>{summary_rows}</tbody>
</table>
<div id="dr-filter-bar">
  {result_buttons}
  <select id="dr-host-select">{host_options}</select>
  <span id="dr-row-count"></span>
</div>
<h2>Findings</h2>
<table>
  <thead>
    <tr>
      <th>Device</th><th>Check</th><th>Result</th>
      <th>Interface</th><th>VDOM</th><th>IP</th><th>Detail</th>
    </tr>
  </thead>
  <tbody id="dr-findings-tbody">{rows_html}</tbody>
</table>
<script>{_REPORT_JS}</script>
</body>
</html>"""


# ── APScheduler integration ───────────────────────────────────────────────────


def _apscheduler_id(job_id: str) -> str:
    return f"dr_{job_id}"


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
                    "device_review_scheduler",
                    f"Failed to register job {job.get('id', '?')}: {exc}",
                )
    _scheduler.start()
    app_log(
        "INFO",
        "device_review_scheduler",
        f"Device Review scheduler started with "
        f"{sum(1 for j in jobs if j.get('enabled'))} active jobs",
    )
