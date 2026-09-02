"""Scheduled Rule Hygiene email export engine.

Jobs and run history are persisted in rule_hygiene_jobs.json (project root).
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
import zipfile
from pathlib import Path
from typing import Any

from app.app_logger import app_log
from app.atomic_io import atomic_write_json

_JOBS_PATH = Path(__file__).parent.parent / "rule_hygiene_jobs.json"
_lock = threading.Lock()
_scheduler = None  # BackgroundScheduler instance, set by init_scheduler
_running_jobs: set[str] = set()

_VALID_DAYS = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}


# ── Indirection points (monkeypatched in tests) ───────────────────────────────


def _bulk_hygiene_adom(adom, checks, include_unused_objects=False, max_workers=4):
    from app.routes.hygiene_routes import bulk_hygiene_adom

    return bulk_hygiene_adom(adom, checks, include_unused_objects, max_workers)


def _send_email(to, subject, body_html, attachments):
    from app.smtp_client import send_email

    send_email(to, subject, body_html, attachments)


# ── Validation ────────────────────────────────────────────────────────────────


def _validate_job_fields(data: dict) -> None:
    if not str(data.get("email", "")).strip():
        raise ValueError("email is required")
    if not str(data.get("adom", "")).strip():
        raise ValueError("adom is required")
    days = data.get("days_of_week")
    if not isinstance(days, list) or not days:
        raise ValueError("days_of_week must be a non-empty list")
    invalid = [d for d in days if d not in _VALID_DAYS]
    if invalid:
        raise ValueError(
            f"days_of_week contains invalid codes: {invalid}. "
            f"Must be from {sorted(_VALID_DAYS)}"
        )
    time_str = data.get("time", "")
    parts = time_str.split(":")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise ValueError("time must be HH:MM format")
    if not (0 <= int(parts[0]) <= 23 and 0 <= int(parts[1]) <= 59):
        raise ValueError("time HH:MM — HH must be 0-23, MM must be 0-59")
    try:
        batch_size = int(data.get("batch_size", 20))
    except (TypeError, ValueError):
        raise ValueError("batch_size must be an integer")
    if not (1 <= batch_size <= 100):
        raise ValueError("batch_size must be between 1 and 100")


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
        "include_unused_objects": bool(data.get("include_unused_objects", False)),
        "batch_size": int(data.get("batch_size", 20)),
        "format": data.get("format", "html"),
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
                "include_unused_objects": bool(
                    data.get("include_unused_objects", False)
                ),
                "batch_size": int(data.get("batch_size", 20)),
                "format": data.get("format", existing.get("format", "html")),
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
    lock_path = Path(tempfile.gettempdir()) / f"4thealth_rh_{job_id}.lock"
    fh = None
    try:
        fh = open(lock_path, "w")  # noqa: SIM115 -- intentionally returned open as an advisory lock handle for the caller to close
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh
    except OSError:
        if fh is not None:
            fh.close()
        return None


# ── Email/report helpers ──────────────────────────────────────────────────────


def _get_all_checks() -> list[str]:
    """Return all hygiene check keys from app.hygiene.CHECKS (deferred to avoid circular import)."""
    from app.hygiene import CHECKS as _HC

    return list(_HC.keys())


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _file_base(result: dict, date_str: str) -> str:
    device = result.get("device")
    pkg_name = result.get("package_name", result.get("package", "pkg"))
    safe_pkg = pkg_name.replace(" ", "_").replace("/", "-")
    if device:
        safe_dev = device.replace(" ", "_").replace("/", "-")
        return f"{safe_dev}-{safe_pkg}-{date_str}"
    return f"{safe_pkg}-{date_str}"


def _build_attachment_rh(
    result: dict, fmt: str, generated_at: str
) -> tuple[str, bytes]:
    """Return (filename, bytes) for one package's report."""
    from app.hygiene import CHECKS as HYGIENE_CHECKS

    date_str = generated_at[:10]
    base = _file_base(result, date_str)
    findings = result.get("findings") or []
    pkg_name = result.get("package_name", result.get("package", ""))
    scope = result.get("scope_members") or []
    device_str = result.get("device") or (", ".join(scope) if scope else "—")
    unused_obj = result.get("unused_objects") or {}
    policy_count = result.get("policy_count", 0)

    pkg_error = result.get("error")

    if fmt == "json":
        payload = json.dumps(
            {
                "report_type": "rule_hygiene",
                "package": result.get("package", ""),
                "package_name": pkg_name,
                "device": device_str,
                "scope_members": scope,
                "policy_count": policy_count,
                "exported_at": generated_at,
                "findings": findings,
                "unused_objects": unused_obj if unused_obj else None,
                **({"error": pkg_error} if pkg_error else {}),
            },
            indent=2,
        ).encode()
        return f"{base}.json", payload

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["# 4THealth Rule Hygiene"])
        w.writerow([f"# Package: {pkg_name}"])
        w.writerow([f"# Device(s): {device_str}"])
        w.writerow([f"# Generated: {generated_at}"])
        if pkg_error:
            w.writerow(["ERROR", pkg_error])
        w.writerow([])
        w.writerow(["Policy ID", "Policy Name", "Seq", "Check", "Detail"])
        for f in findings:
            w.writerow(
                [
                    f.get("policy_id", ""),
                    f.get("policy_name", ""),
                    f.get("seq", ""),
                    f.get("check", ""),
                    f.get("detail", ""),
                ]
            )
        if unused_obj:
            w.writerow([])
            w.writerow(["# Unused Addresses"])
            w.writerow(["Name", "Type"])
            for obj in unused_obj.get("unused_addresses") or []:
                w.writerow([obj.get("name", ""), obj.get("type", "")])
            w.writerow(["# Unused Services"])
            w.writerow(["Name", "Type"])
            for obj in unused_obj.get("unused_services") or []:
                w.writerow([obj.get("name", ""), obj.get("type", "")])
        return f"{base}.csv", buf.getvalue().encode()

    # html (default)
    error_banner_html = (
        (
            f"<p class='error' style='color:#991b1b;font-weight:600'>"
            f"Package error: {_esc(pkg_error)}</p>"
        )
        if pkg_error
        else ""
    )
    rows_html = ""
    for f in findings:
        check_display = HYGIENE_CHECKS.get(f.get("check", ""), f.get("check", ""))
        rows_html += (
            f"<tr>"
            f"<td style='padding:4px 8px'>{_esc(str(f.get('seq', '')))}</td>"
            f"<td style='padding:4px 8px'>{_esc(f.get('policy_id', ''))}</td>"
            f"<td style='padding:4px 8px'>{_esc(f.get('policy_name', ''))}</td>"
            f"<td style='padding:4px 8px'>{_esc(check_display)}</td>"
            f"<td style='padding:4px 8px'>{_esc(f.get('detail', ''))}</td>"
            f"</tr>\n"
        )
    no_findings = (
        "<tr><td colspan='5' style='text-align:center;color:#6b7280'>"
        "No findings</td></tr>"
    )

    unused_html = ""
    if unused_obj:
        addr_rows = "".join(
            f"<tr><td style='padding:4px 8px'>{_esc(o.get('name', ''))}</td>"
            f"<td style='padding:4px 8px'>{_esc(o.get('type', ''))}</td></tr>\n"
            for o in (unused_obj.get("unused_addresses") or [])
        )
        svc_rows = "".join(
            f"<tr><td style='padding:4px 8px'>{_esc(o.get('name', ''))}</td>"
            f"<td style='padding:4px 8px'>{_esc(o.get('type', ''))}</td></tr>\n"
            for o in (unused_obj.get("unused_services") or [])
        )
        unused_html = f"""
<h2 style='font-size:14px;margin-top:24px'>
  Unused Addresses ({len(unused_obj.get("unused_addresses") or [])})
</h2>
<table style='border-collapse:collapse;font-family:sans-serif;font-size:12px;width:100%'>
  <thead><tr style='background:#f3f4f6'>
    <th style='padding:4px 8px'>Name</th><th style='padding:4px 8px'>Type</th>
  </tr></thead>
  <tbody>{addr_rows or "<tr><td colspan='2' style='text-align:center;color:#6b7280'>None</td></tr>"}</tbody>
</table>
<h2 style='font-size:14px;margin-top:24px'>
  Unused Services ({len(unused_obj.get("unused_services") or [])})
</h2>
<table style='border-collapse:collapse;font-family:sans-serif;font-size:12px;width:100%'>
  <thead><tr style='background:#f3f4f6'>
    <th style='padding:4px 8px'>Name</th><th style='padding:4px 8px'>Type</th>
  </tr></thead>
  <tbody>{svc_rows or "<tr><td colspan='2' style='text-align:center;color:#6b7280'>None</td></tr>"}</tbody>
</table>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  body{{font-family:sans-serif;font-size:12px;color:#111}}
  h1{{font-size:18px;margin-bottom:4px}}
  h2{{font-size:14px;margin-top:24px;margin-bottom:6px}}
  .meta{{color:#6b7280;margin-bottom:16px;font-size:11px}}
  table{{border-collapse:collapse;width:100%;margin-bottom:24px}}
  th,td{{border:1px solid #e5e7eb;padding:4px 8px;text-align:left}}
  th{{background:#f3f4f6;font-weight:600}}
  tr:nth-child(even){{background:#fafafa}}
</style>
</head>
<body>
<h1>4THealth Rule Hygiene</h1>
{error_banner_html}
<div class="meta">
  Package: {_esc(pkg_name)} &nbsp;|&nbsp;
  Device(s): {_esc(device_str)} &nbsp;|&nbsp;
  Policies: {policy_count} &nbsp;|&nbsp;
  Findings: {len(findings)} &nbsp;|&nbsp;
  Generated: {generated_at}
</div>
<h2>Findings ({len(findings)})</h2>
<table>
  <thead>
    <tr><th>Seq</th><th>Policy ID</th><th>Policy Name</th><th>Check</th><th>Detail</th></tr>
  </thead>
  <tbody>{rows_html if rows_html else no_findings}</tbody>
</table>
{unused_html}
</body></html>"""
    return f"{base}.html", html.encode()


def _build_all_attachments(
    results: list[dict], fmt: str, generated_at: str
) -> list[tuple[str, bytes]]:
    return [_build_attachment_rh(r, fmt, generated_at) for r in results]


def _make_zip(attachments: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, data in attachments:
            zf.writestr(filename, data)
    return buf.getvalue()


def _build_summary_html(
    adom: str,
    results: list[dict],
    generated_at: str,
    include_unused: bool,
) -> str:
    from app.hygiene import CHECKS as HYGIENE_CHECKS

    check_keys = _get_all_checks()
    check_names = {k: HYGIENE_CHECKS.get(k, k) for k in check_keys}

    check_header_cells = "".join(
        f"<th style='padding:4px 8px;font-size:11px'>{_esc(check_names[k])}</th>"
        for k in check_keys
    )
    unused_headers = (
        (
            "<th style='padding:4px 8px;font-size:11px'>Unused Addr</th>"
            "<th style='padding:4px 8px;font-size:11px'>Unused Svc</th>"
        )
        if include_unused
        else ""
    )

    rows_html = ""
    totals = {k: 0 for k in check_keys}
    total_unused_addr = 0
    total_unused_svc = 0
    error_count = 0

    for r in sorted(results, key=lambda x: x.get("package_name", "")):
        pkg_name = r.get("package_name", r.get("package", ""))
        device = r.get("device")
        scope = r.get("scope_members") or []
        device_cell = device or (", ".join(scope) if scope else "—")
        error = r.get("error")
        findings = r.get("findings") or []

        counts = {k: 0 for k in check_keys}
        for f in findings:
            key = f.get("check", "")
            if key in counts:
                counts[key] += 1
                totals[key] += 1

        unused_obj = r.get("unused_objects") or {}
        unused_addr = len(unused_obj.get("unused_addresses") or [])
        unused_svc = len(unused_obj.get("unused_services") or [])
        total_unused_addr += unused_addr
        total_unused_svc += unused_svc

        has_findings = sum(counts.values()) > 0 or unused_addr > 0 or unused_svc > 0
        if error:
            row_style = "background:#fee2e2"
            error_count += 1
        elif has_findings:
            row_style = "background:#fef3c7"
        else:
            row_style = ""

        check_cells = "".join(
            "<td style='padding:4px 8px;text-align:center;color:{c}'>{v}</td>".format(
                c="#991b1b" if counts[k] > 0 else "#166534", v=counts[k]
            )
            for k in check_keys
        )
        unused_cells = ""
        if include_unused:
            unused_cells = (
                "<td style='padding:4px 8px;text-align:center;color:{ca}'>{va}</td>"
                "<td style='padding:4px 8px;text-align:center;color:{cs}'>{vs}</td>"
            ).format(
                ca="#991b1b" if unused_addr > 0 else "#166534",
                va=unused_addr,
                cs="#991b1b" if unused_svc > 0 else "#166534",
                vs=unused_svc,
            )
        error_note = (
            f" <span style='color:#991b1b'>(error: {_esc(error)})</span>"
            if error
            else ""
        )
        rows_html += (
            f"<tr style='{row_style}'>"
            f"<td style='padding:4px 8px'>{_esc(device_cell)}</td>"
            f"<td style='padding:4px 8px'>{_esc(pkg_name)}{error_note}</td>"
            f"<td style='padding:4px 8px;text-align:center'>{r.get('policy_count', 0)}</td>"
            f"{check_cells}{unused_cells}"
            f"</tr>\n"
        )

    total_check_cells = "".join(
        "<td style='padding:4px 8px;text-align:center;font-weight:600;color:{c}'>{v}</td>".format(
            c="#991b1b" if totals[k] > 0 else "#166534", v=totals[k]
        )
        for k in check_keys
    )
    total_unused_cells = ""
    if include_unused:
        total_unused_cells = (
            "<td style='padding:4px 8px;text-align:center;font-weight:600;color:{ca}'>{va}</td>"
            "<td style='padding:4px 8px;text-align:center;font-weight:600;color:{cs}'>{vs}</td>"
        ).format(
            ca="#991b1b" if total_unused_addr > 0 else "#166534",
            va=total_unused_addr,
            cs="#991b1b" if total_unused_svc > 0 else "#166534",
            vs=total_unused_svc,
        )
    rows_html += (
        f"<tr style='background:#f3f4f6;font-weight:600'>"
        f"<td style='padding:4px 8px' colspan='2'>Totals</td>"
        f"<td style='padding:4px 8px;text-align:center'></td>"
        f"{total_check_cells}{total_unused_cells}"
        f"</tr>\n"
    )

    error_note_html = (
        (
            f"<p style='font-family:sans-serif;color:#991b1b'>"
            f"{error_count} package(s) had errors — see table for details.</p>"
        )
        if error_count
        else ""
    )

    return f"""
<h2 style="font-family:sans-serif">4THealth Rule Hygiene — {_esc(adom)}</h2>
<p style="font-family:sans-serif;color:#6b7280">Generated: {generated_at}</p>
<p style="font-family:sans-serif">Packages scanned: {len(results)}</p>
{error_note_html}
<table style='border-collapse:collapse;font-family:sans-serif;font-size:12px'>
  <thead>
    <tr style='background:#f3f4f6'>
      <th style='padding:4px 8px;text-align:left'>Device(s)</th>
      <th style='padding:4px 8px;text-align:left'>Package</th>
      <th style='padding:4px 8px'>Policies</th>
      {check_header_cells}{unused_headers}
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>
<p style="font-family:sans-serif;font-size:11px;color:#9ca3af;margin-top:16px">
  See attached zip file(s) for per-package finding details.
</p>"""


# ── Core execution ────────────────────────────────────────────────────────────


def _execute_job(job_id: str) -> None:
    lock_fh = _try_acquire_job_lock(job_id)
    if lock_fh is None:
        app_log(
            "INFO", "rule_hygiene_scheduler", f"Job {job_id} already running — skipping"
        )
        return
    with _lock:
        _running_jobs.add(job_id)
    generated_at = (
        datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
    )
    record: dict[str, Any] = {
        "ran_at": generated_at,
        "status": "error",
        "packages_total": 0,
        "packages_reviewed": 0,
        "total_findings": 0,
        "emails_sent": 0,
        "errors": [],
    }
    try:
        with _lock:
            jobs = _load()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if not job:
            app_log("ERROR", "rule_hygiene_scheduler", f"Job {job_id} not found")
            return

        adom = job["adom"]
        fmt = job.get("format", "html")
        email = job["email"]
        checks = job.get("checks") or []
        include_unused = bool(job.get("include_unused_objects", False))
        batch_size = int(job.get("batch_size", 20))

        app_log(
            "INFO",
            "rule_hygiene_scheduler",
            f"Running scheduled Rule Hygiene: adom={adom} format={fmt} to={email}",
        )

        results = _bulk_hygiene_adom(
            adom, checks, include_unused_objects=include_unused
        )

        generated_at = (
            datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        )
        record["ran_at"] = generated_at
        total_findings = sum(len(r.get("findings", [])) for r in results)
        pkg_errors = [
            f"{r['package']}: {r['error']}" for r in results if r.get("error")
        ]

        record.update(
            {
                "status": "ok",
                "packages_total": len(results),
                "packages_reviewed": sum(1 for r in results if not r.get("error")),
                "total_findings": total_findings,
                "errors": pkg_errors,
            }
        )

        summary_html = _build_summary_html(adom, results, generated_at, include_unused)
        attachments = _build_all_attachments(results, fmt, generated_at)

        safe_adom = adom.replace(" ", "_")
        date_str = generated_at[:10]

        if not attachments:
            subject = f"4THealth Rule Hygiene — {adom} — {date_str}"
            _send_email(email, subject, summary_html, [])
            record["emails_sent"] = 1
        else:
            batches = [
                attachments[i : i + batch_size]
                for i in range(0, len(attachments), batch_size)
            ]
            total_parts = len(batches)
            emails_sent = 0
            for part_idx, batch in enumerate(batches):
                part_num = part_idx + 1
                if total_parts == 1:
                    subject = f"4THealth Rule Hygiene — {adom} — {date_str}"
                    zip_filename = f"rule_hygiene_{safe_adom}_{date_str}.zip"
                    body = summary_html
                elif part_num == 1:
                    subject = f"4THealth Rule Hygiene — {adom} — {date_str}"
                    zip_filename = (
                        f"rule_hygiene_{safe_adom}_{date_str}_part1of{total_parts}.zip"
                    )
                    body = (
                        summary_html
                        + f"<p style='font-family:sans-serif;color:#6b7280'>"
                        f"This is Part 1 of {total_parts}. "
                        f"Parts 2–{total_parts} contain the remaining files.</p>"
                    )
                else:
                    subject = (
                        f"[Part {part_num} of {total_parts}] "
                        f"4THealth Rule Hygiene — {adom} — {date_str}"
                    )
                    zip_filename = (
                        f"rule_hygiene_{safe_adom}_{date_str}"
                        f"_part{part_num}of{total_parts}.zip"
                    )
                    body = (
                        f"<p style='font-family:sans-serif'>"
                        f"This is Part {part_num} of {total_parts}. "
                        f"See Part 1 for the full summary.</p>"
                    )
                zip_bytes = _make_zip(batch)
                _send_email(
                    email,
                    subject,
                    body,
                    [
                        {
                            "filename": zip_filename,
                            "data": zip_bytes,
                            "mimetype": "application/zip",
                        }
                    ],
                )
                emails_sent += 1
            record["emails_sent"] = emails_sent

        app_log(
            "INFO",
            "rule_hygiene_scheduler",
            f"Rule Hygiene report sent: adom={adom} packages={len(results)} "
            f"findings={total_findings} emails={record['emails_sent']} to={email}",
        )

    except Exception as exc:
        record["status"] = "error"
        record["errors"] = record.get("errors") or [str(exc)]
        app_log(
            "ERROR",
            "rule_hygiene_scheduler",
            f"Rule Hygiene scheduled job {job_id} failed: {exc}",
        )
    finally:
        _append_run(job_id, record)
        from app.smtp_client import load_smtp_config as _load_smtp_cfg

        try:
            retention = _load_smtp_cfg().get("run_history_days", 30)
        except Exception:
            retention = 30
        _prune_runs(job_id, retention_days=retention)
        with _lock:
            _running_jobs.discard(job_id)
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
            lock_fh.close()
        except Exception:
            pass


# ── APScheduler integration ───────────────────────────────────────────────────


def _apscheduler_id(job_id: str) -> str:
    return f"rh_{job_id}"


_DAY_MAP = {
    "SUN": "sun",
    "MON": "mon",
    "TUE": "tue",
    "WED": "wed",
    "THU": "thu",
    "FRI": "fri",
    "SAT": "sat",
}


def _register(job: dict) -> None:
    if _scheduler is None:
        return
    from apscheduler.triggers.cron import CronTrigger

    h, m = job["time"].split(":")
    day_str = ",".join(_DAY_MAP[d] for d in job["days_of_week"])
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
                    "rule_hygiene_scheduler",
                    f"Failed to register job {job.get('id', '?')}: {exc}",
                )
    _scheduler.start()
    app_log(
        "INFO",
        "rule_hygiene_scheduler",
        f"Rule Hygiene scheduler started with "
        f"{sum(1 for j in jobs if j.get('enabled'))} active jobs",
    )
