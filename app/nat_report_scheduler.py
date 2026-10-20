"""Scheduled NAT Report email export engine.

For an ADOM, lists every NATted address (VIPs = inbound destination NAT,
IP pools = outbound source NAT) and, per policy package, the firewall rules
that use it. Jobs and run history are persisted in nat_report_jobs.json
(project root). Each enabled job is registered as an APScheduler CronTrigger
at startup.
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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from app.app_logger import app_log
from app.atomic_io import atomic_write_json

_JOBS_PATH = Path(__file__).parent.parent / "nat_report_jobs.json"
_lock = threading.Lock()
_scheduler = None  # BackgroundScheduler instance, set by init_scheduler
_running_jobs: set[str] = set()

_VALID_DAYS = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}
_VALID_FORMATS = {"csv", "json", "html"}

CSV_COLUMNS = [
    "Type",
    "NAT Object",
    "NATted IP",
    "Mapped IP",
    "Device",
    "Package",
    "Rule ID",
    "Rule Name",
    "Status",
    "Action",
    "Source",
    "Service",
]


# ── Indirection points (monkeypatched in tests) ───────────────────────────────


def _make_client():
    from app.fmg_helpers import make_client

    return make_client()


def _send_email(to, subject, body_html, attachments):
    from app.smtp_client import send_email

    send_email(to, subject, body_html, attachments)


def _collect(adom: str) -> dict:
    return collect_nat_data(adom)


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
    if data.get("format", "html") not in _VALID_FORMATS:
        raise ValueError(f"format must be one of {sorted(_VALID_FORMATS)}")


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
    lock_path = Path(tempfile.gettempdir()) / f"4thealth_nat_{job_id}.lock"
    fh = None
    try:
        fh = open(lock_path, "w")  # noqa: SIM115
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh
    except OSError:
        if fh is not None:
            fh.close()
        return None


# ── Data collection ───────────────────────────────────────────────────────────


def _names(val: Any) -> list[str]:
    """Flatten a FMG name-list field (list of str/dict, or bare str)."""
    if isinstance(val, list):
        out = []
        for m in val:
            n = (
                m
                if isinstance(m, str)
                else (m.get("name", "") if isinstance(m, dict) else "")
            )
            if n:
                out.append(n)
        return out
    if isinstance(val, str) and val:
        return [val]
    return []


def _norm_vip(vip: dict) -> dict | None:
    """Flatten a raw FMG VIP object into the fields the report needs."""
    name = vip.get("name", "")
    if not name:
        return None
    ext = vip.get("extip", "")
    if isinstance(ext, list):
        ext = ext[0] if ext else ""
    mapped_raw = vip.get("mappedip") or vip.get("mapped-ip") or []
    if isinstance(mapped_raw, str):
        mapped = [mapped_raw] if mapped_raw else []
    else:
        mapped = []
        for e in mapped_raw if isinstance(mapped_raw, list) else []:
            r = e.get("range", "") if isinstance(e, dict) else e
            if r:
                mapped.append(str(r))
    return {
        "nat_type": "VIP",
        "name": name,
        "nat_ip": str(ext),
        "mapped_ip": "; ".join(mapped),
        "device": vip.get("_source_device", ""),
        "vdom": vip.get("_source_vdom", ""),
    }


def _norm_pool(pool: dict) -> dict | None:
    name = pool.get("name", "")
    if not name:
        return None
    start, end = pool.get("startip", ""), pool.get("endip", "")
    nat_ip = start if start == end or not end else f"{start}-{end}"
    return {
        "nat_type": "IP Pool",
        "name": name,
        "nat_ip": nat_ip,
        "mapped_ip": "",
        "device": "",
        "vdom": "",
    }


def _norm_rule(rule: dict) -> dict:
    raw_status = rule.get("status", "enable")
    raw_action = rule.get("action", "accept")
    return {
        "policyid": rule.get("policyid", ""),
        "name": rule.get("name", ""),
        "status": "disable" if raw_status in (0, "disable") else "enable",
        "action": "deny" if raw_action in (0, "deny", "block") else "accept",
        "srcaddr": _names(rule.get("srcaddr")),
        "dstaddr": _names(rule.get("dstaddr")),
        "service": _names(rule.get("service")),
        "poolname": _names(rule.get("poolname")),
    }


def _fetch_package(adom: str, pkg: dict) -> dict:
    """Fetch the rules of one package; own client so workers run concurrently."""
    pkg_name = pkg.get("name", "")
    pkg_path = pkg.get("path", pkg_name)
    scope = [m for m in (pkg.get("scope member") or []) if isinstance(m, dict)]
    result = {
        "package": pkg_path,
        "package_name": pkg_name,
        "scope_members": scope,
        "rules": [],
        "error": None,
    }
    try:
        with _make_client() as client:
            result["rules"] = [
                _norm_rule(r)
                for r in client.get_policies(adom, pkg_path)
                if isinstance(r, dict)
            ]
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _fetch_device_vips(adom: str, dev_name: str) -> list[dict]:
    """Per-device VIPs (installed on a device but not in the shared DB), per VDOM."""
    out: list[dict] = []
    try:
        with _make_client() as c:
            vdoms_data = c.get_device_vdoms(adom, dev_name)
            vdoms = [
                v.get("name", "root")
                for v in (vdoms_data or [])
                if isinstance(v, dict) and v.get("name")
            ] or ["root"]
            for vdom in vdoms:
                try:
                    for e in c.get_device_vip_objects(dev_name, vdom):
                        if isinstance(e, dict):
                            e["_source_device"] = dev_name
                            e["_source_vdom"] = vdom
                            out.append(e)
                except Exception:
                    pass
    except Exception:
        pass
    return out


def collect_nat_data(adom: str, max_workers: int = 4) -> dict:
    """Fetch VIPs, IP pools and every package's rules for an ADOM."""
    with _make_client() as client:
        packages = client.get_policy_packages(adom) or []
        shared_vips = client.get_vip_objects(adom) or []
        pools = client.get_ippool_objects(adom) or []
        devices = client.get_devices(adom) or []

    dev_names = [
        d.get("name", "") for d in devices if isinstance(d, dict) and d.get("name")
    ]
    valid_pkgs = [
        p
        for p in packages
        if isinstance(p, dict)
        and (p.get("type") or "").lower() != "folder"
        and p.get("name")
    ]

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        dev_vip_lists = list(ex.map(lambda d: _fetch_device_vips(adom, d), dev_names))
        pkg_results = list(ex.map(lambda p: _fetch_package(adom, p), valid_pkgs))

    vips: list[dict] = []
    seen: set = set()
    for raw in shared_vips + [v for lst in dev_vip_lists for v in lst]:
        if not isinstance(raw, dict):
            continue
        nv = _norm_vip(raw)
        key = (nv["name"], nv["device"], nv["vdom"]) if nv else None
        if nv and key not in seen:
            seen.add(key)
            vips.append(nv)
    norm_pools = [np for p in pools if isinstance(p, dict) and (np := _norm_pool(p))]
    return {"vips": vips, "pools": norm_pools, "packages": pkg_results}


# ── Matching ──────────────────────────────────────────────────────────────────


def _expand_dst(names: list[str], group_members: dict) -> set[str]:
    """Expand address-group names in a rule's destination to a flat name set."""
    from app.rule_policy_scheduler import _expand_group

    out: set[str] = set()
    for n in names:
        for leaf in _expand_group(n, group_members):
            out.add(leaf["name"])
    return out


def _vip_applies(vip: dict, pkg: dict) -> bool:
    """Shared VIPs apply to every package; per-device VIPs only to packages
    whose scope includes that device (and VDOM, when both sides state one)."""
    if not vip["device"]:
        return True
    for m in pkg.get("scope_members") or []:
        if m.get("name") != vip["device"]:
            continue
        if not vip["vdom"] or not m.get("vdom") or m.get("vdom") == vip["vdom"]:
            return True
    return False


def _row(obj: dict, pkg: dict | None = None, rule: dict | None = None) -> dict:
    return {
        "nat_type": obj["nat_type"],
        "name": obj["name"],
        "nat_ip": obj["nat_ip"],
        "mapped_ip": obj["mapped_ip"],
        "device": obj["device"],
        "package": pkg["package_name"] if pkg else "",
        "policyid": rule["policyid"] if rule else "",
        "rule_name": rule["name"] if rule else "",
        "status": rule["status"] if rule else "",
        "action": rule["action"] if rule else "",
        "source": ", ".join(rule["srcaddr"]) if rule else "",
        "service": ", ".join(rule["service"]) if rule else "",
    }


def build_nat_rows(data: dict, group_members: dict | None = None) -> list[dict]:
    """One row per (NAT object, package, matching rule).

    A NAT object no rule uses gets a single row with blank package/rule fields
    so unused NAT objects are visible in the report.
    """
    group_members = group_members or {}
    packages = [p for p in data["packages"] if not p.get("error")]
    # Pre-expand each rule's destination once
    dst_sets = {
        (p["package"], i): _expand_dst(r["dstaddr"], group_members)
        for p in packages
        for i, r in enumerate(p["rules"])
    }
    rows: list[dict] = []
    for obj in data["vips"] + data["pools"]:
        matched = False
        for p in packages:
            if obj["nat_type"] == "VIP" and not _vip_applies(obj, p):
                continue
            for i, r in enumerate(p["rules"]):
                if obj["nat_type"] == "VIP":
                    hit = obj["name"] in dst_sets[(p["package"], i)]
                else:
                    hit = obj["name"] in r["poolname"]
                if hit:
                    matched = True
                    rows.append(_row(obj, p, r))
        if not matched:
            rows.append(_row(obj))
    rows.sort(
        key=lambda x: (x["nat_type"], x["name"], x["package"], str(x["policyid"]))
    )
    return rows


# ── Report rendering ──────────────────────────────────────────────────────────


def _esc(s: Any) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _row_cells(r: dict) -> list:
    return [
        r["nat_type"],
        r["name"],
        r["nat_ip"],
        r["mapped_ip"],
        r["device"],
        r["package"],
        r["policyid"],
        r["rule_name"],
        r["status"],
        r["action"],
        r["source"],
        r["service"],
    ]


def _summary(rows: list[dict]) -> dict:
    objs = {(r["nat_type"], r["name"], r["device"]) for r in rows}
    unused = {(r["nat_type"], r["name"], r["device"]) for r in rows if not r["package"]}
    return {
        "vips": sum(1 for o in objs if o[0] == "VIP"),
        "pools": sum(1 for o in objs if o[0] == "IP Pool"),
        "unused": len(unused),
        "rule_matches": sum(1 for r in rows if r["package"]),
    }


def scan_stats(data: dict) -> dict:
    """What the run actually looked at, so an empty result can be told apart
    from a run that never saw any packages or rules."""
    pkgs = data["packages"]
    ok = [p for p in pkgs if not p.get("error")]
    return {
        "packages_total": len(pkgs),
        "packages_ok": len(ok),
        "rules_scanned": sum(len(p["rules"]) for p in ok),
    }


def _build_summary_html(
    adom: str,
    rows: list[dict],
    errors: list[str],
    generated_at: str,
    stats: dict | None = None,
) -> str:
    s = _summary(rows)
    stats = stats or {}
    scanned = (
        f"<tr><td style='padding:4px 8px'>Packages scanned</td>"
        f"<td style='padding:4px 8px'>{stats['packages_ok']} of {stats['packages_total']}</td></tr>\n"
        f"  <tr><td style='padding:4px 8px'>Rules scanned</td>"
        f"<td style='padding:4px 8px'>{stats['rules_scanned']}</td></tr>\n  "
        if stats
        else ""
    )
    err = (
        f"<p style='font-family:sans-serif;color:#991b1b'>{len(errors)} package(s) "
        f"could not be read and are missing from this report.</p>"
        if errors
        else ""
    )
    return f"""
<h2 style="font-family:sans-serif">4THealth NAT Report — {_esc(adom)}</h2>
<p style="font-family:sans-serif;color:#6b7280">Generated: {generated_at}</p>
{err}
<table style='border-collapse:collapse;font-family:sans-serif;font-size:12px'>
  {scanned}<tr><td style='padding:4px 8px'>VIPs (inbound NAT)</td><td style='padding:4px 8px'>{s["vips"]}</td></tr>
  <tr><td style='padding:4px 8px'>IP Pools (outbound NAT)</td><td style='padding:4px 8px'>{s["pools"]}</td></tr>
  <tr><td style='padding:4px 8px'>Rule matches</td><td style='padding:4px 8px'>{s["rule_matches"]}</td></tr>
  <tr><td style='padding:4px 8px'>NAT objects used by no rule</td><td style='padding:4px 8px'>{s["unused"]}</td></tr>
</table>
<p style="font-family:sans-serif;font-size:11px;color:#9ca3af;margin-top:16px">See attached file for the full list.</p>"""


def build_attachment(
    adom: str,
    rows: list[dict],
    errors: list[str],
    fmt: str,
    generated_at: str,
    stats: dict | None = None,
) -> tuple[str, bytes]:
    """Return (filename, bytes) for the report."""
    base = f"nat_report_{adom.replace(' ', '_').replace('/', '-')}_{generated_at[:10]}"

    if fmt == "json":
        payload = json.dumps(
            {
                "report_type": "nat_report",
                "adom": adom,
                "exported_at": generated_at,
                "summary": {**_summary(rows), **(stats or {})},
                "package_errors": errors,
                "rows": rows,
            },
            indent=2,
        ).encode()
        return f"{base}.json", payload

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["# 4THealth NAT Report"])
        w.writerow([f"# ADOM: {adom}"])
        w.writerow([f"# Generated: {generated_at}"])
        if stats:
            w.writerow(
                [
                    (
                        f"# Packages scanned: {stats['packages_ok']} of {stats['packages_total']}"
                        f" | Rules scanned: {stats['rules_scanned']}"
                    )
                ]
            )
        for e in errors:
            w.writerow([f"# Package error: {e}"])
        w.writerow([])
        w.writerow(CSV_COLUMNS)
        for r in rows:
            w.writerow(_row_cells(r))
        return f"{base}.csv", buf.getvalue().encode()

    body = (
        "".join(
            "<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in _row_cells(r)) + "</tr>\n"
            for r in rows
        )
        or f"<tr><td colspan='{len(CSV_COLUMNS)}' style='text-align:center'>No NAT objects found</td></tr>"
    )
    head = "".join(f"<th>{_esc(c)}</th>" for c in CSV_COLUMNS)
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  body{{font-family:sans-serif;font-size:12px;color:#111}}
  h1{{font-size:18px;margin-bottom:4px}}
  table{{border-collapse:collapse;width:100%;margin-bottom:24px}}
  th,td{{border:1px solid #e5e7eb;padding:4px 8px;text-align:left}}
  th{{background:#f3f4f6;font-weight:600}}
  tr:nth-child(even){{background:#fafafa}}
</style>
</head>
<body>
<h1>4THealth NAT Report</h1>
{_build_summary_html(adom, rows, errors, generated_at, stats)}
<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>
</body></html>"""
    return f"{base}.html", html.encode()


# ── Core execution ────────────────────────────────────────────────────────────


def _execute_job(job_id: str) -> None:
    lock_fh = _try_acquire_job_lock(job_id)
    if lock_fh is None:
        app_log(
            "INFO", "nat_report_scheduler", f"Job {job_id} already running — skipping"
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
        "nat_objects": 0,
        "rule_matches": 0,
        "unused": 0,
        "packages_total": 0,
        "emails_sent": 0,
        "errors": [],
    }
    try:
        with _lock:
            jobs = _load()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if not job:
            app_log("ERROR", "nat_report_scheduler", f"Job {job_id} not found")
            return

        adom = job["adom"]
        fmt = job.get("format", "html")
        email = job["email"]
        app_log(
            "INFO",
            "nat_report_scheduler",
            f"Running scheduled NAT Report: adom={adom} format={fmt} to={email}",
        )

        data = _collect(adom)
        if not data["packages"]:
            # get_policy_packages() swallows FMG errors and returns [], which
            # would otherwise yield a report claiming no rule uses any NAT object.
            raise RuntimeError(f"No policy packages returned for ADOM {adom!r}")
        stats = scan_stats(data)
        generated_at = (
            datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        )
        record["ran_at"] = generated_at
        errors = [
            f"{p['package']}: {p['error']}" for p in data["packages"] if p.get("error")
        ]
        rows = build_nat_rows(data, _group_members(adom))
        s = _summary(rows)
        record.update(
            {
                "nat_objects": s["vips"] + s["pools"],
                "rule_matches": s["rule_matches"],
                "unused": s["unused"],
                "packages_total": stats["packages_total"],
                "packages_ok": stats["packages_ok"],
                "rules_scanned": stats["rules_scanned"],
                "errors": errors,
            }
        )

        filename, blob = build_attachment(adom, rows, errors, fmt, generated_at, stats)
        mimetype = {"csv": "text/csv", "json": "application/json"}.get(fmt, "text/html")
        _send_email(
            email,
            f"4THealth NAT Report — {adom} — {generated_at[:10]}",
            _build_summary_html(adom, rows, errors, generated_at, stats),
            [{"filename": filename, "data": blob, "mimetype": mimetype}],
        )
        record["emails_sent"] = 1
        record["status"] = "ok"
        app_log(
            "INFO",
            "nat_report_scheduler",
            f"NAT Report sent: adom={adom} nat_objects={record['nat_objects']} "
            f"matches={record['rule_matches']} to={email}",
        )
    except Exception as exc:
        record["status"] = "error"
        record["errors"] = record.get("errors") or [str(exc)]
        app_log(
            "ERROR", "nat_report_scheduler", f"NAT Report job {job_id} failed: {exc}"
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


def _group_members(adom: str) -> dict:
    """name -> {"members": [...]} catalog of address groups, for destination expansion."""
    from app.rule_policy_scheduler import _build_addr_catalog

    with _make_client() as client:
        groups = client.get_address_groups(adom, scope="all") or []
    return _build_addr_catalog([], groups)


# ── APScheduler integration ───────────────────────────────────────────────────


def _apscheduler_id(job_id: str) -> str:
    return f"nat_{job_id}"


_DAY_MAP = {d: d.lower() for d in _VALID_DAYS}


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
                    "nat_report_scheduler",
                    f"Failed to register job {job.get('id', '?')}: {exc}",
                )
    _scheduler.start()
    app_log(
        "INFO",
        "nat_report_scheduler",
        f"NAT Report scheduler started with {sum(1 for j in jobs if j.get('enabled'))} active jobs",
    )
