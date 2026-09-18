"""Scheduled Rule Policy export engine.

Jobs and run history are persisted in rule_policy_jobs.json (project root).
Each enabled job is registered as an APScheduler CronTrigger at startup.
"""

from __future__ import annotations

import csv
import datetime
import fcntl
import io
import json
import re
import tempfile
import threading
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from app.app_logger import app_log
from app.atomic_io import atomic_write_json

_JOBS_PATH = Path(__file__).parent.parent / "rule_policy_jobs.json"
_lock = threading.Lock()
_running_jobs: set[str] = set()


def _get_scheduler():
    """Return the running BackgroundScheduler from the Flask app context, or None."""
    try:
        from flask import current_app

        return current_app.extensions.get("rule_policy_scheduler")
    except RuntimeError:
        return None


_VALID_DAYS = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}
_VALID_SCHEDULE_TYPES = {"daily", "weekly", "monthly"}
_VALID_MONTHLY_POSITIONS = {"beginning", "end"}
_VALID_FORMATS = {"html", "csv", "json"}


# ── Indirection points (monkeypatched in tests) ───────────────────────────────


def _send_email(to, subject, body_html, attachments):
    from app.smtp_client import send_email

    send_email(to, subject, body_html, attachments)


def _bulk_policy_adom(adom, packages, include_global, live_hits, max_workers=4):
    """Thin wrapper around bulk_policy_adom — monkeypatched in tests."""
    return bulk_policy_adom(adom, packages, include_global, live_hits, max_workers)


# ── Validation ────────────────────────────────────────────────────────────────


def _validate_job_fields(data: dict) -> None:
    if not str(data.get("email", "")).strip():
        raise ValueError("email is required")
    if not str(data.get("adom", "")).strip():
        raise ValueError("adom is required")
    stype = data.get("schedule_type", "")
    if stype not in _VALID_SCHEDULE_TYPES:
        raise ValueError(
            f"schedule_type must be one of {sorted(_VALID_SCHEDULE_TYPES)}, got {stype!r}"
        )
    if stype == "weekly":
        days = data.get("days_of_week")
        if not isinstance(days, list) or not days:
            raise ValueError(
                "days_of_week must be a non-empty list for weekly schedule"
            )
        invalid = [d for d in days if d not in _VALID_DAYS]
        if invalid:
            raise ValueError(
                f"days_of_week contains invalid codes: {invalid}. "
                f"Must be from {sorted(_VALID_DAYS)}"
            )
    if stype == "monthly":
        pos = data.get("monthly_position", "")
        if pos not in _VALID_MONTHLY_POSITIONS:
            raise ValueError(
                f"monthly_position must be 'beginning' or 'end', got {pos!r}"
            )
    time_str = str(data.get("time", ""))
    parts = time_str.split(":")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise ValueError("time must be HH:MM format")
    if not (0 <= int(parts[0]) <= 23 and 0 <= int(parts[1]) <= 59):
        raise ValueError("time HH:MM — HH must be 0-23, MM must be 0-59")
    fmt = data.get("format", "html")
    if fmt not in _VALID_FORMATS:
        raise ValueError(f"format must be one of {sorted(_VALID_FORMATS)}, got {fmt!r}")
    try:
        batch_size = int(data.get("batch_size", 10))
    except (TypeError, ValueError):
        raise ValueError("batch_size must be an integer")
    if not (1 <= batch_size <= 50):
        raise ValueError("batch_size must be between 1 and 50")


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
        "name": str(data.get("name", "")).strip(),
        "adom": str(data.get("adom", "")),
        "packages": list(data.get("packages") or []),
        "schedule_type": data.get("schedule_type", "weekly"),
        "days_of_week": list(data.get("days_of_week") or []),
        "monthly_position": data.get("monthly_position", "beginning"),
        "time": data["time"],
        "include_global_policies": bool(data.get("include_global_policies", False)),
        "live_hit_counts": bool(data.get("live_hit_counts", False)),
        "format": data.get("format", "html"),
        "batch_size": int(data.get("batch_size", 10)),
        "email": str(data.get("email", "")),
        "enabled": bool(data.get("enabled", True)),
        "runs": [],
    }
    with _lock:
        jobs = _load()
        jobs.append(job)
        _save(jobs)
    if job["enabled"]:
        sch = _get_scheduler()
        if sch is not None:
            _register(sch, job)
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
                "name": str(data.get("name", existing.get("name", ""))).strip(),
                "adom": str(data.get("adom", existing["adom"])),
                "packages": list(data.get("packages") or []),
                "schedule_type": data.get(
                    "schedule_type", existing.get("schedule_type", "weekly")
                ),
                "days_of_week": list(data.get("days_of_week") or []),
                "monthly_position": data.get(
                    "monthly_position", existing.get("monthly_position", "beginning")
                ),
                "time": data["time"],
                "include_global_policies": bool(
                    data.get("include_global_policies", False)
                ),
                "live_hit_counts": bool(data.get("live_hit_counts", False)),
                "format": data.get("format", existing.get("format", "html")),
                "batch_size": int(data.get("batch_size", 10)),
                "email": str(data.get("email", existing["email"])),
                "enabled": bool(data.get("enabled", True)),
            }
        )
        jobs[idx] = existing
        _save(jobs)
    sch = _get_scheduler()
    if sch is not None:
        _unregister(sch, job_id)
        if existing["enabled"]:
            _register(sch, existing)
    return existing


def delete_job(job_id: str) -> None:
    with _lock:
        jobs = _load()
        new_jobs = [j for j in jobs if j["id"] != job_id]
        if len(new_jobs) == len(jobs):
            raise KeyError(f"Job {job_id} not found")
        _save(new_jobs)
    sch = _get_scheduler()
    if sch is not None:
        _unregister(sch, job_id)


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
    lock_path = Path(tempfile.gettempdir()) / f"4thealth_rp_{job_id}.lock"
    fh = None
    try:
        fh = open(lock_path, "w")  # noqa: SIM115 -- intentionally returned open as an advisory lock handle for the caller to close
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh
    except OSError:
        if fh is not None:
            fh.close()
        return None


# ── Catalog builders ──────────────────────────────────────────────────────────

MAX_GROUP_DEPTH = 8


def _build_addr_catalog(addr_objects: list, addr_groups: list) -> dict:
    """Build name → {"type", "detail", "members"} for address objects and groups.

    members=None means a leaf object; members=list means a group.
    """
    from app.routes.hygiene_routes import _addr_subnet

    catalog: dict = {}
    for ao in addr_objects:
        if not isinstance(ao, dict):
            continue
        name = ao.get("name", "")
        if not name:
            continue
        catalog[name] = {
            "type": ao.get("type", "ipmask"),
            "detail": _addr_subnet(ao),
            "members": None,
        }
    for grp in addr_groups:
        if not isinstance(grp, dict):
            continue
        name = grp.get("name", "")
        if not name:
            continue
        raw = grp.get("member") or []
        members = [
            (m if isinstance(m, str) else m.get("name", ""))
            for m in raw
            if (m if isinstance(m, str) else m.get("name", ""))
        ]
        catalog[name] = {
            "type": "group",
            "detail": f"{len(members)} members",
            "members": members,
        }
    return catalog


def _build_svc_catalog(svc_objects: list, svc_groups: list) -> dict:
    """Build name → {"type", "detail", "members"} for service objects and groups."""
    catalog: dict = {}
    for so in svc_objects:
        if not isinstance(so, dict):
            continue
        name = so.get("name", "")
        if not name:
            continue
        detail_parts = []
        if so.get("tcp-portrange"):
            detail_parts.append(f"tcp/{so['tcp-portrange']}")
        if so.get("udp-portrange"):
            detail_parts.append(f"udp/{so['udp-portrange']}")
        if not detail_parts and so.get("protocol-number"):
            detail_parts.append(f"proto/{so['protocol-number']}")
        catalog[name] = {
            "type": "service",
            "detail": " ".join(detail_parts) or name,
            "members": None,
        }
    for sg in svc_groups:
        if not isinstance(sg, dict):
            continue
        name = sg.get("name", "")
        if not name:
            continue
        raw = sg.get("member") or []
        members = [
            (m if isinstance(m, str) else m.get("name", ""))
            for m in raw
            if (m if isinstance(m, str) else m.get("name", ""))
        ]
        catalog[name] = {
            "type": "service-group",
            "detail": f"{len(members)} members",
            "members": members,
        }
    return catalog


# ── Group expansion ───────────────────────────────────────────────────────────


def _expand_group(
    name: str,
    catalog: dict,
    seen: frozenset | None = None,
    depth: int = 0,
) -> list[dict]:
    """Recursively expand a group name to its leaf members.

    Returns list of {"name", "leaf", "cycle", "reason", "detail"} dicts.
    seen is a frozenset — copy-on-enter prevents false cycle detection for
    diamond-shaped hierarchies (same leaf reachable via two paths).
    """
    if seen is None:
        seen = frozenset()
    if depth >= MAX_GROUP_DEPTH:
        return [
            {
                "name": name,
                "leaf": False,
                "cycle": True,
                "reason": "max_depth",
                "detail": "",
            }
        ]
    if name in seen:
        return [
            {
                "name": name,
                "leaf": False,
                "cycle": True,
                "reason": "circular",
                "detail": "",
            }
        ]

    entry = catalog.get(name)
    if entry is None:
        return [
            {"name": name, "leaf": True, "cycle": False, "reason": "", "detail": ""}
        ]

    members = entry.get("members")
    if members is None:
        return [
            {
                "name": name,
                "leaf": True,
                "cycle": False,
                "reason": "",
                "detail": entry.get("detail", ""),
            }
        ]

    new_seen = seen | {name}
    result: list = []
    for m_name in members:
        result.extend(_expand_group(m_name, catalog, new_seen, depth + 1))
    return result


def _extract_names(val: Any) -> list[str]:
    """Extract a flat list of name strings from a FMG field value.

    FMG returns address/service/interface fields as either a list of dicts
    with "name" keys, a list of plain strings, or a bare string.
    """
    if isinstance(val, list):
        return [
            (m if isinstance(m, str) else m.get("name", ""))
            for m in val
            if (m if isinstance(m, str) else m.get("name", ""))
        ]
    if isinstance(val, str) and val:
        return [val]
    return []


def _collect_groups_from_rules(
    rules: list[dict],
    addr_catalog: dict,
    svc_catalog: dict,
) -> dict:
    """Return group details for every group referenced in the rule set.

    Keys:
      "addr"    — {name: [leaf_dicts]} for address groups found in catalog
      "svc"     — {name: [leaf_dicts]} for service groups found in catalog
      "unknown" — sorted list of names referenced in rules but absent from
                  both the address and service catalogs entirely; these may be
                  groups, VIPs, or other objects whose catalog fetch returned
                  no matching entry.
    """
    addr_groups: dict = {}
    svc_groups: dict = {}
    unknown: set = set()

    for rule in rules:
        for field in ("srcaddr", "dstaddr"):
            for name in rule.get(field) or []:
                if name and name not in addr_groups:
                    entry = addr_catalog.get(name)
                    if entry is None:
                        unknown.add(name)
                    elif entry.get("members") is not None:
                        addr_groups[name] = _expand_group(name, addr_catalog)

        for name in rule.get("service") or []:
            if name and name not in svc_groups:
                entry = svc_catalog.get(name)
                if entry is None:
                    unknown.add(name)
                elif entry.get("members") is not None:
                    svc_groups[name] = _expand_group(name, svc_catalog)

    # Remove names that resolved as address or service groups
    unknown -= set(addr_groups) | set(svc_groups)
    return {"addr": addr_groups, "svc": svc_groups, "unknown": sorted(unknown)}


# ── FMG client indirection (monkeypatched in tests) ──────────────────────────


def _make_client():
    from app.fmg_helpers import make_client

    return make_client()


# ── Per-package data fetch ────────────────────────────────────────────────────


def _policy_for_pkg(
    adom: str,
    pkg: dict,
    catalogs: dict,
    live_hits: bool,
) -> dict:
    """Fetch and process all rules for a single policy package.

    Opens its own FMGClient so callers can dispatch many workers concurrently.
    Returns a result dict; on any exception the dict has error set and rules=[].
    """
    pkg_name = pkg.get("name", "")
    pkg_path = pkg.get("path", pkg_name)
    scope_members = pkg.get("scope member") or []
    device_str = (
        scope_members[0]["name"]
        if scope_members and isinstance(scope_members[0], dict)
        else ""
    )
    pulled_at = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

    _empty: dict = {
        "package": pkg_path,
        "package_name": pkg_name,
        "device": device_str,
        "scope_members": scope_members,
        "rules": [],
        "group_details": {"addr": {}, "svc": {}},
        "pulled_at": pulled_at,
        "total_rules": 0,
        "error": None,
        "hit_count_note": "",
    }

    try:
        with _make_client() as client:
            rules_raw = client.get_policies(adom, pkg_path)
            hit_map: dict = {}
            hit_source_label = "na"

            if live_hits and scope_members:
                hit_source_label = "live"
                for member in scope_members:
                    if not isinstance(member, dict):
                        continue
                    dev = member.get("name", "")
                    vdom = member.get("vdom", "root")
                    if dev:
                        hit_map.update(client.get_live_policy_hits(adom, dev, vdom))
            elif not live_hits:
                hit_source_label = "cached"
    except Exception as exc:
        return {**_empty, "error": str(exc)}

    addr_catalog = catalogs["addr_catalog"]
    svc_catalog = catalogs["svc_catalog"]

    rule_rows: list[dict] = []
    for idx, rule in enumerate(rules_raw):
        pid = rule.get("policyid", 0)
        raw_logtraffic = rule.get("logtraffic", "utm")
        if raw_logtraffic in (0, "disable"):
            logtraffic = "disable"
        elif raw_logtraffic in (1, "all"):
            logtraffic = "all"
        else:
            logtraffic = "utm"

        if logtraffic == "disable":
            hit_count = None
            hit_src = "disabled"
        elif live_hits:
            raw_hit = hit_map.get(int(pid)) if pid else None
            hit_count = raw_hit
            hit_src = "live"
        else:
            raw_hit = rule.get("_hitcount")
            hit_count = int(raw_hit) if raw_hit is not None else None
            hit_src = "cached" if raw_hit is not None else "na"

        raw_status = rule.get("status", "enable")
        raw_action = rule.get("action", "accept")
        raw_nat = rule.get("nat", "disable")
        rule_rows.append(
            {
                "seq": idx + 1,
                "policyid": pid,
                "name": rule.get("name", ""),
                "status": ("disable" if raw_status in (0, "disable") else "enable"),
                "srcintf": _extract_names(rule.get("srcintf")),
                "dstintf": _extract_names(rule.get("dstintf")),
                "srcaddr": _extract_names(rule.get("srcaddr")),
                "dstaddr": _extract_names(rule.get("dstaddr")),
                "service": _extract_names(rule.get("service")),
                "action": (
                    "deny"
                    if raw_action in (0, "deny", "block")
                    else "ipsec"
                    if raw_action in (2, "ipsec")
                    else "accept"
                ),
                "nat": "enable" if raw_nat in (1, "enable") else "disable",
                "logtraffic": logtraffic,
                "hit_count": hit_count,
                "hit_count_source": hit_src,
                "comments": rule.get("comments", ""),
            }
        )

    group_details = _collect_groups_from_rules(rule_rows, addr_catalog, svc_catalog)
    # Append synthetic implicit deny AFTER group collection so "all"/"ALL" never appear as unknowns
    rule_rows.append(
        {
            "seq": len(rule_rows) + 1,
            "policyid": "implicit",
            "name": "Implicit Deny",
            "status": "enable",
            "srcintf": ["any"],
            "dstintf": ["any"],
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "action": "deny",
            "nat": "disable",
            "logtraffic": "utm",
            "hit_count": None,
            "hit_count_source": "na",
            "comments": "Default implicit deny — all unmatched traffic is dropped",
            "implicit": True,
        }
    )
    hit_count_note = {
        "live": "Live (as of report time)",
        "cached": "FMG-cached (may be stale)",
        "na": "N/A",
    }.get(hit_source_label, "")

    return {
        "package": pkg_path,
        "package_name": pkg_name,
        "device": device_str,
        "scope_members": scope_members,
        "rules": rule_rows,
        "group_details": group_details,
        "pulled_at": pulled_at,
        "total_rules": len(rule_rows),
        "error": None,
        "hit_count_note": hit_count_note,
    }


def bulk_policy_adom(
    adom: str,
    packages: list,
    include_global: bool,
    live_hits: bool,
    max_workers: int = 4,
) -> tuple:
    """Fetch rule data for all (or named) packages in an ADOM.

    Returns (results, skipped) where skipped contains named packages not found.
    The catalog-fetch client is closed before ThreadPoolExecutor starts —
    each worker opens its own client.
    """
    with _make_client() as client:
        all_pkgs = client.get_policy_packages(adom)
        addr_objects = client.get_address_objects(adom, scope="all") or []
        addr_groups = client.get_address_groups(adom, scope="all") or []
        vip_objects = client.get_vip_objects(adom) or []
        svc_objects = client.get_service_objects(adom, scope="all") or []
        svc_groups = client.get_service_groups(adom, scope="all") or []

    # Build catalogs once — workers use them read-only
    addr_catalog = _build_addr_catalog(addr_objects + vip_objects, addr_groups)
    svc_catalog = _build_svc_catalog(svc_objects, svc_groups)
    catalogs = {"addr_catalog": addr_catalog, "svc_catalog": svc_catalog}

    # Filter to non-folder packages
    valid_pkgs = [
        p
        for p in all_pkgs
        if isinstance(p, dict)
        and (p.get("type") or "").lower() != "folder"
        and p.get("name")
    ]

    # Resolve requested package names; collect skipped ones
    skipped: list = []
    if packages:
        pkg_name_set = {p.get("name", "") for p in valid_pkgs}
        skipped = [
            f"{n} (not found in ADOM {adom!r})"
            for n in packages
            if n not in pkg_name_set
        ]
        requested = set(packages)
        valid_pkgs = [p for p in valid_pkgs if p.get("name", "") in requested]

    actual_workers = min(max_workers, 2) if live_hits else max_workers

    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        futures = [
            executor.submit(_policy_for_pkg, adom, pkg, catalogs, live_hits)
            for pkg in valid_pkgs
        ]
        results = [f.result() for f in futures]

    return {
        "adom": adom,
        "results": results,
        "skipped": skipped,
        "generated_at": datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z",
    }


# ── HTML/text helpers ─────────────────────────────────────────────────────────


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _file_base(result: dict, date_str: str) -> str:
    pkg = result.get("package_name", result.get("package", "pkg"))
    safe = re.sub(r"[^\w\-]", "_", pkg)
    dev = result.get("device", "")
    if dev:
        safe_dev = re.sub(r"[^\w\-]", "_", dev)
        return f"{safe_dev}-{safe}-{date_str}"
    return f"{safe}-{date_str}"


def _hit_display(rule: dict) -> tuple:
    """Return (cell_text, css_style) for the hit count column."""
    src = rule.get("hit_count_source", "na")
    if src == "disabled":
        return "Disabled", "color:#9ca3af"
    if src == "na" or rule.get("hit_count") is None:
        return "N/A", "color:#9ca3af"
    return str(rule["hit_count"]), ""


def _group_members_html(members: list, indent: int = 0) -> str:
    pad = "&nbsp;" * (indent * 4)
    rows = []
    for m in members:
        if m.get("cycle"):
            rows.append(
                f"<tr><td style='padding:2px 8px'>{pad}"
                f"<em style='color:#dc2626'>[cycle detected: {_esc(m['name'])}]</em>"
                f"</td><td></td></tr>"
            )
        else:
            rows.append(
                f"<tr><td style='padding:2px 8px'>{pad}{_esc(m['name'])}</td>"
                f"<td style='padding:2px 8px;color:#6b7280'>{_esc(m.get('detail', ''))}</td>"
                f"</tr>"
            )
    return "".join(rows)


# ── Report builders ───────────────────────────────────────────────────────────


def _build_attachment_rp(pkg_result: dict, job: dict, fmt: str) -> list:
    """Return list of (filename, bytes) for one package. CSV returns two files."""
    generated_at = pkg_result.get(
        "pulled_at", datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
    )
    date_str = generated_at[:10]
    result = pkg_result
    base = _file_base(result, date_str)
    rules = result.get("rules") or []
    group_details = result.get("group_details") or {"addr": {}, "svc": {}}
    pkg_name = result.get("package_name", result.get("package", ""))
    device_str = result.get("device") or "—"
    hit_note = result.get("hit_count_note", "")
    pkg_error = result.get("error")

    if fmt == "json":
        payload = json.dumps(
            {
                "report_type": "rule_policy",
                "job_name": job.get("name", ""),
                "package": result.get("package", ""),
                "package_name": pkg_name,
                "adom": job.get("adom", result.get("_adom", "")),
                "device": device_str,
                "scope_members": result.get("scope_members") or [],
                "pulled_at": result.get("pulled_at", generated_at),
                "total_rules": result.get("total_rules", len(rules)),
                "hit_count_note": hit_note,
                "rules": rules,
                "group_details": group_details,
                **({"error": pkg_error} if pkg_error else {}),
            },
            indent=2,
        ).encode()
        return [(f"{base}.json", payload)]

    if fmt == "csv":
        # File 1: rules
        rules_buf = io.StringIO()
        w = csv.writer(rules_buf)
        w.writerow(["# 4THealth Rule Policy Export"])
        w.writerow([f"# Package: {pkg_name}"])
        w.writerow([f"# Device(s): {device_str}"])
        w.writerow([f"# Generated: {generated_at}"])
        w.writerow([f"# Hit counts: {hit_note}"])
        if pkg_error:
            w.writerow(["ERROR", pkg_error])
        w.writerow([])
        w.writerow(
            [
                "Seq",
                "Policy ID",
                "Name",
                "Enabled",
                "Src Interface",
                "Dst Interface",
                "Source",
                "Destination",
                "Service",
                "Action",
                "NAT",
                "Logging",
                "Hit Count",
                "Comments",
            ]
        )
        for rule in rules:
            hit_text, _ = _hit_display(rule)
            w.writerow(
                [
                    rule.get("seq", ""),
                    rule.get("policyid", ""),
                    rule.get("name", ""),
                    rule.get("status", ""),
                    ";".join(rule.get("srcintf") or []),
                    ";".join(rule.get("dstintf") or []),
                    ";".join(rule.get("srcaddr") or []),
                    ";".join(rule.get("dstaddr") or []),
                    ";".join(rule.get("service") or []),
                    rule.get("action", ""),
                    rule.get("nat", ""),
                    rule.get("logtraffic", ""),
                    hit_text,
                    rule.get("comments", ""),
                ]
            )

        # File 2: groups
        grp_buf = io.StringIO()
        gw = csv.writer(grp_buf)
        gw.writerow(["# Group Details"])
        gw.writerow(["Group Name", "Type", "Member Name", "Member Detail"])
        for grp_name, members in (group_details.get("addr") or {}).items():
            for m in members:
                gw.writerow([grp_name, "address-group", m["name"], m.get("detail", "")])
        for grp_name, members in (group_details.get("svc") or {}).items():
            for m in members:
                gw.writerow([grp_name, "service-group", m["name"], m.get("detail", "")])
        for name in group_details.get("unknown") or []:
            gw.writerow([name, "not-found-in-catalog", "", ""])

        return [
            (f"{base}_rules.csv", rules_buf.getvalue().encode()),
            (f"{base}_groups.csv", grp_buf.getvalue().encode()),
        ]

    # html (default)
    error_banner = (
        f"<p style='color:#991b1b;font-weight:600'>Package error: {_esc(pkg_error)}</p>"
        if pkg_error
        else ""
    )

    rows_html = ""
    for rule in rules:
        if rule.get("implicit"):
            disabled_style = "background:#fff1f2;color:#9f1239;font-style:italic"
        elif rule.get("status") == "disable":
            disabled_style = "background:#f9fafb;color:#9ca3af"
        else:
            disabled_style = ""
        hit_text, hit_style = _hit_display(rule)
        rows_html += (
            f"<tr style='{disabled_style}'>"
            f"<td>{_esc(str(rule.get('seq', '')))}</td>"
            f"<td>{_esc(str(rule.get('policyid', '')))}</td>"
            f"<td>{_esc(rule.get('name', ''))}</td>"
            f"<td>{_esc(rule.get('status', ''))}</td>"
            f"<td>{_esc(';'.join(rule.get('srcintf') or []))}</td>"
            f"<td>{_esc(';'.join(rule.get('dstintf') or []))}</td>"
            f"<td>{_esc(';'.join(rule.get('srcaddr') or []))}</td>"
            f"<td>{_esc(';'.join(rule.get('dstaddr') or []))}</td>"
            f"<td>{_esc(';'.join(rule.get('service') or []))}</td>"
            f"<td>{_esc(rule.get('action', ''))}</td>"
            f"<td>{_esc(rule.get('nat', ''))}</td>"
            f"<td>{_esc(rule.get('logtraffic', ''))}</td>"
            f"<td style='{hit_style}'>{_esc(hit_text)}</td>"
            f"<td>{_esc(rule.get('comments', ''))}</td>"
            f"</tr>\n"
        )

    # Group Details section
    grp_html_parts = []
    for grp_name, members in (group_details.get("addr") or {}).items():
        grp_html_parts.append(
            f"<h3 style='font-size:13px;margin:16px 0 4px'>"
            f"{_esc(grp_name)} <span style='color:#6b7280;font-weight:normal'>"
            f"(address group)</span></h3>"
            f"<table style='border-collapse:collapse;font-size:11px;width:100%'>"
            f"<thead><tr style='background:#f3f4f6'>"
            f"<th style='padding:2px 8px'>Member</th><th style='padding:2px 8px'>Detail</th>"
            f"</tr></thead>"
            f"<tbody>{_group_members_html(members)}</tbody></table>"
        )
    for grp_name, members in (group_details.get("svc") or {}).items():
        grp_html_parts.append(
            f"<h3 style='font-size:13px;margin:16px 0 4px'>"
            f"{_esc(grp_name)} <span style='color:#6b7280;font-weight:normal'>"
            f"(service group)</span></h3>"
            f"<table style='border-collapse:collapse;font-size:11px;width:100%'>"
            f"<thead><tr style='background:#f3f4f6'>"
            f"<th style='padding:2px 8px'>Member</th><th style='padding:2px 8px'>Detail</th>"
            f"</tr></thead>"
            f"<tbody>{_group_members_html(members)}</tbody></table>"
        )

    unknown_names = group_details.get("unknown") or []
    if unknown_names:
        items_html = "".join(
            f"<tr><td style='padding:2px 8px'>{_esc(n)}</td>"
            f"<td style='padding:2px 8px;color:#6b7280'>not found in ADOM object catalog</td></tr>"
            for n in unknown_names
        )
        grp_html_parts.append(
            f"<h3 style='font-size:13px;margin:16px 0 4px;color:#92400e'>"
            f"Referenced names not found in catalog</h3>"
            f"<p style='font-size:11px;color:#78350f;margin:0 0 4px'>"
            f"These names appear in rule src/dst/service fields but were not returned "
            f"by the address group or address object catalog fetch. They may be VIPs, "
            f"IP ranges, or objects in a different scope.</p>"
            f"<table style='border-collapse:collapse;font-size:11px;width:100%'>"
            f"<thead><tr style='background:#fef3c7'>"
            f"<th style='padding:2px 8px'>Name</th><th style='padding:2px 8px'>Note</th>"
            f"</tr></thead>"
            f"<tbody>{items_html}</tbody></table>"
        )

    grp_section = (
        "".join(grp_html_parts) or "<p style='color:#6b7280'>No groups referenced.</p>"
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  body{{font-family:sans-serif;font-size:12px;color:#111;margin:20px}}
  h1{{font-size:18px;margin-bottom:4px}}
  h2{{font-size:15px;margin-top:28px;margin-bottom:8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}}
  h3{{font-size:13px;margin:16px 0 4px}}
  .meta{{color:#6b7280;font-size:11px;margin-bottom:16px}}
  table{{border-collapse:collapse;width:100%;margin-bottom:16px}}
  th,td{{border:1px solid #e5e7eb;padding:3px 6px;text-align:left;vertical-align:top}}
  th{{background:#f3f4f6;font-weight:600;white-space:nowrap}}
  tr:nth-child(even){{background:#fafafa}}
</style>
</head><body>
<h1>4THealth Rule Policy Export</h1>
{error_banner}
<div class="meta">
  Package: {_esc(pkg_name)} &nbsp;|&nbsp;
  Device(s): {_esc(device_str)} &nbsp;|&nbsp;
  Rules: {len(rules)} &nbsp;|&nbsp;
  Hit counts: {_esc(hit_note)} &nbsp;|&nbsp;
  Generated: {_esc(generated_at)}
</div>

<h2>Rule Details</h2>
<table>
  <thead><tr>
    <th>Seq</th><th>ID</th><th>Name</th><th>Enabled</th>
    <th>Src Intf</th><th>Dst Intf</th>
    <th>Source</th><th>Destination</th><th>Service</th>
    <th>Action</th><th>NAT</th><th>Logging</th><th>Hit Count</th><th>Comments</th>
  </tr></thead>
  <tbody>{rows_html if rows_html else "<tr><td colspan='14' style='text-align:center;color:#9ca3af'>No rules</td></tr>"}</tbody>
</table>

<h2>Group Details</h2>
{grp_section}
</body></html>"""

    return [(f"{base}.html", html.encode())]


def _build_all_attachments(bulk_result: dict, job: dict) -> list:
    fmt = job.get("format", "html")
    out: list = []
    for r in bulk_result.get("results", []):
        out.extend(_build_attachment_rp(r, job, fmt))
    return out


def _make_zip(attachments: list) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, data in attachments:
            zf.writestr(filename, data)
    return buf.getvalue()


def _build_summary_html(
    adom: str,
    results: list,
    skipped: list,
    generated_at: str,
) -> str:
    error_count = sum(1 for r in results if r.get("error"))
    rows_html = ""
    for r in results:
        status_color = "#dc2626" if r.get("error") else "#16a34a"
        status_text = f"Error: {_esc(r['error'])}" if r.get("error") else "OK"
        rows_html += (
            f"<tr>"
            f"<td style='padding:4px 8px'>{_esc(r.get('package_name', r.get('package', '')))}</td>"
            f"<td style='padding:4px 8px'>{_esc(r.get('device', '—'))}</td>"
            f"<td style='padding:4px 8px;text-align:right'>{r.get('total_rules', 0)}</td>"
            f"<td style='padding:4px 8px;color:{status_color}'>{status_text}</td>"
            f"</tr>\n"
        )

    skipped_html = ""
    if skipped:
        skip_items = "".join(f"<li>{_esc(s)}</li>" for s in skipped)
        skipped_html = (
            f"<p style='font-family:sans-serif;color:#b45309'>"
            f"<strong>Skipped packages ({len(skipped)}):</strong></p>"
            f"<ul style='font-family:sans-serif;font-size:12px;color:#b45309'>{skip_items}</ul>"
        )

    error_note = (
        f"<p style='font-family:sans-serif;color:#991b1b'>"
        f"{error_count} package(s) had errors.</p>"
        if error_count
        else ""
    )

    total_rules = sum(r.get("total_rules", 0) for r in results)

    return f"""
<h2 style="font-family:sans-serif">4THealth Rule Policy Export — {_esc(adom)}</h2>
<p style="font-family:sans-serif;color:#6b7280">Generated: {generated_at}</p>
<p style="font-family:sans-serif">Packages: {len(results)} &nbsp;|&nbsp; Total rules: {total_rules}</p>
{error_note}{skipped_html}
<table style='border-collapse:collapse;font-family:sans-serif;font-size:12px'>
  <thead><tr style='background:#f3f4f6'>
    <th style='padding:4px 8px'>Package</th>
    <th style='padding:4px 8px'>Device(s)</th>
    <th style='padding:4px 8px;text-align:right'>Rules</th>
    <th style='padding:4px 8px'>Status</th>
  </tr></thead>
  <tbody>{rows_html}</tbody>
</table>
<p style="font-family:sans-serif;font-size:11px;color:#9ca3af;margin-top:16px">
  See attached zip file(s) for per-package rule details.
</p>"""


# ── APScheduler integration ───────────────────────────────────────────────────

_DAY_MAP = {
    "SUN": "sun",
    "MON": "mon",
    "TUE": "tue",
    "WED": "wed",
    "THU": "thu",
    "FRI": "fri",
    "SAT": "sat",
}


def _apscheduler_id(job_id: str) -> str:
    return f"rp_{job_id}"


def _make_trigger(job: dict):
    from apscheduler.triggers.cron import CronTrigger

    h, m = job["time"].split(":")
    stype = job.get("schedule_type", "weekly")
    if stype == "daily":
        return CronTrigger(hour=int(h), minute=int(m))
    if stype == "monthly":
        day = 1 if job.get("monthly_position", "beginning") == "beginning" else "last"
        return CronTrigger(day=day, hour=int(h), minute=int(m))
    # weekly (default)
    day_str = ",".join(_DAY_MAP[d] for d in job.get("days_of_week", ["MON"]))
    return CronTrigger(day_of_week=day_str, hour=int(h), minute=int(m))


def _register(scheduler, job: dict) -> None:
    if not job.get("enabled", True):
        return
    scheduler.add_job(
        _execute_job,
        _make_trigger(job),
        args=[job["id"]],
        id=_apscheduler_id(job["id"]),
        replace_existing=True,
    )


def _unregister(scheduler, job_id: str) -> None:
    try:
        scheduler.remove_job(_apscheduler_id(job_id))
    except Exception:
        pass


def _execute_job(job_id: str) -> None:
    lock_fh = _try_acquire_job_lock(job_id)
    if lock_fh is None:
        app_log(
            "INFO", "rule_policy_scheduler", f"Job {job_id} already running — skipping"
        )
        return
    with _lock:
        _running_jobs.add(job_id)
    ran_at = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
    record: dict[str, Any] = {
        "ran_at": ran_at,
        "status": "error",
        "packages_total": 0,
        "packages_reviewed": 0,
        "packages_skipped": [],
        "total_rules": 0,
        "emails_sent": 0,
        "errors": [],
    }
    try:
        jobs = _load()
        job = next((j for j in jobs if j["id"] == job_id), None)
        if not job:
            app_log("ERROR", "rule_policy_scheduler", f"Job {job_id} not found")
            return
        if not job.get("enabled", True):
            app_log(
                "INFO", "rule_policy_scheduler", f"Job {job_id} is disabled — skipping"
            )
            return

        adom = job["adom"]
        email = job["email"]
        packages = list(job.get("packages") or [])
        include_global = bool(job.get("include_global_policies", False))
        live_hits = bool(job.get("live_hit_counts", False))
        batch_size = int(job.get("batch_size", 10))

        app_log(
            "INFO",
            "rule_policy_scheduler",
            f"Running scheduled Rule Policy: adom={adom} to={email}",
        )

        bulk_result = _bulk_policy_adom(adom, packages, include_global, live_hits)
        results = bulk_result["results"]
        skipped = bulk_result["skipped"]
        gen_at = bulk_result.get("generated_at", ran_at)

        total_rules = sum(r.get("total_rules", 0) for r in results)
        pkg_errors = [
            f"{r['package']}: {r['error']}" for r in results if r.get("error")
        ]

        record.update(
            {
                "ran_at": gen_at,
                "status": "ok",
                "packages_total": len(results) + len(skipped),
                "packages_reviewed": sum(1 for r in results if not r.get("error")),
                "packages_skipped": skipped,
                "total_rules": total_rules,
                "errors": pkg_errors,
            }
        )

        attachments = _build_all_attachments(bulk_result, job)
        summary_html = _build_summary_html(adom, results, skipped, gen_at)

        total_batch_emails = 0
        if attachments:
            batches = [
                attachments[i : i + batch_size]
                for i in range(0, len(attachments), batch_size)
            ]
            total = len(batches)
            for i, batch in enumerate(batches):
                if total == 1:
                    subject = f"[Rule Policy] {job['name']}"
                else:
                    subject = f"[Rule Policy] {job['name']} — Part {i + 1} of {total}"
                zip_bytes = _make_zip(batch)
                _send_email(
                    email,
                    subject,
                    summary_html
                    if i == 0
                    else f"<p>Part {i + 1} of {total}. See Part 1 for the summary.</p>",
                    [
                        {
                            "filename": f"report_part_{i + 1}.zip",
                            "data": zip_bytes,
                            "mimetype": "application/zip",
                        }
                    ],
                )
                total_batch_emails += 1

        # Send standalone summary only when there are no batch attachments
        if total_batch_emails == 0:
            _send_email(
                email,
                f"[Rule Policy] {job['name']} — Summary",
                summary_html,
                [],
            )
            record["emails_sent"] = 1
        else:
            record["emails_sent"] = total_batch_emails

        app_log(
            "INFO",
            "rule_policy_scheduler",
            f"Rule Policy sent: adom={adom} pkgs={len(results)} "
            f"rules={total_rules} emails={record['emails_sent']} to={email}",
        )

    except Exception as exc:
        record["status"] = "error"
        record["errors"] = record.get("errors") or [str(exc)]
        app_log(
            "ERROR", "rule_policy_scheduler", f"Rule Policy job {job_id} failed: {exc}"
        )
    finally:
        _append_run(job_id, record)
        try:
            from app.smtp_client import load_smtp_config as _load_smtp_cfg

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


def init_scheduler(app) -> None:
    from apscheduler.schedulers.background import BackgroundScheduler

    scheduler = BackgroundScheduler(daemon=True)
    jobs = _load()
    for job in jobs:
        if job.get("enabled", True):
            try:
                _register(scheduler, job)
            except Exception as exc:
                app_log(
                    "ERROR",
                    "rule_policy_scheduler",
                    f"Failed to register job {job.get('id', '?')}: {exc}",
                )
    scheduler.start()
    app.extensions["rule_policy_scheduler"] = scheduler
    app_log("INFO", "rule_policy_scheduler", "Rule Policy scheduler started")
