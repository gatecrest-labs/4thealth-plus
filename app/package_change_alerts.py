"""Package Change Alerts — email when a watched policy package has new pending changes.

Rules are persisted in package_change_alerts.json (project root). Evaluation is
driven by the Config-Delta scheduler: config_diff_scheduler._execute_job calls
evaluate_alerts() with the install-preview results it already collected.
Read-only — nothing is pushed to any device.
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import html
import io
import json
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from app.app_logger import app_log
from app.atomic_io import atomic_write_json

_RULES_PATH = Path(__file__).parent.parent / "package_change_alerts.json"
_lock = threading.Lock()

_VALID_FORMATS = {"html", "csv", "json"}
_MAX_RUNS = 50

# Top-level `config <section>` prefixes that count as "policy" changes.
_POLICY_SECTIONS = (
    "firewall policy",
    "firewall address",
    "firewall addrgrp",
    "firewall service",
    "firewall vip",
)


# ── Pure helpers ──────────────────────────────────────────────────────────────


def _is_frame(line: str) -> bool:
    low = line.strip().lower()
    return low.startswith("config ") or low == "end"


def filter_policy_changes(changes: list[dict]) -> list[dict]:
    """Keep only lines inside top-level policy-related `config` blocks.

    Nesting is tracked with both config/end depth and indentation. The depth
    alone is not enough: parse_preview_diff() strips the first `end` of each
    VDOM block, so real diffs arrive with unbalanced config/end lines. A
    `config` at or above the open section's indentation therefore starts a
    new top-level section (recovering from a lost `end`), while a deeper
    `config` is nested inside the current `edit`. Returns [] when a kept
    section holds only its config/end frame lines.
    """
    kept: list[dict] = []
    depth = 0
    section_indent = 0
    keep_section = False
    for change in changes:
        line = change["line"]
        low = line.strip().lower()
        indent = len(line) - len(line.lstrip())
        if low.startswith("config "):
            if depth == 0 or indent <= section_indent:
                depth = 1
                section_indent = indent
                keep_section = low[len("config ") :].startswith(_POLICY_SECTIONS)
            else:
                depth += 1
            if keep_section:
                kept.append(change)
        elif low == "end":
            if keep_section:
                kept.append(change)
            if depth > 1 and indent > section_indent:
                depth -= 1  # closes a nested block
            else:
                depth = 0  # closes the section (a stray `end` at depth 0 is ignored)
                keep_section = False
        elif keep_section:
            kept.append(change)
    if all(_is_frame(c["line"]) for c in kept):
        return []
    return kept


def _scope_of(pkg: dict) -> list[dict]:
    scope = pkg.get("scope member") or pkg.get("scope_member") or []
    return [m for m in scope if isinstance(m, dict) and m.get("name")]


def package_targets(
    packages: list[dict], group_members: dict[str, list[str]]
) -> dict[str, list[tuple[str, str]]]:
    """Map package name -> [(device, vdom)]; vdom "" means every vdom."""
    out: dict[str, list[tuple[str, str]]] = {}
    for pkg in packages:
        name = pkg.get("name")
        if not name or (pkg.get("type") or "").lower() == "folder":
            continue
        targets: list[tuple[str, str]] = []
        for member in _scope_of(pkg):
            vdom = member.get("vdom") or ""
            for device in group_members.get(member["name"], [member["name"]]):
                targets.append((device, vdom))
        out[name] = targets
    return out


def collect_package_diffs(
    targets: list[tuple[str, str]], results: list[dict]
) -> dict[str, dict[str, list[dict]]]:
    """Return {device: {vdom: policy_changes}} for a package's targets."""
    by_device = {r["device"]: r for r in results if r.get("status") == "ok"}
    diffs: dict[str, dict[str, list[dict]]] = {}
    for device, vdom in targets:
        result = by_device.get(device)
        if not result:
            continue
        for v in result.get("vdoms") or []:
            if vdom and v.get("name") != vdom:
                continue
            kept = filter_policy_changes(v.get("changes") or [])
            if kept:
                diffs.setdefault(device, {})[v["name"]] = kept
    return diffs


def has_unreadable_targets(targets: list[tuple[str, str]], results: list[dict]) -> bool:
    """True if any target device has no usable preview, so 'no diff' is unknown.

    That covers a device whose preview errored and one that is missing from
    the results entirely (for example a device-group scope member that could
    not be expanded).
    """
    readable = {r["device"] for r in results if r.get("status") != "error"}
    return any(device not in readable for device, _ in targets)


def diff_hash(diffs: dict[str, dict[str, list[dict]]]) -> str:
    h = hashlib.sha256()
    for device in sorted(diffs):
        for vdom in sorted(diffs[device]):
            for c in diffs[device][vdom]:
                h.update(f"{device}|{vdom}|{c['type']}|{c['line']}\n".encode())
    return h.hexdigest()


# ── Rule persistence ──────────────────────────────────────────────────────────


def _validate_rule_fields(data: dict) -> None:
    for field in ("name", "adom", "email"):
        if not str(data.get(field) or "").strip():
            raise ValueError(f"{field} is required")
    packages = data.get("packages", [])
    if not isinstance(packages, list) or not all(
        isinstance(p, str) and p.strip() for p in packages
    ):
        raise ValueError("packages must be a list of package names")
    if data.get("format", "html") not in _VALID_FORMATS:
        raise ValueError(f"format must be one of {sorted(_VALID_FORMATS)}")


def _load() -> list[dict]:
    if not _RULES_PATH.exists():
        return []
    try:
        data = json.loads(_RULES_PATH.read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save(rules: list[dict]) -> None:
    atomic_write_json(_RULES_PATH, rules)


def get_all_rules() -> list[dict]:
    with _lock:
        return _load()


def create_rule(data: dict) -> dict:
    _validate_rule_fields(data)
    rule: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "name": data["name"].strip(),
        "adom": data["adom"].strip(),
        "packages": [p.strip() for p in data.get("packages", [])],
        "email": data["email"].strip(),
        "format": data.get("format", "html"),
        "enabled": bool(data.get("enabled", True)),
        "sent": {},
        "runs": [],
        "created_at": datetime.datetime.now(datetime.UTC)
        .replace(tzinfo=None)
        .isoformat()
        + "Z",
    }
    with _lock:
        rules = _load()
        rules.append(rule)
        _save(rules)
    return rule


def update_rule(rule_id: str, data: dict) -> dict:
    _validate_rule_fields(data)
    with _lock:
        rules = _load()
        for i, r in enumerate(rules):
            if r["id"] == rule_id:
                rules[i] = {
                    **r,
                    "name": data["name"].strip(),
                    "adom": data["adom"].strip(),
                    "packages": [p.strip() for p in data.get("packages", [])],
                    "email": data["email"].strip(),
                    "format": data.get("format", "html"),
                    "enabled": bool(data.get("enabled", True)),
                }
                _save(rules)
                return rules[i]
    raise KeyError(f"Rule {rule_id} not found")


def delete_rule(rule_id: str) -> None:
    with _lock:
        rules = _load()
        remaining = [r for r in rules if r["id"] != rule_id]
        if len(remaining) == len(rules):
            raise KeyError(f"Rule {rule_id} not found")
        _save(remaining)


def _save_rule_state(rule_id: str, sent: dict | None, record: dict) -> None:
    """Persist dedupe state + run record. Re-loads under the lock so concurrent
    rule edits are preserved; silently skips a rule deleted mid-evaluation.
    ``sent=None`` leaves the stored dedupe state untouched (failure records)."""
    with _lock:
        rules = _load()
        for r in rules:
            if r["id"] == rule_id:
                if sent is not None:
                    r["sent"] = sent
                r["runs"] = ([record] + (r.get("runs") or []))[:_MAX_RUNS]
                _save(rules)
                return


# ── Attachment / email builders ───────────────────────────────────────────────

_MIME = {"html": "text/html", "csv": "text/csv", "json": "application/json"}


def _safe(name: str) -> str:
    return re.sub(r"[^\w\-]", "_", name)


def build_diff_attachment(
    adom: str, package: str, diffs: dict, fmt: str, generated_at: str
) -> dict:
    date = generated_at[:10]
    base = f"{_safe(package)}-policy-changes-{date}"
    if fmt == "json":
        data = json.dumps(
            {
                "adom": adom,
                "package": package,
                "generated_at": generated_at,
                "devices": diffs,
            },
            indent=2,
        ).encode()
    elif fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([f"# Package Change Alert — {package} ({adom}) — {generated_at}"])
        w.writerow(["device", "vdom", "type", "line"])
        for device in sorted(diffs):
            for vdom in sorted(diffs[device]):
                for c in diffs[device][vdom]:
                    w.writerow([device, vdom, c["type"], c["line"]])
        data = buf.getvalue().encode()
    else:
        fmt = "html"
        parts = [
            "<html><body style='font-family:sans-serif'>",
            f"<h2>Policy changes — {html.escape(package)}</h2>",
            f"<p>ADOM: {html.escape(adom)} &middot; Generated: {html.escape(generated_at)}</p>",
        ]
        for device in sorted(diffs):
            for vdom in sorted(diffs[device]):
                parts.append(
                    f"<h3>{html.escape(device)} / {html.escape(vdom)}</h3><pre>"
                )
                parts.extend(html.escape(c["line"]) + "\n" for c in diffs[device][vdom])
                parts.append("</pre>")
        parts.append("</body></html>")
        data = "".join(parts).encode()
    return {"filename": f"{base}.{fmt}", "data": data, "mimetype": _MIME[fmt]}


def build_email_html(
    rule_name: str, adom: str, package: str, diffs: dict, generated_at: str
) -> str:
    rows = "".join(
        f"<tr><td>{html.escape(device)}</td><td>{html.escape(vdom)}</td>"
        f"<td>{len(diffs[device][vdom])}</td></tr>"
        for device in sorted(diffs)
        for vdom in sorted(diffs[device])
    )
    return (
        f"<p>Policy package <strong>{html.escape(package)}</strong> in ADOM "
        f"<strong>{html.escape(adom)}</strong> has pending policy changes "
        f"(rule: {html.escape(rule_name)}, detected {html.escape(generated_at)}).</p>"
        "<table border='1' cellpadding='4' cellspacing='0'>"
        "<thead><tr><th>Device</th><th>VDOM</th><th>Changed lines</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "<p>Attached: (1) the pending policy changes, (2) the current policy "
        "&ldquo;as is&rdquo; with groups expanded.</p>"
    )


def _send_email(to, subject, body_html, attachments):
    from app.smtp_client import send_email

    send_email(to, subject, body_html, attachments)


def _policy_reports(adom: str, packages: list[str], fmt: str) -> dict[str, list[dict]]:
    """Build the 'policy as is' attachments for several packages in one FMG pass.

    Reuses the Rule Policy builders. Packages that are missing from the ADOM or
    whose report errored are omitted so the caller treats them as failed.
    """
    from app import rule_policy_scheduler as rp

    bulk = rp._bulk_policy_adom(adom, packages, False, False, 2)
    out: dict[str, list[dict]] = {}
    for result in bulk.get("results", []):
        if result.get("error"):
            continue
        atts = []
        for filename, data in rp._build_attachment_rp(result, {"format": fmt}, fmt):
            ext = filename.rsplit(".", 1)[-1]
            atts.append(
                {
                    "filename": filename,
                    "data": data if isinstance(data, bytes) else data.encode(),
                    "mimetype": _MIME.get(ext, "application/octet-stream"),
                }
            )
        out[result["package_name"]] = atts
    return out


# ── Evaluation ────────────────────────────────────────────────────────────────


def _fetch_packages_and_groups(adom: str) -> tuple[list[dict], dict[str, list[str]]]:
    """Fetch the ADOM's packages and expand any device-group scope members.

    Indirection point (monkeypatched in tests). Read-only FMG calls.
    """
    from app.fmg_helpers import make_client

    with make_client() as client:
        packages = client.get_policy_packages(adom)
        if not packages:
            # FMGClient swallows errors and returns []; an empty answer would
            # make every watched package look clean and wipe the dedupe state.
            raise RuntimeError(
                f"no policy packages returned for ADOM {adom!r} "
                "(FortiManager unreachable or ADOM empty)"
            )
        names = {m["name"] for p in packages for m in _scope_of(p)}
        group_members: dict[str, list[str]] = {}
        if names:
            for group in names & client.get_device_group_names(adom):
                group_members[group] = client.get_device_group_members(adom, group)
    return packages, group_members


def _evaluate_rule(
    rule: dict,
    adom: str,
    targets: dict[str, list[tuple[str, str]]],
    results: list[dict],
    generated_at: str,
) -> None:
    watched = rule.get("packages") or sorted(targets)
    sent = dict(rule.get("sent") or {})
    record: dict[str, Any] = {
        "ran_at": generated_at,
        "status": "ok",
        "packages_checked": len(watched),
        "alerts_sent": 0,
        "errors": [],
        "skipped": [],
    }
    changed: dict[str, tuple[dict, str]] = {}
    for pkg in watched:
        if pkg not in targets:
            # Renamed/deleted package, or the package lookup came back short:
            # the state is unknown, so leave it alone.
            record["skipped"].append(f"{pkg}: package not found in ADOM")
            continue
        pkg_targets = targets[pkg]
        if has_unreadable_targets(pkg_targets, results):
            # A diff built from only some of the package's devices would alert
            # with partial content and again once the device is readable, and
            # "no diff" cannot be trusted either. Skip; keep dedupe state.
            record["skipped"].append(
                f"{pkg}: a target device could not be previewed this run"
            )
            continue
        diffs = collect_package_diffs(pkg_targets, results)
        if not diffs:
            sent.pop(pkg, None)  # clean -> re-arm
            continue
        digest = diff_hash(diffs)
        if sent.get(pkg) != digest:
            changed[pkg] = (diffs, digest)

    reports: dict[str, list[dict]] = {}
    if changed:
        try:
            reports = _policy_reports(adom, list(changed), rule.get("format", "html"))
        except Exception as exc:
            record["errors"].append(f"policy report fetch failed: {exc}")

    for pkg, (diffs, digest) in changed.items():
        try:
            if pkg not in reports:
                raise RuntimeError("policy report unavailable")
            attachments = [
                build_diff_attachment(
                    adom, pkg, diffs, rule.get("format", "html"), generated_at
                )
            ] + reports[pkg]
            _send_email(
                rule["email"],
                f"[Package Change] {adom} / {pkg}",
                build_email_html(rule["name"], adom, pkg, diffs, generated_at),
                attachments,
            )
            sent[pkg] = digest
            record["alerts_sent"] += 1
        except Exception as exc:
            record["errors"].append(f"{pkg}: {exc}")
            app_log(
                "ERROR",
                "package_change_alerts",
                f"Alert for {adom}/{pkg} (rule {rule['id']}) failed: {exc}",
            )
    if record["errors"]:
        record["status"] = "error"
    _save_rule_state(rule["id"], sent, record)


def evaluate_alerts(adom: str, preview_results: list[dict]) -> None:
    """Called by the Config-Delta scheduler with its install-preview results."""
    with _lock:
        rules = [r for r in _load() if r.get("enabled") and r.get("adom") == adom]
    if not rules:
        return
    generated_at = (
        datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
    )
    try:
        packages, group_members = _fetch_packages_and_groups(adom)
    except Exception as exc:
        app_log(
            "ERROR",
            "package_change_alerts",
            f"Package lookup failed for ADOM {adom}: {exc}",
        )
        for rule in rules:
            _record_failure(rule, generated_at, f"package lookup failed: {exc}")
        return
    targets = package_targets(packages, group_members)
    for rule in rules:
        try:
            _evaluate_rule(rule, adom, targets, preview_results, generated_at)
        except Exception as exc:  # one bad rule must not stop the others
            app_log(
                "ERROR",
                "package_change_alerts",
                f"Rule {rule.get('id', '?')} evaluation failed for ADOM {adom}: {exc}",
            )
            _record_failure(rule, generated_at, str(exc))


def _record_failure(rule: dict, generated_at: str, message: str) -> None:
    """Record a failed evaluation on the rule without touching its dedupe state."""
    try:
        _save_rule_state(
            rule["id"],
            None,
            {
                "ran_at": generated_at,
                "status": "error",
                "packages_checked": 0,
                "alerts_sent": 0,
                "errors": [message],
                "skipped": [],
            },
        )
    except Exception as exc:
        app_log(
            "ERROR",
            "package_change_alerts",
            f"Could not record failure for rule {rule.get('id', '?')}: {exc}",
        )


def send_test_email(rule_id: str) -> None:
    """Send a sample alert (no attachments, no FMG calls, no dedupe state)."""
    rule = next((r for r in get_all_rules() if r["id"] == rule_id), None)
    if rule is None:
        raise KeyError(f"Rule {rule_id} not found")
    _send_email(
        rule["email"],
        f"[Package Change] TEST — {rule['name']}",
        "<p>This is a test of the 4THealth Package Change Alerts rule "
        f"<strong>{html.escape(rule['name'])}</strong> for ADOM "
        f"<strong>{html.escape(rule['adom'])}</strong>. No action required.</p>",
        [],
    )
