"""FortiManager API self-test.

Runs a registry of read-only FMG calls against whatever FortiManager the app
is configured for and reports, per call, whether it works — and which app
feature depends on it. It exists to answer two questions quickly after an FMG
upgrade or a token change:

  * Did the API shape change? (``error`` results)
  * Is the API token allowed to do everything the app needs? (``denied``)

The latter matters because several client methods deliberately swallow
failures and return ``{}``/``[]``; the self-test reads ``client.degraded``
(see ``FMGClient._note_degraded``) so those no longer look like "no data".

Strictly read-only. It never calls the install-preview chain (which stages a
package on the FMG), and never writes anything.
"""

from __future__ import annotations

import time

from app.fmg_client import FMGError

NO_PERMISSION = -11  # FMG status code: "No permission for the resource"
_MAX_ADOMS_PROBED = 30


def _probe_device(client, sample):
    """Raise if FMG cannot reach the sample device through its proxy."""
    err = client.get_device_proxy_error(sample["adom"], sample["device"])
    if err:
        raise FMGError(
            err.get("message") or "device unreachable via FortiManager",
            code=err.get("code"),
        )
    return {}


def _is_system_adom(name: str) -> bool:
    # Same convention as every ADOM list endpoint in the app (see CLAUDE.md).
    return name.lower().startswith("forti")


def _describe(result) -> str:
    if isinstance(result, (list, tuple, set)):
        return f"{len(result)} item(s)"
    if isinstance(result, dict):
        return f"{len(result)} field(s)"
    return ""


def _pick_sample(client) -> dict:
    """Choose the ADOM/device/package the sample-dependent checks run against."""
    sample = {"adom": None, "device": None, "package": None}
    try:
        names = [
            a.get("name", "")
            for a in client.get_adoms()
            if isinstance(a, dict) and a.get("name") and not _is_system_adom(a["name"])
        ]
    except Exception:
        return sample
    if not names:
        return sample
    sample["adom"] = names[0]
    for name in names[:_MAX_ADOMS_PROBED]:
        try:
            devices = client.get_devices(name)
        except Exception:
            continue
        first = next(
            (d.get("name") for d in devices if isinstance(d, dict) and d.get("name")),
            None,
        )
        if first:
            sample["adom"], sample["device"] = name, first
            break
    try:
        pkgs = client.get_policy_packages(sample["adom"])
        sample["package"] = next(
            (p.get("path") or p.get("name") for p in pkgs if isinstance(p, dict)), None
        )
    except Exception:
        pass
    return sample


# id, label, app feature that depends on it, needs, call, degraded-op name.
# ``needs`` lists sample keys that must be present, else the check is skipped.
_CHECKS = [
    (
        "system_status",
        "System status",
        "FortiManager version, Infrastructure page, PSIRT",
        (),
        lambda c, s: c.get_system_status(),
        None,
    ),
    ("adoms", "ADOM list", "Every ADOM picker", (), lambda c, s: c.get_adoms(), None),
    (
        "resource_performance",
        "Resource performance",
        "FMG CPU/memory on the Infrastructure page (non-SNMP path)",
        (),
        lambda c, s: c.get_performance(),
        "get_performance",
    ),
    (
        "resource_usage",
        "Resource usage",
        "FMG CPU/memory fallback endpoint",
        (),
        lambda c, s: c.get_resource_usage(),
        "get_resource_usage",
    ),
    (
        "audit_log",
        "Audit log",
        "Change Control (admin audit-log aggregation)",
        (),
        lambda c, s: c.get_audit_log(24),
        "get_audit_log",
    ),
    (
        "devices",
        "Managed devices",
        "Firewalls, Versions, Map, summary job",
        ("adom",),
        lambda c, s: c.get_devices(s["adom"]),
        None,
    ),
    (
        "device_sync_status",
        "Device sync status",
        "Config-Delta device table",
        ("adom",),
        lambda c, s: c.get_devices_with_sync_status(s["adom"]),
        None,
    ),
    (
        "adom_revisions",
        "Config revisions",
        "Device backup age (executive summary)",
        ("adom",),
        lambda c, s: c.get_adom_revisions(s["adom"]),
        None,
    ),
    (
        "policy_packages",
        "Policy packages",
        "Rule Review, Hygiene, Audit Review package pickers",
        ("adom",),
        lambda c, s: c.get_policy_packages(s["adom"]),
        None,
    ),
    (
        "policies",
        "Policy rules",
        "Rule Review, Hygiene Analysis, Rule Lookup",
        ("adom", "package"),
        lambda c, s: c.get_policies(s["adom"], s["package"]),
        None,
    ),
    (
        "address_objects",
        "Address objects",
        "Object Lookup, unused-objects scan, Rule Validation",
        ("adom",),
        lambda c, s: c.get_address_objects(s["adom"]),
        None,
    ),
    (
        "service_objects",
        "Service objects",
        "Object Lookup, Rule Validation",
        ("adom",),
        lambda c, s: c.get_service_objects(s["adom"]),
        None,
    ),
    (
        "vip_objects",
        "VIP objects",
        "NAT Lookup, NAT Report",
        ("adom",),
        lambda c, s: c.get_vip_objects(s["adom"]),
        None,
    ),
    (
        "device_proxy",
        "Device reachable via FMG proxy",
        "Everything below that reads a live FortiGate (health, CIS checks, licenses)",
        ("adom", "device"),
        _probe_device,
        None,
    ),
    (
        "device_license",
        "Device license (proxy)",
        "License Status, FortiGuard Subscriptions",
        ("adom", "device"),
        lambda c, s: c.get_device_license_status(s["adom"], s["device"]),
        None,
    ),
    (
        "device_system_global",
        "Device system global (proxy)",
        "Audit Review CIS checks",
        ("adom", "device"),
        lambda c, s: c.get_device_system_global(s["adom"], s["device"]),
        None,
    ),
    (
        "device_interfaces",
        "Device interfaces (proxy)",
        "Interface Lookup, Audit Review, route tracing",
        ("adom", "device"),
        lambda c, s: c.get_device_interfaces(s["adom"], s["device"]),
        None,
    ),
]


def _entry(check_id, label, feature, status, started, code=None, message=""):
    return {
        "id": check_id,
        "label": label,
        "feature": feature,
        "status": status,  # ok | denied | error | skipped
        "code": code,
        "message": message,
        "ms": int((time.monotonic() - started) * 1000),
    }


# Checks that read a live FortiGate through FMG's proxy; skipped when the
# device itself cannot be reached (their results would be meaningless).
_NEEDS_REACHABLE_DEVICE = {
    "device_license",
    "device_system_global",
    "device_interfaces",
}


def _run_one(client, check, sample, unreachable=None) -> dict:
    check_id, label, feature, needs, call, degraded_op = check
    started = time.monotonic()
    if unreachable and check_id in _NEEDS_REACHABLE_DEVICE:
        return _entry(
            check_id,
            label,
            feature,
            "skipped",
            started,
            message=f"Device unreachable via FortiManager: {unreachable}",
        )
    missing = [k for k in needs if not sample.get(k)]
    if missing:
        return _entry(
            check_id,
            label,
            feature,
            "skipped",
            started,
            message=f"No sample {', '.join(missing)} available in this FortiManager",
        )
    degraded = getattr(client, "degraded", None)
    if degraded is not None and degraded_op:
        degraded.pop(degraded_op, None)
    try:
        result = call(client, sample)
    except Exception as exc:
        code = getattr(exc, "code", None)
        status = "denied" if code == NO_PERMISSION else "error"
        return _entry(
            check_id, label, feature, status, started, code=code, message=str(exc)
        )
    if degraded is not None and degraded_op and degraded_op in degraded:
        info = degraded[degraded_op]
        code = info.get("code")
        status = "denied" if code == NO_PERMISSION else "error"
        return _entry(
            check_id,
            label,
            feature,
            status,
            started,
            code=code,
            message=info.get("message", ""),
        )
    return _entry(check_id, label, feature, "ok", started, message=_describe(result))


def run_selftest(client) -> dict:
    """Run every check against ``client`` and return a JSON-serialisable report."""
    version = getattr(client, "version", None)
    sample = _pick_sample(client)
    checks = []
    unreachable = None
    for check in _CHECKS:
        entry = _run_one(client, check, sample, unreachable)
        if check[0] == "device_proxy" and entry["status"] == "error":
            unreachable = entry["message"]
        checks.append(entry)
    summary = {"ok": 0, "denied": 0, "error": 0, "skipped": 0}
    for c in checks:
        summary[c["status"]] += 1
    return {
        "fmg_version": f"{version.major}.{version.minor}.{version.patch}"
        if version
        else None,
        "train": version.train if version else None,
        "sample": sample,
        "summary": summary,
        "checks": checks,
    }
