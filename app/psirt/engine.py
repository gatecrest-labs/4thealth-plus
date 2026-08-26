"""
The PSIRT assessment engine: given a structured Advisory, determines the
verdict for every FortiGate + the FortiManager itself. This is the
deterministic core other packages call — it never asks an LLM anything.

adom_scope is either one ADOM name or the literal "*" for every ADOM
fmg_client.get_adoms() returns. Access-control filtering of which ADOMs a
"*" scan may touch is the caller's responsibility (app/routes/psirt_routes.py)
— this module has no session/user concept.

Fleet scan strategy: for each ADOM in scope, list every device, evaluate
FortiOS findings for each device plus one FortiManager-itself finding (if
the advisory names FortiManager as a product). A per-ADOM device-list
failure degrades the assessment (those devices become
unknown_needs_manual_check via the degraded flag) rather than being
silently skipped.
"""

from __future__ import annotations

import re
from typing import Any

from app.psirt.enrich import enrich_advisory
from app.psirt.models import Advisory, DeviceFinding, PsirtAssessment
from app.psirt.scoring import compute_priority
from app.psirt.version_match import VersionMatchError, version_in_range
from app.psirt.workaround_checks import check_workaround, match_workaround_pattern

_SUPPORTED_PRODUCTS = {"fortios", "fortigate", "fortimanager"}
_VERSION_EXTRACT = re.compile(r"\d+\.\d+\.\d+")


def _fmg_version(raw: str) -> str:
    """Extract a clean X.Y.Z version from a FortiManager get_system_status() Version string.

    FortiManager returns strings like "v7.4.5,build2360,240702 (GA)". Strip
    the leading 'v', take the first X.Y.Z component found. "" if not found.
    """
    m = _VERSION_EXTRACT.search(raw)
    return m.group(0) if m else ""


def _device_firmware(device: dict) -> str:
    # FortiManager stores versions across three fields:
    #   os_ver  — major version, sometimes "7.0" where ".0" is a legacy
    #             branch suffix, NOT the minor release. Take the leading int.
    #   mr      — the actual minor/feature release (e.g. 4 for FortiOS 7.4.x)
    #   patch   — patch level; -1 means no specific patch is tracked (unknown)
    os_ver_raw = str(device.get("os_ver", "")).strip()
    major_str = os_ver_raw.split(".")[0] if os_ver_raw else ""
    mr_str = str(device.get("mr", "")).strip()
    patch_str = str(device.get("patch", "")).strip()
    if not major_str or not mr_str or not patch_str:
        return ""
    try:
        major, mr, patch = int(major_str), int(mr_str), int(patch_str)
    except ValueError:
        return ""
    if patch < 0:
        return ""
    return f"{major}.{mr}.{patch}"


def _evaluate_device(
    advisory: Advisory,
    ranges: list,
    device_name: str,
    adom: str,
    product_label: str,
    firmware: str,
    fmg_client: Any,
) -> DeviceFinding:
    if not firmware:
        return DeviceFinding(
            device=device_name,
            adom=adom,
            product=product_label,
            current_version="",
            in_range=False,
            workaround_status="not_applicable",
            verdict="unknown_needs_manual_check",
            reason="No firmware version reported by FortiManager for this device.",
        )

    in_range = False
    matched_range = None
    try:
        for rng in ranges:
            if version_in_range(firmware, rng):
                in_range = True
                matched_range = rng
                break
    except VersionMatchError as exc:
        return DeviceFinding(
            device=device_name,
            adom=adom,
            product=product_label,
            current_version=firmware,
            in_range=False,
            workaround_status="not_applicable",
            verdict="unknown_needs_manual_check",
            reason=f"Could not compare firmware version: {exc}",
        )

    if not in_range:
        return DeviceFinding(
            device=device_name,
            adom=adom,
            product=product_label,
            current_version=firmware,
            in_range=False,
            workaround_status="not_applicable",
            verdict="no_action",
            reason=f"Firmware {firmware} is outside the advisory's affected range(s).",
        )

    pattern_key = match_workaround_pattern(advisory.workaround_text)
    if pattern_key is None:
        if advisory.workaround_text.strip():
            return DeviceFinding(
                device=device_name,
                adom=adom,
                product=product_label,
                current_version=firmware,
                in_range=True,
                workaround_status="manual_verification_required",
                verdict="config_change_required",
                reason=(
                    f"Firmware {firmware} is affected. A workaround is published "
                    f"but not automatically verifiable: {advisory.workaround_text!r}. "
                    "Manually confirm it's applied, or upgrade to "
                    f"{matched_range.fixed_version or 'the fixed version'}."
                ),
            )
        return DeviceFinding(
            device=device_name,
            adom=adom,
            product=product_label,
            current_version=firmware,
            in_range=True,
            workaround_status="not_applicable",
            verdict="upgrade_required",
            reason=(
                f"Firmware {firmware} is affected and no workaround is published. "
                f"Upgrade to {matched_range.fixed_version or 'the fixed version'}."
            ),
        )

    try:
        status = check_workaround(pattern_key, fmg_client, adom, device_name)
    except Exception as exc:
        return DeviceFinding(
            device=device_name,
            adom=adom,
            product=product_label,
            current_version=firmware,
            in_range=True,
            workaround_status="manual_verification_required",
            verdict="config_change_required",
            reason=f"Firmware {firmware} is affected. Workaround check failed: {exc}. Manual verification required.",
        )
    if status == "in_place":
        return DeviceFinding(
            device=device_name,
            adom=adom,
            product=product_label,
            current_version=firmware,
            in_range=True,
            workaround_status="in_place",
            verdict="no_action",
            reason=(
                f"Firmware {firmware} is affected, but the workaround is already "
                f"in place: {advisory.workaround_text}"
            ),
        )
    elif status == "not_in_place":
        return DeviceFinding(
            device=device_name,
            adom=adom,
            product=product_label,
            current_version=firmware,
            in_range=True,
            workaround_status="not_in_place",
            verdict="config_change_required",
            reason=(
                f"Firmware {firmware} is affected and the workaround is NOT in place: "
                f"{advisory.workaround_text}"
            ),
        )
    else:
        return DeviceFinding(
            device=device_name,
            adom=adom,
            product=product_label,
            current_version=firmware,
            in_range=True,
            workaround_status="manual_verification_required",
            verdict="config_change_required",
            reason=(
                f"Firmware {firmware} is affected and the workaround status is unknown "
                f"(manual verification required): {advisory.workaround_text}"
            ),
        )


def assess(
    advisory: Advisory,
    fmg_client: Any,
    adom_scope: str,
    http_client: Any,
    kev_url: str,
    enrichment_enabled: bool = True,
    fetch_timeout: float = 5.0,
) -> PsirtAssessment:
    """Main entry point.

    adom_scope: a single ADOM name, or "*" to scan every ADOM
    fmg_client.get_adoms() returns (caller is responsible for pre-filtering
    which ADOMs "*" may include for the requesting user).
    fetch_timeout: seconds, forwarded to enrich_advisory()'s HTTP calls
    (Config.PSIRT_FETCH_TIMEOUT at the route layer).
    """
    advisory = enrich_advisory(
        advisory,
        http_client,
        kev_url,
        enrichment_enabled=enrichment_enabled,
        timeout=fetch_timeout,
    )
    kev_hit = getattr(advisory, "_kev_hit", False)

    out_of_scope = sorted(
        {
            r.product
            for r in advisory.affected_ranges
            if r.product.strip().lower() not in _SUPPORTED_PRODUCTS
        }
    )

    findings: list[DeviceFinding] = []
    warnings: list[str] = []
    degraded = advisory.enrichment_degraded
    if getattr(advisory, "_kev_fetch_failed", False):
        warnings.append(
            "CISA KEV catalog unreachable — exploitation status not corroborated."
        )

    fortios_ranges = [
        r
        for r in advisory.affected_ranges
        if r.product.strip().lower() in ("fortios", "fortigate")
    ]
    fmg_ranges = [
        r
        for r in advisory.affected_ranges
        if r.product.strip().lower() == "fortimanager"
    ]

    if fmg_ranges:
        try:
            status = fmg_client.get_system_status()
            fmg_version = _fmg_version(str(status.get("Version", "")))
            findings.append(
                _evaluate_device(
                    advisory,
                    fmg_ranges,
                    "FortiManager (primary)",
                    "-",
                    "FortiManager",
                    fmg_version,
                    fmg_client,
                )
            )
        except Exception as exc:
            degraded = True
            warnings.append(f"Could not reach FortiManager (primary): {exc}")

    if fortios_ranges:
        if adom_scope == "*":
            try:
                # Filter out FortiManager system ADOMs (FortiManager_Managed_
                # Devices, etc.) — same forti-prefix convention as every other
                # ADOM-returning endpoint in this repo (see CLAUDE.md).
                adoms = [
                    a.get("name", "")
                    for a in fmg_client.get_adoms()
                    if isinstance(a, dict)
                    and not str(a.get("name", "")).lower().startswith("forti")
                ]
            except Exception as exc:
                degraded = True
                warnings.append(f"Could not list ADOMs: {exc}")
                adoms = []
        else:
            adoms = [adom_scope]

        for adom in adoms:
            try:
                devices = fmg_client.get_devices(adom)
            except Exception as exc:
                degraded = True
                warnings.append(f"Could not list devices in ADOM {adom!r}: {exc}")
                continue
            for d in devices:
                if not isinstance(d, dict):
                    continue
                name = d.get("name", "")
                firmware = _device_firmware(d)
                findings.append(
                    _evaluate_device(
                        advisory,
                        fortios_ranges,
                        name,
                        adom,
                        "FortiOS",
                        firmware,
                        fmg_client,
                    )
                )

    any_in_range = any(f.in_range for f in findings)

    if degraded and not findings:
        return PsirtAssessment(
            advisory=advisory,
            findings=findings,
            out_of_scope_products=out_of_scope,
            priority="unknown",
            priority_rationale=(
                "Fleet assessment is degraded and no devices could be checked. "
                "Manual verification required."
            ),
            kev_hit=kev_hit,
            degraded=degraded,
            warnings=warnings,
        )

    if degraded and findings and not any_in_range:
        # Some devices WERE checked (findings is non-empty), but a
        # different ADOM's device list failed (degraded=True) and none of
        # the devices that WERE checked fell in the affected range. Do not
        # let compute_priority() call this "informational / nothing to act
        # on" — the fleet coverage is incomplete, so the true answer is
        # unknown, not "safe."
        return PsirtAssessment(
            advisory=advisory,
            findings=findings,
            out_of_scope_products=out_of_scope,
            priority="unknown",
            priority_rationale=(
                "Fleet assessment is degraded and no devices were confirmed to be "
                "in the advisory's affected range(s) — partial fleet coverage means "
                "this fleet may still be exposed. Manual verification required."
            ),
            kev_hit=kev_hit,
            degraded=degraded,
            warnings=warnings,
        )

    priority, rationale = compute_priority(
        cvss_score=advisory.cvss_score,
        fortinet_severity=advisory.fortinet_severity,
        exploited_in_wild_text=advisory.exploited_in_wild_text,
        kev_hit=kev_hit,
        any_device_in_range=any_in_range,
    )

    return PsirtAssessment(
        advisory=advisory,
        findings=findings,
        out_of_scope_products=out_of_scope,
        priority=priority,
        priority_rationale=rationale,
        kev_hit=kev_hit,
        degraded=degraded,
        warnings=warnings,
    )
