"""PSIRT Advisory Assessment — new section on the Device Review tab.

API (JSON):
  GET  /api/device-review/psirt/extract-status
       returns: { available: bool }  (reads ai_assist_enabled, same flag as
       every other AI-Assist feature in this repo)

  POST /api/device-review/psirt/extract
       body: { email_text: str }  (or multipart with a "file" field — .eml/.txt)
       returns: { advisory: {...Advisory.to_dict()...} }
       or 422 { field, error } if the LLM's extraction was missing/malformed
       a required field — never a silent guess.

  POST /api/device-review/psirt/assess/device
       body: { adom, device, advisory: {...} }
       Single-device evaluation — used by the frontend's per-device
       progress loop (mirrors /api/device-review/run/device).
       returns: { finding: {...DeviceFinding.to_dict()...} }

  POST /api/device-review/psirt/assess
       body: { adom: "<name>" | "*", advisory: {...} }
       Bulk entry point (adom="*" resolves to every ADOM the requesting
       user can access via app.groups.get_allowed_adoms).
       returns: {...PsirtAssessment.to_dict()...}

  POST /api/device-review/psirt/report
       body: { assessment: {...PsirtAssessment.to_dict() shape...} }
       Renders the already-computed assessment to HTML — never recomputes.
       returns: HTML document (Content-Type: text/html)
"""

from __future__ import annotations

import email
from email import policy as email_policy

from flask import Blueprint, jsonify, request, session

from app.app_settings import get_setting
from app.config import Config
from app.decorators import check_adom_access, tab_required
from app.fmg_client import FMGError
from app.fmg_helpers import make_client
from app.llm import get_provider
from app.llm.base import LLMError
from app.psirt.engine import assess as psirt_assess
from app.psirt.extract import ExtractionError, extract_advisory
from app.psirt.models import Advisory, AffectedRange
from app.psirt.render import render_psirt_html
from app.security import internal_api_error, upstream_api_error

bp = Blueprint("psirt", __name__)

_ALLOWED_UPLOAD_EXTS = (".eml", ".txt")


def _advisory_from_payload(data: dict) -> Advisory:
    ranges = [
        AffectedRange(
            product=str(r.get("product", "")),
            min_version=str(r.get("min_version", "") or ""),
            max_version=str(r.get("max_version", "") or ""),
            fixed_version=str(r.get("fixed_version", "") or ""),
            notes=str(r.get("notes", "") or ""),
        )
        for r in data.get("affected_ranges", [])
        if isinstance(r, dict)
    ]
    return Advisory(
        advisory_id=str(data.get("advisory_id", "")),
        advisory_url=str(data.get("advisory_url", "") or ""),
        cve_ids=[str(c) for c in data.get("cve_ids", [])],
        published_date=str(data.get("published_date", "") or ""),
        fortinet_severity=str(data.get("fortinet_severity", "") or ""),
        cvss_score=data.get("cvss_score"),
        description=str(data.get("description", "") or ""),
        affected_ranges=ranges,
        workaround_text=str(data.get("workaround_text", "") or ""),
        exploited_in_wild_text=str(data.get("exploited_in_wild_text", "") or ""),
        enrichment_degraded=bool(data.get("enrichment_degraded", False)),
    )


def _http_client():
    import requests

    return requests


# ── extract-status ───────────────────────────────────────────────────────────


@bp.route("/api/device-review/psirt/extract-status")
@tab_required("device_review")
def psirt_extract_status():
    return jsonify({"available": get_setting("ai_assist_enabled", False)})


# ── extract ───────────────────────────────────────────────────────────────────


@bp.route("/api/device-review/psirt/extract", methods=["POST"])
@tab_required("device_review")
def psirt_extract():
    if not get_setting("ai_assist_enabled", False):
        return jsonify({"error": "AI Assist is not enabled"}), 503

    is_multipart = "file" in request.files
    if is_multipart:
        upload = request.files["file"]
        filename = (upload.filename or "").lower()
        if not filename.endswith(_ALLOWED_UPLOAD_EXTS):
            return jsonify({"error": "Only .eml or .txt uploads are supported"}), 400
        raw = upload.read()
        if filename.endswith(".eml"):
            msg = email.message_from_bytes(raw, policy=email_policy.default)
            body = msg.get_body(preferencelist=("plain", "html"))
            email_text = (
                body.get_content() if body else raw.decode("utf-8", errors="replace")
            )
        else:
            email_text = raw.decode("utf-8", errors="replace")
    else:
        data = request.get_json(silent=True) or {}
        email_text = (data.get("email_text") or "").strip()

    if not email_text:
        return jsonify({"error": "email_text (or an uploaded file) is required"}), 400

    try:
        provider = get_provider()
        advisory = extract_advisory(email_text, provider)
    except ExtractionError as exc:
        return jsonify({"field": exc.field, "error": exc.detail}), 422
    except LLMError as exc:
        return jsonify({"error": str(exc)}), 502

    return jsonify({"advisory": advisory.to_dict()})


# ── assess: single device (progress-loop entry point) ─────────────────────────


@bp.route("/api/device-review/psirt/assess/device", methods=["POST"])
@tab_required("device_review")
def psirt_assess_device():
    # NOTE: not currently called by the frontend (psirt.js only calls the
    # bulk /assess endpoint below and drives its own per-device UI off the
    # merged result). Runs a full ADOM-wide assess() — including both
    # enrichment HTTP fetches — then filters to one device, so it is not
    # efficient to drive in a per-device loop across many devices. Kept for
    # API completeness / direct testing; building a true per-device engine
    # entry point is a larger change out of scope for this fix wave.
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    device = (data.get("device") or "").strip()
    if not adom or not device:
        return jsonify({"error": "adom and device are required"}), 400
    if err := check_adom_access(adom):
        return err

    advisory = _advisory_from_payload(data.get("advisory") or {})

    try:
        with make_client() as client:
            result = psirt_assess(
                advisory,
                client,
                adom,
                _http_client(),
                Config.PSIRT_KEV_URL if Config.PSIRT_ENRICHMENT_ENABLED else "",
                enrichment_enabled=Config.PSIRT_ENRICHMENT_ENABLED,
                fetch_timeout=Config.PSIRT_FETCH_TIMEOUT,
            )
    except FMGError as exc:
        return upstream_api_error("psirt", exc)
    except Exception as exc:
        return internal_api_error("psirt", exc)

    matching = [f for f in result.findings if f.device == device]
    finding = matching[0] if matching else None
    return jsonify(
        {
            "finding": finding.to_dict() if finding else None,
            "priority": result.priority,
            "priority_rationale": result.priority_rationale,
            "kev_hit": result.kev_hit,
        }
    )


# ── assess: bulk (adom="*" resolves to every accessible ADOM) ─────────────────


@bp.route("/api/device-review/psirt/assess", methods=["POST"])
@tab_required("device_review")
def psirt_assess_bulk():
    data = request.get_json(silent=True) or {}
    adom = (data.get("adom") or "").strip()
    if not adom:
        return jsonify(
            {"error": 'adom is required (use "*" for all accessible ADOMs)'}
        ), 400

    if adom != "*":
        if err := check_adom_access(adom):
            return err
        adom_scope = adom
    else:
        from app.groups import get_allowed_adoms

        allowed = get_allowed_adoms(
            session.get("user", ""), ad_groups=session.get("ad_groups", [])
        )
        # allowed is None for unrestricted users — engine.assess() handles
        # "*" itself in that case by calling fmg_client.get_adoms() directly.
        # For restricted users we can't pass "*" through (engine has no
        # user concept), so pre-resolve to their allowed ADOM list and run
        # per-ADOM, merging results.
        if allowed is None:
            adom_scope = "*"
        else:
            adom_scope = None  # signal: iterate `allowed` below
            if not allowed:
                return jsonify({"error": "You have no accessible ADOMs"}), 403

    advisory = _advisory_from_payload(data.get("advisory") or {})

    try:
        with make_client() as client:
            if adom_scope is not None:
                result = psirt_assess(
                    advisory,
                    client,
                    adom_scope,
                    _http_client(),
                    Config.PSIRT_KEV_URL if Config.PSIRT_ENRICHMENT_ENABLED else "",
                    enrichment_enabled=Config.PSIRT_ENRICHMENT_ENABLED,
                    fetch_timeout=Config.PSIRT_FETCH_TIMEOUT,
                )
            else:
                from app.psirt.enrich import enrich_advisory
                from app.psirt.scoring import compute_priority

                kev_url = (
                    Config.PSIRT_KEV_URL if Config.PSIRT_ENRICHMENT_ENABLED else ""
                )
                # Enrich exactly once here (fortiguard.com page fetch + CISA
                # KEV download) rather than once per ADOM — with N allowed
                # ADOMs that would otherwise be 2*N external fetches inside a
                # single request. Each per-ADOM psirt_assess() call below is
                # passed enrichment_enabled=False; enrich_advisory() detects
                # the already-enriched advisory (via the _kev_hit dynamic
                # attribute) and passes its enrichment signal through
                # unchanged rather than re-stomping it.
                advisory = enrich_advisory(
                    advisory,
                    _http_client(),
                    kev_url,
                    enrichment_enabled=Config.PSIRT_ENRICHMENT_ENABLED,
                    timeout=Config.PSIRT_FETCH_TIMEOUT,
                )

                merged = None
                for one_adom in allowed:
                    partial = psirt_assess(
                        advisory,
                        client,
                        one_adom,
                        _http_client(),
                        kev_url,
                        enrichment_enabled=False,
                        fetch_timeout=Config.PSIRT_FETCH_TIMEOUT,
                    )
                    if merged is None:
                        merged = partial
                    else:
                        # engine.assess() appends a "FortiManager (primary)"
                        # finding whenever the advisory names FortiManager as
                        # an affected product — that happens on every
                        # per-ADOM call, so only keep it from the first
                        # iteration to avoid N duplicate rows in the merge.
                        new_findings = [
                            f
                            for f in partial.findings
                            if not (
                                f.device == "FortiManager (primary)" and f.adom == "-"
                            )
                        ]
                        merged.findings.extend(new_findings)
                        merged.warnings.extend(partial.warnings)
                        merged.degraded = merged.degraded or partial.degraded
                        merged.kev_hit = merged.kev_hit or partial.kev_hit
                # Each per-ADOM psirt_assess() call computed priority from only
                # that ADOM's findings — recompute once over the full merged
                # set so "any device in range" reflects the whole scope, not
                # just whichever ADOM happened to run first. Mirror engine.
                # assess()'s degraded-coverage guards here too, so a partial
                # ADOM failure elsewhere in the merge can't get reported as
                # "informational / nothing to act on".
                any_in_range = any(f.in_range for f in merged.findings)
                if merged.degraded and not merged.findings:
                    merged.priority = "unknown"
                    merged.priority_rationale = (
                        "Fleet assessment is degraded and no devices could be checked. "
                        "Manual verification required."
                    )
                elif merged.degraded and merged.findings and not any_in_range:
                    merged.priority = "unknown"
                    merged.priority_rationale = (
                        "Fleet assessment is degraded and no devices were confirmed to be "
                        "in the advisory's affected range(s) — partial fleet coverage means "
                        "this fleet may still be exposed. Manual verification required."
                    )
                else:
                    merged.priority, merged.priority_rationale = compute_priority(
                        cvss_score=merged.advisory.cvss_score,
                        fortinet_severity=merged.advisory.fortinet_severity,
                        exploited_in_wild_text=merged.advisory.exploited_in_wild_text,
                        kev_hit=merged.kev_hit,
                        any_device_in_range=any_in_range,
                    )
                result = merged
    except FMGError as exc:
        return upstream_api_error("psirt", exc)
    except Exception as exc:
        return internal_api_error("psirt", exc)

    return jsonify(result.to_dict())


# ── report ──────────────────────────────────────────────────────────────────


@bp.route("/api/device-review/psirt/report", methods=["POST"])
@tab_required("device_review")
def psirt_report():
    data = request.get_json(silent=True) or {}
    assessment = data.get("assessment")
    if not isinstance(assessment, dict):
        return jsonify({"error": "assessment is required"}), 400
    try:
        html = render_psirt_html(assessment)
    except Exception as exc:
        return internal_api_error("psirt", exc)
    return html, 200, {"Content-Type": "text/html"}
