"""AI narrative summaries for Device Review (CIS) results.

The LLM here never computes a finding — app.device_review.run_checks() and
the scheduler's check-summary aggregation already have. This module only
turns already-computed, aggregated results into a short prose summary, via
the same provider-agnostic app.llm interface used by Rule Validation's AI
Assist.
"""

from __future__ import annotations

import json

_MAX_ROWS_SENT = 40  # cap the failing/insecure rows sent to the LLM


def _fail_rows(results: list[dict]) -> list[dict]:
    """Return up to _MAX_ROWS_SENT FAIL/INSECURE rows across all devices."""
    out: list[dict] = []
    for dev in results:
        for row in dev.get("rows", []):
            if row.get("result") in ("FAIL", "INSECURE"):
                out.append(
                    {
                        "device": row.get("device", ""),
                        "check": row.get("check", ""),
                        "result": row.get("result", ""),
                        "interface": row.get("interface", ""),
                        "detail": row.get("detail", ""),
                    }
                )
                if len(out) >= _MAX_ROWS_SENT:
                    return out
    return out


def build_narrative(
    adom: str,
    check_summary: list[dict],
    results: list[dict],
    user: str | None = None,
) -> str:
    """Return an AI-written narrative summary for one Device Review run.

    Raises whatever the configured provider's narrate() raises — callers
    must catch this and degrade to the deterministic report without a
    narrative, same pattern as Rule Validation's AI Assist.
    """
    from app.llm import get_provider

    errors = [d.get("device", "?") for d in results if d.get("error")]
    payload = {
        "adom": adom,
        "devices_scanned": len(results),
        "devices_with_errors": errors,
        "check_summary": check_summary,
        "failing_and_insecure_findings": _fail_rows(results),
    }

    provider = get_provider()
    return provider.narrate(
        system_prompt=(
            "You are a firewall security analyst assistant. You are given "
            "already-computed CIS hardening / interface-protocol check "
            "results as JSON for one FortiManager ADOM. Write a short "
            "executive summary (3-6 sentences) for a NOC/SOC reader: what "
            "is the overall posture, which devices or checks need "
            "attention first, and why. Never invent a finding or change "
            "any count or value — only explain what is already there."
        ),
        user_prompt=json.dumps(payload, default=str),
        feature="device_review_summary",
        user=user,
    )
