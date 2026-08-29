"""AI explanations for individual Rule Hygiene findings.

Per-finding and on-demand only (one "Explain" click = one LLM call) — this
is deliberately not a bulk operation. The LLM never re-runs or overrides a
check from app.hygiene — it only explains an already-computed finding and
suggests (never applies) a FortiOS CLI remediation snippet, mirroring the
"explain, never compute" boundary used throughout app/llm/.
"""

from __future__ import annotations

import json


def explain_finding(finding: dict, user: str | None = None) -> str:
    """Return an AI-written explanation + suggested remediation for one
    Rule Hygiene finding.

    Raises whatever the configured provider's narrate() raises — callers
    must catch this and show an inline error instead of an explanation.
    """
    from app.llm import get_provider

    payload = {
        "check": finding.get("check", ""),
        "policy_name": finding.get("policy_name", ""),
        "policy_id": finding.get("policy_id", ""),
        "detail": finding.get("detail", ""),
    }
    if "shadow_rule" in finding and "shadowing_rule" in finding:
        payload["shadow_rule"] = finding["shadow_rule"]
        payload["shadowing_rule"] = finding["shadowing_rule"]
    elif "rule_detail" in finding:
        payload["rule_detail"] = finding["rule_detail"]

    payload_json = json.dumps(payload, default=str)
    if len(payload_json) > 64_000:
        raise ValueError(
            "Finding payload too large to explain (exceeds 64,000 characters)"
        )

    provider = get_provider()
    return provider.narrate(
        system_prompt=(
            "You are a firewall rule hygiene assistant. You are given one "
            "already-computed hygiene finding (from a fixed set of checks: "
            "unnamed, unlogged, shadow, disabled, expired, unhit) as JSON, "
            "along with the affected rule's fields. Explain in 2-4 "
            "sentences why this finding matters from a security/operations "
            "standpoint for the specific rule shown, then suggest a FortiOS "
            "CLI snippet that would remediate it. Never invent rule fields "
            "not present in the JSON, and never claim the change has been "
            "applied — the snippet is a suggestion for a human reviewer."
        ),
        user_prompt=payload_json,
        feature="hygiene_explain_finding",
        user=user,
    )
