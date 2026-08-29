"""AI narrative summaries for Config-Delta (FortiManager install-preview) diffs.

The LLM never alters or re-derives a diff line — app.fmg_client.parse_preview_diff()
already parsed the raw CLI text. This module only turns the already-structured
diff into a short prose description, via the same provider-agnostic app.llm
interface used elsewhere in the app. The raw CLI diff is always shown/exported
alongside the summary, never replaced by it.
"""

from __future__ import annotations

import json

_MAX_LINES_PER_DEVICE = 30
_MAX_DEVICES_DETAILED = 20


def _trim_device(dev: dict) -> dict:
    """Return a copy of one device's parsed diff, capped to _MAX_LINES_PER_DEVICE
    total change lines across all its VDOMs."""
    remaining = _MAX_LINES_PER_DEVICE
    vdoms_out = []
    for vdom in dev.get("vdoms", []):
        if remaining <= 0:
            break
        changes = vdom.get("changes", [])[:remaining]
        remaining -= len(changes)
        vdoms_out.append({"name": vdom.get("name", "root"), "changes": changes})
    return {
        "device": dev.get("device", ""),
        "summary": dev.get("summary", {}),
        "vdoms": vdoms_out,
    }


def build_diff_narrative(
    adom: str, devices: list[dict], user: str | None = None
) -> str:
    """Return an AI-written narrative summary of one or more device diffs.

    Raises whatever the configured provider's narrate() raises — callers
    must catch this and continue without a narrative.
    """
    from app.llm import get_provider

    with_changes = [
        d for d in devices if any(v.get("changes") for v in d.get("vdoms", []))
    ]
    detailed = [_trim_device(d) for d in with_changes[:_MAX_DEVICES_DETAILED]]
    omitted_count = max(0, len(with_changes) - _MAX_DEVICES_DETAILED)

    payload = {
        "adom": adom,
        "devices_total": len(devices),
        "devices_with_changes": len(with_changes),
        "devices": detailed,
        "additional_devices_with_changes_not_detailed": omitted_count,
    }

    provider = get_provider()
    return provider.narrate(
        system_prompt=(
            "You are a firewall change analyst assistant. You are given "
            "already-parsed FortiManager install-preview CLI diffs (config "
            "adds/removes/modifies awaiting push to devices) as JSON. Write "
            "a short summary (2-6 sentences, or one short bullet per device "
            "if there are several) describing what is actually changing — "
            "e.g. new/removed policies, address or service object changes, "
            "routing changes — in plain English for an engineer reviewing "
            "pending changes before they are pushed. Never invent a change "
            "or omit that changes exist — only describe what is present in "
            "the JSON."
        ),
        user_prompt=json.dumps(payload, default=str),
        feature="pending_changes_diff_summary",
        user=user,
    )
