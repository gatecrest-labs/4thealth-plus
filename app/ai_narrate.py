"""Shared helper for LLM-narrated features.

The LLM only explains an already-computed, bounded JSON payload. Routes use
``safe_narrate`` so a provider failure never becomes a 500.
"""

from __future__ import annotations

import json


def ai_enabled() -> bool:
    from app.app_settings import get_setting

    return bool(get_setting("ai_assist_enabled", False))


def narrate_payload(
    system_prompt: str,
    payload: dict,
    *,
    feature: str,
    user: str | None = None,
    max_chars: int = 64_000,
) -> str:
    from app.llm import get_provider
    from app.llm.base import LLMError

    payload_json = json.dumps(payload, default=str)
    if len(payload_json) > max_chars:
        raise ValueError(
            f"Payload too large to narrate (exceeds {max_chars:,} characters)"
        )
    text = get_provider().narrate(
        system_prompt=system_prompt,
        user_prompt=payload_json,
        feature=feature,
        user=user,
    )
    if not text or not str(text).strip():
        raise LLMError("The AI provider returned an empty response")
    return str(text).strip()


def safe_narrate(
    system_prompt: str,
    payload: dict,
    *,
    feature: str,
    user: str | None = None,
) -> tuple[str | None, str | None]:
    try:
        return narrate_payload(system_prompt, payload, feature=feature, user=user), None
    except Exception as exc:  # noqa: BLE001 - never let narration raise
        return None, str(exc)
