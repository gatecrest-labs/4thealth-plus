"""Provider-agnostic interface every LLM narration backend implements."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod


class LLMError(Exception):
    """Raised when a provider is misconfigured or a completion call fails."""


class LLMProvider(ABC):
    @abstractmethod
    def narrate(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        feature: str,
        user: str | None = None,
    ) -> str:
        """Return the model's text completion for one single-shot prompt.

        Raises LLMError on any failure (missing key, network error, non-2xx
        response) — callers must catch this and degrade gracefully rather
        than let it propagate to the user as a raw exception.
        """

    def extract_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        feature: str,
        user: str | None = None,
    ) -> dict:
        """Call narrate() with a JSON-only instruction and parse the result.

        Used for structured extraction (e.g. pulling PSIRT advisory fields
        out of a pasted email) — narrate() itself stays free-text-in/out for
        every other caller. Raises LLMError if narrate() fails, the response
        isn't valid JSON, or the parsed value isn't a JSON object. Never
        returns a partially-guessed dict.
        """
        strict_system_prompt = (
            system_prompt
            + "\n\nRespond with ONLY a single valid JSON object — no prose, "
            "no markdown code fences, no explanation before or after."
        )
        raw = self.narrate(
            strict_system_prompt, user_prompt, feature=feature, user=user
        )
        text = raw.strip()
        if text.startswith("```"):
            text = text[3:]
            if text.lower().startswith("json"):
                text = text[4:]
            text = text.removesuffix("```")
            text = text.strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError(f"model did not return valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise LLMError("model's JSON response was not a JSON object")
        return parsed
