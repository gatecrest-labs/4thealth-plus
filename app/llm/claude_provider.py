"""Anthropic Claude provider — the default AI Assist backend."""

from __future__ import annotations

from app.config import Config
from app.llm.base import LLMError, LLMProvider


class ClaudeProvider(LLMProvider):
    def __init__(self) -> None:
        if not Config.ANTHROPIC_API_KEY:
            raise LLMError("ANTHROPIC_API_KEY is not set in .env")
        self._model = Config.ANTHROPIC_MODEL

    def narrate(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        feature: str,
        user: str | None = None,
    ) -> str:
        from app.ai_usage import record_usage
        from app.llm.pricing import estimate_cost

        try:
            import anthropic

            client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)
            response = client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            text = "".join(
                block.text
                for block in response.content
                if getattr(block, "type", "") == "text"
            )
        except ImportError as exc:
            record_usage(
                provider="claude",
                model=self._model,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                success=False,
                feature=feature,
                user=user,
                error=str(exc),
            )
            raise LLMError("the 'anthropic' package is not installed") from exc
        except Exception as exc:
            record_usage(
                provider="claude",
                model=self._model,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                success=False,
                feature=feature,
                user=user,
                error=str(exc),
            )
            raise LLMError(f"Claude API call failed: {exc}") from exc

        # Usage/cost tracking is best-effort and isolated from the call's
        # success/failure — a malformed usage object must never turn an
        # already-successful narration into a reported error.
        try:
            input_tokens = int(getattr(response.usage, "input_tokens", 0) or 0)
            output_tokens = int(getattr(response.usage, "output_tokens", 0) or 0)
        except Exception:
            input_tokens = output_tokens = 0
        record_usage(
            provider="claude",
            model=self._model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=estimate_cost("claude", self._model, input_tokens, output_tokens),
            success=True,
            feature=feature,
            user=user,
        )
        return text
