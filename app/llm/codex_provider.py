"""OpenAI (Codex/GPT) provider."""

from __future__ import annotations

from app.config import Config
from app.llm.base import LLMError, LLMProvider


class CodexProvider(LLMProvider):
    def __init__(self) -> None:
        if not Config.OPENAI_API_KEY:
            raise LLMError("OPENAI_API_KEY is not set in .env")
        self._model = Config.OPENAI_MODEL

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
            import openai

            client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
            response = client.chat.completions.create(
                model=self._model,
                max_completion_tokens=2048,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            text = response.choices[0].message.content or ""
        except ImportError as exc:
            record_usage(
                provider="codex",
                model=self._model,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                success=False,
                feature=feature,
                user=user,
                error=str(exc),
            )
            raise LLMError("the 'openai' package is not installed") from exc
        except Exception as exc:
            record_usage(
                provider="codex",
                model=self._model,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                success=False,
                feature=feature,
                user=user,
                error=str(exc),
            )
            raise LLMError(f"OpenAI API call failed: {exc}") from exc

        try:
            input_tokens = int(getattr(response.usage, "prompt_tokens", 0) or 0)
            output_tokens = int(getattr(response.usage, "completion_tokens", 0) or 0)
        except Exception:
            input_tokens = output_tokens = 0
        record_usage(
            provider="codex",
            model=self._model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=estimate_cost("codex", self._model, input_tokens, output_tokens),
            success=True,
            feature=feature,
            user=user,
        )
        return text
