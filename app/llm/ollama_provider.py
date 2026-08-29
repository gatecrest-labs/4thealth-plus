"""Ollama provider — local or cloud, via plain HTTP (no extra SDK dependency)."""

from __future__ import annotations

import requests

from app.config import Config
from app.llm.base import LLMError, LLMProvider


class OllamaProvider(LLMProvider):
    def __init__(self) -> None:
        if not Config.OLLAMA_HOST:
            raise LLMError("OLLAMA_HOST is not set in .env")
        self._host = Config.OLLAMA_HOST.rstrip("/")
        self._model = Config.OLLAMA_MODEL

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

        headers = {}
        if Config.OLLAMA_API_KEY:
            headers["Authorization"] = f"Bearer {Config.OLLAMA_API_KEY}"
        try:
            resp = requests.post(
                f"{self._host}/api/chat",
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                },
                headers=headers,
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            text = data.get("message", {}).get("content", "")
        except Exception as exc:
            record_usage(
                provider="ollama",
                model=self._model,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                success=False,
                feature=feature,
                user=user,
                error=str(exc),
            )
            raise LLMError(f"Ollama API call failed: {exc}") from exc

        try:
            input_tokens = int(data.get("prompt_eval_count", 0) or 0)
            output_tokens = int(data.get("eval_count", 0) or 0)
        except Exception:
            input_tokens = output_tokens = 0
        record_usage(
            provider="ollama",
            model=self._model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=estimate_cost("ollama", self._model, input_tokens, output_tokens),
            success=True,
            feature=feature,
            user=user,
        )
        return text
