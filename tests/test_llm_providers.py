"""Tests for app.llm — multi-provider LLM narration."""
from unittest.mock import MagicMock, patch

import pytest

from app.llm.base import LLMError


def test_get_provider_returns_claude_by_default(monkeypatch):
    monkeypatch.setattr("app.config.Config.AI_PROVIDER", "claude")
    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "test-key")
    from app.llm import get_provider
    from app.llm.claude_provider import ClaudeProvider
    provider = get_provider()
    assert isinstance(provider, ClaudeProvider)


def test_get_provider_unknown_raises():
    with patch("app.config.Config.AI_PROVIDER", "not-a-real-provider"):
        from app.llm import get_provider
        with pytest.raises(LLMError):
            get_provider()


def test_claude_provider_requires_api_key(monkeypatch):
    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "")
    from app.llm.claude_provider import ClaudeProvider
    with pytest.raises(LLMError):
        ClaudeProvider()


def test_claude_provider_narrate_calls_anthropic_sdk(monkeypatch):
    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("app.config.Config.ANTHROPIC_MODEL", "claude-sonnet-4-5")
    from app.llm.claude_provider import ClaudeProvider

    fake_block = MagicMock(type="text", text="Here is the report.")
    fake_response = MagicMock(content=[fake_block])
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response

    with patch("anthropic.Anthropic", return_value=fake_client):
        provider = ClaudeProvider()
        result = provider.narrate("system prompt", "user prompt", feature="rule_review_ai_assist")
    assert result == "Here is the report."
    fake_client.messages.create.assert_called_once()


def test_claude_provider_narrate_wraps_sdk_errors(monkeypatch):
    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "test-key")
    from app.llm.claude_provider import ClaudeProvider
    fake_client = MagicMock()
    fake_client.messages.create.side_effect = RuntimeError("rate limited")
    with patch("anthropic.Anthropic", return_value=fake_client):
        provider = ClaudeProvider()
        with pytest.raises(LLMError):
            provider.narrate("system", "user", feature="rule_review_ai_assist")


def test_codex_provider_requires_api_key(monkeypatch):
    monkeypatch.setattr("app.config.Config.OPENAI_API_KEY", "")
    from app.llm.codex_provider import CodexProvider
    with pytest.raises(LLMError):
        CodexProvider()


def test_codex_provider_narrate_calls_openai_sdk(monkeypatch):
    monkeypatch.setattr("app.config.Config.OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("app.config.Config.OPENAI_MODEL", "gpt-5")
    from app.llm.codex_provider import CodexProvider

    fake_message = MagicMock(content="Here is the report.")
    fake_choice = MagicMock(message=fake_message)
    fake_response = MagicMock(choices=[fake_choice])
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = fake_response

    with patch("openai.OpenAI", return_value=fake_client):
        provider = CodexProvider()
        result = provider.narrate("system prompt", "user prompt", feature="rule_review_ai_assist")
    assert result == "Here is the report."


def test_codex_provider_narrate_wraps_sdk_errors(monkeypatch):
    monkeypatch.setattr("app.config.Config.OPENAI_API_KEY", "test-key")
    from app.llm.codex_provider import CodexProvider
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = RuntimeError("rate limited")
    with patch("openai.OpenAI", return_value=fake_client):
        provider = CodexProvider()
        with pytest.raises(LLMError):
            provider.narrate("system", "user", feature="rule_review_ai_assist")


def test_ollama_provider_requires_host(monkeypatch):
    monkeypatch.setattr("app.config.Config.OLLAMA_HOST", "")
    from app.llm.ollama_provider import OllamaProvider
    with pytest.raises(LLMError):
        OllamaProvider()


def test_ollama_provider_narrate_calls_http_api(monkeypatch):
    monkeypatch.setattr("app.config.Config.OLLAMA_HOST", "http://localhost:11434")
    monkeypatch.setattr("app.config.Config.OLLAMA_MODEL", "llama3.1")
    monkeypatch.setattr("app.config.Config.OLLAMA_API_KEY", "")
    from app.llm.ollama_provider import OllamaProvider

    fake_response = MagicMock()
    fake_response.json.return_value = {"message": {"content": "Here is the report."}}
    fake_response.raise_for_status.return_value = None

    with patch("requests.post", return_value=fake_response) as mock_post:
        provider = OllamaProvider()
        result = provider.narrate("system prompt", "user prompt", feature="rule_review_ai_assist")
    assert result == "Here is the report."
    call_kwargs = mock_post.call_args
    assert call_kwargs.args[0] == "http://localhost:11434/api/chat"


def test_ollama_provider_narrate_wraps_http_errors(monkeypatch):
    monkeypatch.setattr("app.config.Config.OLLAMA_HOST", "http://localhost:11434")
    from app.llm.ollama_provider import OllamaProvider
    with patch("requests.post", side_effect=ConnectionError("refused")):
        provider = OllamaProvider()
        with pytest.raises(LLMError):
            provider.narrate("system", "user", feature="rule_review_ai_assist")


# ---------------------------------------------------------------------------
# Usage/cost recording (app.ai_usage) — isolated from success/failure
# ---------------------------------------------------------------------------

def test_claude_provider_narrate_records_usage_on_success(monkeypatch):
    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("app.config.Config.ANTHROPIC_MODEL", "claude-sonnet-4-5")
    from app.llm.claude_provider import ClaudeProvider

    fake_block = MagicMock(type="text", text="Report text.")
    fake_usage = MagicMock(input_tokens=1234, output_tokens=567)
    fake_response = MagicMock(content=[fake_block], usage=fake_usage)
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response

    with patch("anthropic.Anthropic", return_value=fake_client), \
         patch("app.ai_usage.record_usage") as mock_record:
        provider = ClaudeProvider()
        provider.narrate("system", "user", feature="rule_review_ai_assist")

    mock_record.assert_called_once()
    kwargs = mock_record.call_args.kwargs
    assert kwargs["provider"] == "claude"
    assert kwargs["model"] == "claude-sonnet-4-5"
    assert kwargs["input_tokens"] == 1234
    assert kwargs["output_tokens"] == 567
    assert kwargs["success"] is True
    assert kwargs["cost_usd"] > 0


def test_claude_provider_narrate_records_usage_on_failure(monkeypatch):
    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "test-key")
    from app.llm.claude_provider import ClaudeProvider
    fake_client = MagicMock()
    fake_client.messages.create.side_effect = RuntimeError("rate limited")
    with patch("anthropic.Anthropic", return_value=fake_client), \
         patch("app.ai_usage.record_usage") as mock_record:
        provider = ClaudeProvider()
        with pytest.raises(LLMError):
            provider.narrate("system", "user", feature="rule_review_ai_assist")

    mock_record.assert_called_once()
    kwargs = mock_record.call_args.kwargs
    assert kwargs["success"] is False
    assert "rate limited" in kwargs["error"]


def test_claude_provider_narrate_survives_malformed_usage_object(monkeypatch):
    """A bad/missing .usage on the SDK response must not turn a
    successful narration into a raised error."""
    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "test-key")
    from app.llm.claude_provider import ClaudeProvider

    fake_block = MagicMock(type="text", text="Report text.")
    fake_response = MagicMock(content=[fake_block])
    del fake_response.usage  # accessing .usage now raises AttributeError
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response

    with patch("anthropic.Anthropic", return_value=fake_client):
        provider = ClaudeProvider()
        result = provider.narrate("system", "user", feature="rule_review_ai_assist")
    assert result == "Report text."


def test_codex_provider_narrate_records_usage_on_success(monkeypatch):
    monkeypatch.setattr("app.config.Config.OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("app.config.Config.OPENAI_MODEL", "gpt-5")
    from app.llm.codex_provider import CodexProvider

    fake_message = MagicMock(content="Report text.")
    fake_choice = MagicMock(message=fake_message)
    fake_usage = MagicMock(prompt_tokens=200, completion_tokens=100)
    fake_response = MagicMock(choices=[fake_choice], usage=fake_usage)
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = fake_response

    with patch("openai.OpenAI", return_value=fake_client), \
         patch("app.ai_usage.record_usage") as mock_record:
        provider = CodexProvider()
        provider.narrate("system", "user", feature="rule_review_ai_assist")

    kwargs = mock_record.call_args.kwargs
    assert kwargs["provider"] == "codex"
    assert kwargs["feature"] == "rule_review_ai_assist"
    assert kwargs["input_tokens"] == 200
    assert kwargs["output_tokens"] == 100
    assert kwargs["success"] is True


def test_ollama_provider_narrate_records_usage_on_success(monkeypatch):
    monkeypatch.setattr("app.config.Config.OLLAMA_HOST", "http://localhost:11434")
    monkeypatch.setattr("app.config.Config.OLLAMA_MODEL", "llama3.1")
    from app.llm.ollama_provider import OllamaProvider

    fake_response = MagicMock()
    fake_response.json.return_value = {
        "message": {"content": "Report text."},
        "prompt_eval_count": 300, "eval_count": 150,
    }
    fake_response.raise_for_status.return_value = None

    with patch("requests.post", return_value=fake_response), \
         patch("app.ai_usage.record_usage") as mock_record:
        provider = OllamaProvider()
        provider.narrate("system", "user", feature="rule_review_ai_assist")

    kwargs = mock_record.call_args.kwargs
    assert kwargs["provider"] == "ollama"
    assert kwargs["feature"] == "rule_review_ai_assist"
    assert kwargs["input_tokens"] == 300
    assert kwargs["output_tokens"] == 150
    assert kwargs["cost_usd"] == 0.0
    assert kwargs["success"] is True
