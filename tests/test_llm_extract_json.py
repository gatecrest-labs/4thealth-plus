"""Tests for LLMProvider.extract_json() — structured JSON extraction on top of narrate()."""
import pytest
from app.llm.base import LLMError, LLMProvider


class _FakeProvider(LLMProvider):
    def __init__(self, response: str):
        self._response = response

    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        return self._response


def test_extract_json_parses_plain_json():
    provider = _FakeProvider('{"advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"]}')
    result = provider.extract_json("system", "user")
    assert result == {"advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"]}


def test_extract_json_strips_markdown_fences():
    provider = _FakeProvider('```json\n{"advisory_id": "FG-IR-24-001"}\n```')
    result = provider.extract_json("system", "user")
    assert result == {"advisory_id": "FG-IR-24-001"}


def test_extract_json_strips_bare_fences_no_language_tag():
    provider = _FakeProvider('```\n{"advisory_id": "FG-IR-24-001"}\n```')
    result = provider.extract_json("system", "user")
    assert result == {"advisory_id": "FG-IR-24-001"}


def test_extract_json_malformed_raises_llm_error():
    provider = _FakeProvider("this is not json at all")
    with pytest.raises(LLMError):
        provider.extract_json("system", "user")


def test_extract_json_non_object_json_raises():
    provider = _FakeProvider('["just", "a", "list"]')
    with pytest.raises(LLMError):
        provider.extract_json("system", "user")


def test_extract_json_narrate_failure_propagates():
    class _FailingProvider(LLMProvider):
        def narrate(self, system_prompt: str, user_prompt: str) -> str:
            raise LLMError("API call failed")

    with pytest.raises(LLMError):
        _FailingProvider().extract_json("system", "user")


def test_extract_json_appends_json_only_instruction_to_system_prompt():
    """The system prompt narrate() receives must instruct JSON-only output."""
    captured = {}

    class _CapturingProvider(LLMProvider):
        def narrate(self, system_prompt: str, user_prompt: str) -> str:
            captured["system_prompt"] = system_prompt
            return "{}"

    _CapturingProvider().extract_json("Extract PSIRT fields.", "email text")
    assert "Extract PSIRT fields." in captured["system_prompt"]
    assert "json" in captured["system_prompt"].lower()
