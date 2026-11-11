import pytest

import app.llm as llm
from app.llm.base import LLMError
from app import ai_narrate


class _Stub:
    def __init__(self, result="ok", exc=None):
        self.result, self.exc, self.calls = result, exc, []

    def narrate(self, **kw):
        self.calls.append(kw)
        if self.exc:
            raise self.exc
        return self.result


def test_oversize_payload_raises_value_error(monkeypatch):
    monkeypatch.setattr(llm, "get_provider", lambda: _Stub())
    with pytest.raises(ValueError):
        ai_narrate.narrate_payload("sys", {"x": "a" * 70_000}, feature="f")


def test_blank_completion_becomes_llm_error(monkeypatch):
    monkeypatch.setattr(llm, "get_provider", lambda: _Stub("   "))
    with pytest.raises(LLMError):
        ai_narrate.narrate_payload("sys", {"a": 1}, feature="f")


def test_safe_narrate_returns_error_tuple_on_provider_failure(monkeypatch):
    monkeypatch.setattr(llm, "get_provider", lambda: _Stub(exc=LLMError("boom")))
    assert ai_narrate.safe_narrate("sys", {"a": 1}, feature="f") == (None, "boom")


def test_safe_narrate_passes_feature_and_user(monkeypatch):
    stub = _Stub("  hello ")
    monkeypatch.setattr(llm, "get_provider", lambda: stub)
    assert ai_narrate.safe_narrate("sys", {"a": 1}, feature="feat", user="bob") == ("hello", None)
    assert stub.calls[0]["feature"] == "feat"
    assert stub.calls[0]["user"] == "bob"
    assert stub.calls[0]["system_prompt"] == "sys"


def test_ai_enabled_reads_setting(monkeypatch):
    import app.app_settings as s
    monkeypatch.setattr(s, "get_setting", lambda k, d=None: True)
    assert ai_narrate.ai_enabled() is True
