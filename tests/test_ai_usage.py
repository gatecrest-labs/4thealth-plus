"""Tests for app.ai_usage — SQLite-backed AI Assist usage/cost tracking."""
from __future__ import annotations

import datetime as dt

import pytest

from app import ai_usage


@pytest.fixture
def usage_db(tmp_path, monkeypatch):
    db_path = tmp_path / "ai_usage_test.db"
    monkeypatch.setattr(ai_usage, "_DB_PATH", db_path)
    ai_usage._init_db()
    return db_path


def _dt(hours_ago: float) -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours_ago)


def test_record_usage_persists_a_row(usage_db):
    ai_usage.record_usage(
        provider="claude", model="claude-sonnet-4-5",
        input_tokens=1000, output_tokens=500, cost_usd=0.0123, success=True,
        feature="rule_review_ai_assist",
    )
    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert len(rows) == 1
    assert rows[0]["provider"] == "claude"
    assert rows[0]["model"] == "claude-sonnet-4-5"
    assert rows[0]["input_tokens"] == 1000
    assert rows[0]["output_tokens"] == 500
    assert rows[0]["cost_usd"] == pytest.approx(0.0123)
    assert rows[0]["success"] is True
    assert rows[0]["error"] is None


def test_record_usage_captures_failure(usage_db):
    ai_usage.record_usage(
        provider="codex", model="gpt-5",
        input_tokens=0, output_tokens=0, cost_usd=0.0, success=False,
        feature="rule_review_ai_assist", error="rate limited",
    )
    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert len(rows) == 1
    assert rows[0]["success"] is False
    assert rows[0]["error"] == "rate limited"


def test_query_usage_filters_by_time_range(usage_db, monkeypatch):
    # Insert one row "now" and one row we backdate outside the query window.
    ai_usage.record_usage(
        provider="claude", model="m", input_tokens=1, output_tokens=1,
        cost_usd=0.001, success=True, feature="x",
    )
    old_ts = (_dt(48)).isoformat()
    import sqlite3
    conn = sqlite3.connect(usage_db)
    conn.execute(
        "INSERT INTO ai_usage (timestamp, provider, model, input_tokens, "
        "output_tokens, cost_usd, success, error) VALUES (?, 'claude', 'm', 1, 1, 0.001, 1, NULL)",
        (old_ts,),
    )
    conn.commit()
    conn.close()

    recent = ai_usage.query_usage(_dt(1), _dt(-1))
    assert len(recent) == 1

    everything = ai_usage.query_usage(_dt(72), _dt(-1))
    assert len(everything) == 2


def test_usage_summary_buckets_and_totals(usage_db):
    ai_usage.record_usage(
        provider="claude", model="m", input_tokens=100, output_tokens=50,
        cost_usd=0.01, success=True, feature="x",
    )
    ai_usage.record_usage(
        provider="claude", model="m", input_tokens=200, output_tokens=100,
        cost_usd=0.02, success=True, feature="x",
    )
    ai_usage.record_usage(
        provider="ollama", model="llama3.1", input_tokens=50, output_tokens=25,
        cost_usd=0.0, success=False, feature="y", error="connection refused",
    )

    summary = ai_usage.usage_summary(_dt(1), _dt(-1), num_buckets=4)
    assert len(summary["buckets"]) == 4
    assert sum(b["count"] for b in summary["buckets"]) == 3
    assert summary["total_calls"] == 3
    assert summary["total_cost_usd"] == pytest.approx(0.03)
    assert summary["total_failures"] == 1
    assert summary["total_input_tokens"] == 350
    assert summary["total_output_tokens"] == 175


def test_usage_summary_empty_range_returns_zeroed_buckets(usage_db):
    summary = ai_usage.usage_summary(_dt(1), _dt(-1), num_buckets=6)
    assert len(summary["buckets"]) == 6
    assert all(b["count"] == 0 for b in summary["buckets"])
    assert summary["total_calls"] == 0
    assert summary["total_cost_usd"] == 0.0


def test_init_db_adds_feature_and_user_columns_to_existing_table(tmp_path, monkeypatch):
    import sqlite3

    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE ai_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
        "provider TEXT NOT NULL, model TEXT NOT NULL, input_tokens INTEGER NOT NULL, "
        "output_tokens INTEGER NOT NULL, cost_usd REAL NOT NULL, success INTEGER NOT NULL, error TEXT)"
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(ai_usage, "_DB_PATH", db_path)
    ai_usage._init_db()
    # Idempotent: a second init on an already-migrated DB must not raise.
    ai_usage._init_db()

    conn = sqlite3.connect(db_path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(ai_usage)")}
    conn.close()
    assert "feature" in columns
    assert "user" in columns


def test_record_usage_stores_feature_and_user(usage_db):
    ai_usage.record_usage(
        provider="claude", model="claude-sonnet-4-5", input_tokens=100, output_tokens=50,
        cost_usd=0.01, success=True, feature="device_review_summary", user="alice",
    )
    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert rows[0]["feature"] == "device_review_summary"
    assert rows[0]["user"] == "alice"


def test_record_usage_user_defaults_to_none(usage_db):
    ai_usage.record_usage(
        provider="claude", model="claude-sonnet-4-5", input_tokens=100, output_tokens=50,
        cost_usd=0.01, success=True, feature="device_review_summary",
    )
    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert rows[0]["user"] is None


def test_claude_provider_narrate_records_feature_and_user(usage_db, monkeypatch):
    """narrate() takes a required feature label and attributes the row to it."""
    from unittest.mock import MagicMock, patch

    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("app.config.Config.ANTHROPIC_MODEL", "claude-sonnet-4-5")
    from app.llm.claude_provider import ClaudeProvider

    fake_block = MagicMock(type="text", text="narrated")
    fake_response = MagicMock(content=[fake_block])
    fake_response.usage.input_tokens = 10
    fake_response.usage.output_tokens = 5
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response

    with patch("anthropic.Anthropic", return_value=fake_client):
        provider = ClaudeProvider()
        provider.narrate("system", "user", feature="device_review_summary", user="alice")

    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert rows[-1]["feature"] == "device_review_summary"
    assert rows[-1]["user"] == "alice"


def test_claude_provider_narrate_records_feature_on_failure(usage_db, monkeypatch):
    from unittest.mock import MagicMock, patch

    from app.llm.base import LLMError

    monkeypatch.setattr("app.config.Config.ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("app.config.Config.ANTHROPIC_MODEL", "claude-sonnet-4-5")
    from app.llm.claude_provider import ClaudeProvider

    fake_client = MagicMock()
    fake_client.messages.create.side_effect = RuntimeError("rate limited")

    with patch("anthropic.Anthropic", return_value=fake_client):
        provider = ClaudeProvider()
        with pytest.raises(LLMError):
            provider.narrate("system", "user", feature="psirt_extract")

    rows = ai_usage.query_usage(_dt(1), _dt(-1))
    assert rows[-1]["feature"] == "psirt_extract"
    assert rows[-1]["success"] is False
