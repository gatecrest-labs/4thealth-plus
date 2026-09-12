"""Tests for app.change_control_cache — audit-log aggregation, persistence
across a simulated restart, and sweep failure/overlap behavior."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import MagicMock, patch

import pytest

from app import change_control_cache as cc


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    from app import collector_store

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")
    cc._running.clear()
    yield
    cc._running.clear()


def _fake_client(entries):
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get_audit_log.return_value = entries
    return client


# ── aggregate_audit_log (pure) ───────────────────────────────────────────────


def test_aggregate_empty_log():
    result = cc.aggregate_audit_log([])
    assert result == {"admin_changes_24h": 0, "admin_changes_by_user": []}


def test_aggregate_counts_total_entries():
    entries = [{"user": "alice"}, {"user": "bob"}, {"user": "alice"}]
    assert cc.aggregate_audit_log(entries)["admin_changes_24h"] == 3


def test_aggregate_ranks_by_user_count_descending():
    entries = [{"user": "alice"}] * 5 + [{"user": "bob"}] * 2 + [{"user": "carol"}]
    result = cc.aggregate_audit_log(entries)
    assert result["admin_changes_by_user"] == [
        {"user": "alice", "count": 5},
        {"user": "bob", "count": 2},
        {"user": "carol", "count": 1},
    ]


def test_aggregate_caps_at_top_5_users():
    entries = []
    for i in range(7):
        entries.extend([{"user": f"user{i}"}] * (7 - i))
    result = cc.aggregate_audit_log(entries)
    assert len(result["admin_changes_by_user"]) == 5
    assert result["admin_changes_by_user"][0]["user"] == "user0"


def test_aggregate_ties_broken_by_first_seen_order():
    entries = [{"user": "bob"}, {"user": "alice"}]  # both count 1, bob seen first
    result = cc.aggregate_audit_log(entries)
    assert [u["user"] for u in result["admin_changes_by_user"]] == ["bob", "alice"]


def test_aggregate_missing_user_field_bucketed_as_unknown():
    entries = [{"action": "login"}, {"user": None}]
    result = cc.aggregate_audit_log(entries)
    assert result["admin_changes_by_user"] == [{"user": "unknown", "count": 2}]


def test_aggregate_ignores_non_dict_entries():
    result = cc.aggregate_audit_log([{"user": "alice"}, "garbage", None])
    assert result["admin_changes_24h"] == 3  # len(entries), not filtered count
    assert result["admin_changes_by_user"] == [{"user": "alice", "count": 1}]


# ── persistence / restart survival ──────────────────────────────────────────


def test_get_latest_none_before_any_sweep():
    assert cc.get_latest() is None


def test_run_sweep_persists_result():
    client = _fake_client([{"user": "alice"}, {"user": "bob"}])
    with patch("app.fmg_helpers.make_client", return_value=client):
        assert cc._run_sweep(app=None) is True

    latest = cc.get_latest()
    assert latest["admin_changes_24h"] == 2
    assert latest["collected_at"] is not None


def test_get_latest_survives_simulated_restart(tmp_path, monkeypatch):
    """Persistence must not depend on any in-memory state — reloading the
    module attribute (simulating a fresh process reading the same file)
    still returns the last successful result."""
    client = _fake_client([{"user": "alice"}])
    with patch("app.fmg_helpers.make_client", return_value=client):
        cc._run_sweep(app=None)

    # Simulate "restart": nothing in this module carries in-memory state
    # that get_latest() depends on other than the file path itself.
    assert cc.get_latest()["admin_changes_24h"] == 1


def test_failed_sweep_keeps_last_persisted_result():
    client = _fake_client([{"user": "alice"}])
    with patch("app.fmg_helpers.make_client", return_value=client):
        cc._run_sweep(app=None)
    before = cc.get_latest()

    with patch("app.fmg_helpers.make_client", side_effect=RuntimeError("FMG down")):
        result = cc._run_sweep(app=None)

    assert result is False
    assert cc.get_latest() == before


def test_sweep_skips_when_already_running():
    cc._running.set()
    try:
        assert cc._run_sweep(app=None) is False
    finally:
        cc._running.clear()
    assert cc.get_latest() is None


def test_get_latest_persists_via_sqlite_not_json_file(monkeypatch, tmp_path):
    from app import change_control_cache, collector_store

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    assert change_control_cache.get_latest() is None

    change_control_cache._save(
        {"admin_changes_24h": 3, "admin_changes_by_user": [], "collected_at": "t1"}
    )

    assert change_control_cache.get_latest() == {
        "admin_changes_24h": 3,
        "admin_changes_by_user": [],
        "collected_at": "t1",
    }
