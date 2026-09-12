import json

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Point collector_store at a throwaway DB file per test."""
    from app import collector_store

    db_path = tmp_path / "collector_state_test.db"
    monkeypatch.setattr(collector_store, "_DB_PATH", db_path)
    yield


def test_read_snapshot_missing_key_returns_none():
    from app.collector_store import read_snapshot

    assert read_snapshot("nope") is None


def test_write_then_read_snapshot_round_trips():
    from app.collector_store import read_snapshot, write_snapshot

    write_snapshot("device_review", {"devices_reviewed": 5}, collected_at="2026-09-12T00:00:00+00:00")

    result = read_snapshot("device_review")

    assert result == {"devices_reviewed": 5}


def test_write_snapshot_overwrites_previous_value_for_same_key():
    from app.collector_store import read_snapshot, write_snapshot

    write_snapshot("device_review", {"devices_reviewed": 5})
    write_snapshot("device_review", {"devices_reviewed": 9})

    assert read_snapshot("device_review") == {"devices_reviewed": 9}


def test_write_snapshot_is_wal_mode(tmp_path):
    from app import collector_store

    collector_store.write_snapshot("x", {"a": 1})
    conn = collector_store._connect()
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal"
