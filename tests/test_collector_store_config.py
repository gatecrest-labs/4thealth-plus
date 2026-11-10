"""collector_store location and journal mode are configurable."""

import logging
import sqlite3

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("COLLECTOR_DB_PATH", raising=False)
    monkeypatch.delenv("COLLECTOR_DB_JOURNAL", raising=False)


def _mode(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("PRAGMA journal_mode").fetchone()[0].lower()
    finally:
        conn.close()


def test_db_path_env_override(tmp_path, monkeypatch):
    from app import collector_store

    target = tmp_path / "sub" / "alt.db"
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(target))
    collector_store.write_snapshot("k", {"a": 1})
    assert target.exists()
    assert collector_store.read_snapshot("k") == {"a": 1}


def test_journal_delete_mode_applied(tmp_path, monkeypatch):
    from app import collector_store

    target = tmp_path / "d.db"
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(target))
    monkeypatch.setenv("COLLECTOR_DB_JOURNAL", "DELETE")
    collector_store.write_snapshot("k", {"a": 1})
    conn = collector_store._connect()
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
    finally:
        conn.close()
    assert _mode(target) == "delete"


def test_journal_invalid_falls_back_to_wal_and_warns(tmp_path, monkeypatch, caplog):
    from app import collector_store

    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "w.db"))
    monkeypatch.setenv("COLLECTOR_DB_JOURNAL", "bogus")
    with caplog.at_level(logging.WARNING):
        assert collector_store._journal_mode() == "WAL"
    assert "COLLECTOR_DB_JOURNAL" in caplog.text
    collector_store.write_snapshot("k", {"a": 1})
    assert _mode(tmp_path / "w.db") == "wal"
