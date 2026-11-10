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


class _FlakyConn:
    """sqlite3 connection wrapper whose first N PRAGMA/script calls report a lock."""

    def __init__(self, real, fail_times):
        self._real = real
        self.fail_times = fail_times

    def _maybe_fail(self):
        if self.fail_times > 0:
            self.fail_times -= 1
            raise sqlite3.OperationalError("database is locked")

    def execute(self, sql, *a):
        if sql.strip().upper().startswith("PRAGMA JOURNAL_MODE"):
            self._maybe_fail()
        return self._real.execute(sql, *a)

    def executescript(self, sql):
        self._maybe_fail()
        return self._real.executescript(sql)

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __setattr__(self, name, value):
        if name == "row_factory":
            self._real.row_factory = value
        else:
            super().__setattr__(name, value)


@pytest.mark.parametrize("fail_times", [1, 3])
def test_first_use_survives_transient_database_locked(
    tmp_path, monkeypatch, fail_times
):
    """Web and collector can both create a fresh DB at once; a transient
    'database is locked' on the journal PRAGMA or schema script must be retried."""
    from app import collector_store

    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "flaky.db"))
    real_connect = sqlite3.connect
    flaky = {}

    def connect(*a, **k):
        c = _FlakyConn(real_connect(*a, **k), fail_times)
        flaky.setdefault("first", c)
        return c

    monkeypatch.setattr(collector_store.sqlite3, "connect", connect)
    monkeypatch.setattr(collector_store.time, "sleep", lambda s: None)
    collector_store.write_snapshot("k", {"a": 1})
    assert collector_store.read_snapshot("k") == {"a": 1}


def test_persistent_lock_still_raises(tmp_path, monkeypatch):
    from app import collector_store

    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "stuck.db"))
    real_connect = sqlite3.connect
    monkeypatch.setattr(
        collector_store.sqlite3,
        "connect",
        lambda *a, **k: _FlakyConn(real_connect(*a, **k), 10_000),
    )
    monkeypatch.setattr(collector_store.time, "sleep", lambda s: None)
    with pytest.raises(sqlite3.OperationalError):
        collector_store.write_snapshot("k", {"a": 1})
