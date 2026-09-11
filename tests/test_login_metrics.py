"""Tests for app.login_metrics — SQLite-backed login success/failure tracking."""
from __future__ import annotations

import sqlite3
import time

import pytest

from app import login_metrics


@pytest.fixture
def metrics_db(tmp_path, monkeypatch):
    db_path = tmp_path / "login_events_test.db"
    monkeypatch.setattr(login_metrics, "_DB_PATH", db_path)
    login_metrics._init_db()
    return db_path


def _insert(db_path, ts, success):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO login_events (ts, success) VALUES (?, ?)",
        (ts, int(success)),
    )
    conn.commit()
    conn.close()


def test_record_event_persists_a_row(metrics_db):
    login_metrics.record_event(True)
    login_metrics.record_event(False)

    conn = sqlite3.connect(metrics_db)
    rows = conn.execute(
        "SELECT success FROM login_events ORDER BY ts"
    ).fetchall()
    conn.close()
    assert rows == [(1,), (0,)]


def test_get_metrics_buckets_success_and_failure_separately(metrics_db):
    now = int(time.time())
    _insert(metrics_db, now - 10, True)
    _insert(metrics_db, now - 10, False)
    _insert(metrics_db, now - 10, False)

    data = login_metrics.get_metrics("1h")
    assert data["range"] == "1h"
    assert sum(p["v"] for p in data["success"]) == 1
    assert sum(p["v"] for p in data["failed"]) == 2


def test_get_metrics_excludes_rows_outside_window(metrics_db):
    now = int(time.time())
    _insert(metrics_db, now - 10, True)
    _insert(metrics_db, now - 999_999, True)  # far outside any window

    data = login_metrics.get_metrics("1h")
    total_success = sum(p["v"] for p in data["success"])
    assert total_success == 1


def test_get_metrics_defaults_to_1h_for_invalid_range(metrics_db):
    data = login_metrics.get_metrics("not-a-range")
    assert data["range"] == "1h"


def test_prune_old_data_removes_rows_past_retention(metrics_db):
    now = int(time.time())
    _insert(metrics_db, now - (91 * 86_400), True)
    _insert(metrics_db, now, False)

    login_metrics.prune_old_data()

    conn = sqlite3.connect(metrics_db)
    rows = conn.execute("SELECT success FROM login_events").fetchall()
    conn.close()
    assert rows == [(0,)]


def test_record_event_never_raises_on_bad_db_path(monkeypatch, tmp_path):
    bad_path = tmp_path / "does" / "not" / "exist" / "x.db"
    monkeypatch.setattr(login_metrics, "_DB_PATH", bad_path)
    login_metrics.record_event(True)  # must not raise
