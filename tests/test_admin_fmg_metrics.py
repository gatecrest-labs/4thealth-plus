"""Tests for GET /admin/api/fmg-metrics."""

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest


@pytest.fixture
def app():
    from app import create_app

    return create_app()


_USERS = {
    "admin": {"password_hash": "$2b$12$placeholder", "role": "admin"},
    "viewer": {"password_hash": "$2b$12$placeholder", "role": "viewer"},
}


def _client(app, user):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user"] = user
        sess["role"] = _USERS[user]["role"]
        sess["_csrf_token"] = "test-csrf"
        sess["login_at"] = int(time.time())
    return c


def _snap(role, total=3):
    return {"role": role, "since": "x", "total": total, "errors": 0, "by_url": {}}


def _get(app, user="admin"):
    with patch("app.auth._load_users", return_value=_USERS):
        return _client(app, user).get("/admin/api/fmg-metrics")


def test_requires_admin(app):
    assert _get(app, "viewer").status_code in (401, 403)


def test_returns_web_and_collector_snapshots(app):
    from app import collector_store, fmg_metrics

    fmg_metrics.reset()
    fmg_metrics.record("get", "/sys/status", 0.01, True)
    collector_store.write_snapshot(
        "fmg_metrics:collector",
        _snap("collector", 9),
        collected_at=datetime.now(UTC).isoformat(),
    )
    body = _get(app).get_json()
    assert body["web"]["total"] == 1
    assert body["collector"]["total"] == 9
    assert body["note"] is None


def test_missing_collector_snapshot_returns_note_not_500(app):
    from app import fmg_metrics

    fmg_metrics.reset()
    resp = _get(app)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["collector"] is None
    assert "collector" in body["note"].lower()


def test_stale_collector_snapshot_flagged_in_note(app):
    from app import collector_store, fmg_metrics

    fmg_metrics.reset()
    old = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
    collector_store.write_snapshot(
        "fmg_metrics:collector", _snap("collector"), collected_at=old
    )
    body = _get(app).get_json()
    assert body["collector"]["total"] == 3
    assert "stale" in body["note"].lower()


def test_admin_page_has_metrics_panel(app):
    with patch("app.auth._load_users", return_value=_USERS):
        html = _client(app, "admin").get("/admin/").get_data(as_text=True)
    assert 'id="btnFmgMetrics"' in html
    assert 'id="fmgMetricsResult"' in html


def test_web_view_merges_other_workers_and_ignores_stale_ones(app):
    """I2: with several gunicorn workers the web view sums them."""
    import os

    from app import collector_store, fmg_metrics

    fmg_metrics.reset()
    fmg_metrics.record("get", "/sys/status", 0.01, True)
    now = datetime.now(UTC).isoformat()
    old = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
    other = _snap("web", 5)
    other["by_url"] = {
        "get /sys/status": {
            "count": 5,
            "errors": 0,
            "total_s": 0.5,
            "p50_s": 0.1,
            "p95_s": 0.2,
        }
    }
    collector_store.write_snapshot(
        f"fmg_metrics:web:{os.getpid() + 1}", other, collected_at=now
    )
    collector_store.write_snapshot(
        f"fmg_metrics:web:{os.getpid() + 2}", _snap("web", 99), collected_at=old
    )
    collector_store.write_snapshot(
        f"fmg_metrics:web:{os.getpid()}", _snap("web", 77), collected_at=now
    )
    body = _get(app).get_json()
    assert (
        body["web"]["total"] == 6
    )  # live own (1) + fresh other worker (5); stale + own stored row ignored
    assert body["web"]["workers"] == 2
