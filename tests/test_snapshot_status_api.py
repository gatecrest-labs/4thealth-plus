"""Snapshot coverage status API and badge (Phase 5, Task 7)."""

import json
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from app import audit_data, snapshot_cache, snapshot_store
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

_USERS = {
    "admin": {"password_hash": "$2b$12$placeholder", "role": "admin"},
    "viewer1": {"password_hash": "$2b$12$placeholder", "role": "viewer"},
}


@pytest.fixture
def rig(monkeypatch):
    for k, v in (("INVENTORY_CACHE", False), ("AUDIT_SNAPSHOTS", True), ("AUDIT_SNAPSHOT_WINDOW_DAYS", 7), ("AUDIT_SNAPSHOT_MAX_AGE_HOURS", 0)):
        monkeypatch.setattr(Config, k, v)
    snapshot_cache._revision_flags.clear()
    audit_data.reset_counters()
    synth = SyntheticFMG(adoms=1, devices=5, seed=4)
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    monkeypatch.setattr("app.routes.api_routes._make_client", lambda: real)
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: real)
    adom = next(a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti"))
    names = sorted(d["name"] for d in real.get_devices(adom))
    return synth, real, adom, names


def _client(role="admin", tabs=("audit_review",)):
    from app import create_app

    app = create_app()
    c = app.test_client()
    p = patch("app.auth._load_users", return_value=_USERS)
    p.start()
    with c.session_transaction() as sess:
        sess["user"] = "admin" if role == "admin" else "viewer1"
        sess["role"] = role
        sess["allowed_tabs"] = list(tabs)
        sess["_csrf_token"] = "t"
        sess["login_at"] = int(time.time())
    return c, p


def _get(c, adom):
    return c.get("/api/audit-snapshots/status", query_string={"adom": adom})


def test_requires_login_tab_and_adom(rig):
    synth, real, adom, names = rig
    from app import create_app

    anon = create_app().test_client()
    assert _get(anon, adom).status_code in (302, 401)
    c, p = _client("viewer", tabs=("versions",))
    try:
        assert _get(c, adom).status_code == 403
    finally:
        p.stop()
    c, p = _client()
    try:
        assert c.get("/api/audit-snapshots/status").status_code == 400
        with patch("app.routes.api_routes.check_adom_access", return_value=({"error": "no"}, 403)):
            assert _get(c, adom).status_code == 403
    finally:
        p.stop()


def test_disabled_shape_when_flag_off(monkeypatch, rig):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)
    c, p = _client()
    try:
        body = _get(c, adom).get_json()
    finally:
        p.stop()
    assert body["enabled"] is False and body["devices_captured"] == 0


def test_counts_coverage_stale_and_unreachable(monkeypatch, rig):
    synth, real, adom, names = rig
    for n in names[:4]:
        snapshot_cache.capture_device(real, adom, n)
    snapshot_store._set_collected_at_for_test(adom, names[0], "ntp", (datetime.now(UTC) - timedelta(hours=400)).isoformat())
    snapshot_store.mark_failed(adom, names[1], ["ntp"], "boom")
    c, p = _client()
    try:
        body = _get(c, adom).get_json()
    finally:
        p.stop()
    assert body["enabled"] is True and body["adom"] == adom
    assert body["devices_total"] == 5 and body["devices_captured"] == 4
    assert body["coverage_pct"] == 80.0
    assert body["devices_stale"] >= 1 and body["devices_unreachable"] >= 1
    assert body["window_days"] == 7 and body["max_age_hours"] == 7 * 24 + 24
    assert body["oldest_at"] and body["newest_at"] and body["oldest_at"] <= body["newest_at"]


def test_response_has_no_config_content(rig):
    synth, real, adom, names = rig
    snapshot_cache.capture_device(real, adom, names[0])
    c, p = _client()
    try:
        raw = _get(c, adom).get_data(as_text=True)
    finally:
        p.stop()
    assert set(json.loads(raw)) == {
        "enabled", "adom", "window_days", "max_age_hours", "devices_total", "devices_captured",
        "coverage_pct", "devices_stale", "devices_unreachable", "oldest_at", "newest_at",
    }
    assert "allowaccess" not in raw and "trusthost" not in raw


def test_page_has_badge_only_when_enabled(monkeypatch, rig):
    synth, real, adom, names = rig
    c, p = _client()
    try:
        on = c.get("/audit-review").get_data(as_text=True)
        monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)
        off = c.get("/audit-review").get_data(as_text=True)
    finally:
        p.stop()
    assert 'id="drSnapshotBadge"' in on
    assert 'id="drSnapshotBadge"' not in off
