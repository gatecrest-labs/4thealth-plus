"""Tests for the ai_assist_enabled admin setting toggle."""
import time
from unittest.mock import patch

import pytest

from app import create_app


@pytest.fixture
def admin_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def test_settings_get_includes_ai_assist_enabled(admin_client):
    resp = admin_client.get("/admin/api/settings")
    assert resp.status_code == 200
    assert "ai_assist_enabled" in resp.get_json()


def test_settings_put_toggles_ai_assist_enabled(admin_client):
    with patch("app.routes.admin_routes.set_setting") as mock_set:
        resp = admin_client.put(
            "/admin/api/settings",
            json={"ai_assist_enabled": True},
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    mock_set.assert_any_call("ai_assist_enabled", True)


# ---------------------------------------------------------------------------
# GET /admin/api/ai-usage
# ---------------------------------------------------------------------------

def test_ai_usage_default_range_is_24h(admin_client):
    with patch("app.ai_usage.usage_summary", return_value={
        "buckets": [], "total_calls": 0, "total_cost_usd": 0.0,
        "total_failures": 0, "total_input_tokens": 0, "total_output_tokens": 0,
    }) as mock_summary:
        resp = admin_client.get("/admin/api/ai-usage")
    assert resp.status_code == 200
    start, end = mock_summary.call_args.args[:2]
    assert (end - start).total_seconds() == pytest.approx(24 * 3600, abs=5)


def test_ai_usage_named_ranges(admin_client):
    for range_name, hours in [("1h", 1), ("4h", 4), ("12h", 12), ("1d", 24), ("7d", 168)]:
        with patch("app.ai_usage.usage_summary", return_value={
            "buckets": [], "total_calls": 0, "total_cost_usd": 0.0,
            "total_failures": 0, "total_input_tokens": 0, "total_output_tokens": 0,
        }) as mock_summary:
            resp = admin_client.get(f"/admin/api/ai-usage?range={range_name}")
        assert resp.status_code == 200
        start, end = mock_summary.call_args.args[:2]
        assert (end - start).total_seconds() == pytest.approx(hours * 3600, abs=5)


def test_ai_usage_custom_date_range(admin_client):
    with patch("app.ai_usage.usage_summary", return_value={
        "buckets": [], "total_calls": 0, "total_cost_usd": 0.0,
        "total_failures": 0, "total_input_tokens": 0, "total_output_tokens": 0,
    }) as mock_summary:
        resp = admin_client.get(
            "/admin/api/ai-usage?start=2026-01-01T00:00:00%2B00:00&end=2026-01-03T00:00:00%2B00:00"
        )
    assert resp.status_code == 200
    start, end = mock_summary.call_args.args[:2]
    assert (end - start).total_seconds() == pytest.approx(2 * 24 * 3600, abs=5)


def test_ai_usage_end_before_start_returns_400(admin_client):
    resp = admin_client.get(
        "/admin/api/ai-usage?start=2026-01-03T00:00:00%2B00:00&end=2026-01-01T00:00:00%2B00:00"
    )
    assert resp.status_code == 400


def test_ai_usage_invalid_datetime_returns_400(admin_client):
    resp = admin_client.get("/admin/api/ai-usage?start=not-a-date&end=also-not-a-date")
    assert resp.status_code == 400


def test_ai_usage_response_includes_summary_fields(admin_client):
    with patch("app.ai_usage.usage_summary", return_value={
        "buckets": [{"start": "x", "end": "y", "count": 2, "cost_usd": 0.05,
                      "input_tokens": 100, "output_tokens": 50}],
        "total_calls": 2, "total_cost_usd": 0.05,
        "total_failures": 0, "total_input_tokens": 100, "total_output_tokens": 50,
    }):
        resp = admin_client.get("/admin/api/ai-usage?range=1h")
    data = resp.get_json()
    assert data["total_calls"] == 2
    assert data["total_cost_usd"] == 0.05
    assert len(data["buckets"]) == 1
    assert "start" in data and "end" in data


def test_settings_get_includes_executive_compliant_versions(admin_client):
    resp = admin_client.get("/admin/api/settings")
    assert resp.status_code == 200
    assert "executive_compliant_versions" in resp.get_json()


def test_settings_put_accepts_list_of_versions(admin_client):
    with patch("app.routes.admin_routes.set_setting") as mock_set:
        resp = admin_client.put(
            "/admin/api/settings",
            json={"executive_compliant_versions": ["v7.4.3", "v7.6.2"]},
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    mock_set.assert_any_call(
        "executive_compliant_versions", ["v7.4.3", "v7.6.2"]
    )


def test_settings_put_splits_comma_and_newline_separated_string(admin_client):
    with patch("app.routes.admin_routes.set_setting") as mock_set:
        resp = admin_client.put(
            "/admin/api/settings",
            json={"executive_compliant_versions": "v7.4.3,\nv7.6.2, v7.6.3"},
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    mock_set.assert_any_call(
        "executive_compliant_versions", ["v7.4.3", "v7.6.2", "v7.6.3"]
    )


def test_settings_put_empty_string_clears_versions(admin_client):
    with patch("app.routes.admin_routes.set_setting") as mock_set:
        resp = admin_client.put(
            "/admin/api/settings",
            json={"executive_compliant_versions": ""},
            headers={"X-CSRF-Token": "test-csrf"},
        )
    assert resp.status_code == 200
    mock_set.assert_any_call("executive_compliant_versions", [])
