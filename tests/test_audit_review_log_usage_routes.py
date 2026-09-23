import json
import time
from unittest.mock import patch

import pytest


@pytest.fixture
def app():
    from app import create_app
    return create_app()


_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def client(app):
    with app.test_client() as c, \
         patch("app.auth._load_users", return_value=_TEST_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def _post(client, url, payload):
    return client.post(
        url, data=json.dumps(payload), content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )


def test_log_usage_status_unavailable_by_default(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    resp = client.get("/api/audit-review/log-usage-status")
    assert resp.get_json() == {"available": False}


def test_log_usage_status_available_when_configured(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({
        "enabled": True, "base_url": "https://4tlog:5443", "token": "tok", "verify_ssl": True,
    })
    resp = client.get("/api/audit-review/log-usage-status")
    assert resp.get_json() == {"available": True}


def test_log_usage_check_disabled_returns_503(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    resp = _post(client, "/api/audit-review/log-usage-check",
                 {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 30})
    assert resp.status_code == 503


def test_log_usage_check_missing_fields_returns_400(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    resp = _post(client, "/api/audit-review/log-usage-check", {"adom": "ADOM"})
    assert resp.status_code == 400


def test_log_usage_check_clamps_days_out_of_range(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    with patch("app.log_hygiene.check_rule_log_usage", return_value={"ok": True}) as mock_check:
        _post(client, "/api/audit-review/log-usage-check",
              {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 9999})
    assert mock_check.call_args.args == ("ADOM", "pkg", 1, 60)


def test_log_usage_check_infinity_policy_id_returns_400(client, tmp_path, monkeypatch):
    """json.loads (used by Flask's request.get_json()) accepts the literal
    Infinity; int(Infinity) raises OverflowError, which must be caught and
    turned into a 400, never a raw 500."""
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    resp = client.post(
        "/api/audit-review/log-usage-check",
        data='{"adom": "ADOM", "pkg": "pkg", "policy_id": Infinity, "days": 30}',
        content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )
    assert resp.status_code == 400


def test_log_usage_check_success(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    fake_result = {"rule": {"policy_id": 1, "name": "R"}, "days": 30}
    with patch("app.log_hygiene.check_rule_log_usage", return_value=fake_result):
        resp = _post(client, "/api/audit-review/log-usage-check",
                     {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 30})
    assert resp.status_code == 200
    assert resp.get_json() == fake_result


def test_log_usage_check_stale_rule_returns_400(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    from app.log_hygiene import LogHygieneError
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    with patch("app.log_hygiene.check_rule_log_usage", side_effect=LogHygieneError("Rule 1 not found")):
        resp = _post(client, "/api/audit-review/log-usage-check",
                     {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 30})
    assert resp.status_code == 400
    assert "not found" in resp.get_json()["error"]


def test_log_usage_check_upstream_failure_returns_502(client, tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    from app.log_usage_client import LogUsageError
    log_source.save_log_source_config({"enabled": True, "base_url": "https://x", "token": "t", "verify_ssl": True})
    with patch("app.log_hygiene.check_rule_log_usage", side_effect=LogUsageError("unreachable")):
        resp = _post(client, "/api/audit-review/log-usage-check",
                     {"adom": "ADOM", "pkg": "pkg", "policy_id": 1, "days": 30})
    assert resp.status_code == 502
