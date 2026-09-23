from unittest.mock import MagicMock, patch

import pytest


def _cfg(**overrides):
    base = {"enabled": True, "base_url": "https://4tlog.test:5443",
            "token": "tok123", "verify_ssl": True}
    base.update(overrides)
    return base


def test_get_rule_log_usage_not_enabled_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg(enabled=False))
    with pytest.raises(log_usage_client.LogUsageError, match="not enabled"):
        log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_not_configured_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config",
                         lambda: _cfg(base_url="", token=""))
    with pytest.raises(log_usage_client.LogUsageError, match="not configured"):
        log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_success(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"srcips": ["10.1.1.5"], "dstips": [], "dstports": [443]}
    with patch("app.log_usage_client.requests.post", return_value=mock_resp) as mock_post:
        result = log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 123, 30)
    assert result["srcips"] == ["10.1.1.5"]
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["json"] == {"adom": "ADOM", "devices": ["FW01"], "policyid": 123, "days": 30}
    assert call_kwargs["headers"]["Authorization"] == "Bearer tok123"


def test_get_rule_log_usage_unauthorized_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=401)
    with patch("app.log_usage_client.requests.post", return_value=mock_resp):
        with pytest.raises(log_usage_client.LogUsageError, match="rejected"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_disabled_on_4tlog_side_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=503)
    with patch("app.log_usage_client.requests.post", return_value=mock_resp):
        with pytest.raises(log_usage_client.LogUsageError, match="disabled"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_connection_error_raises(monkeypatch):
    import requests

    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    with patch("app.log_usage_client.requests.post",
               side_effect=requests.ConnectionError("refused")):
        with pytest.raises(log_usage_client.LogUsageError, match="Could not reach"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_bad_json_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.side_effect = ValueError("bad json")
    with patch("app.log_usage_client.requests.post", return_value=mock_resp):
        with pytest.raises(log_usage_client.LogUsageError, match="invalid response"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_test_connection_ok(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=200)
    with patch("app.log_usage_client.requests.get", return_value=mock_resp):
        result = log_usage_client.test_connection()
    assert result == {"ok": True, "error": None}


def test_test_connection_not_configured(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config",
                         lambda: _cfg(base_url="", token=""))
    result = log_usage_client.test_connection()
    assert result["ok"] is False
    assert "required" in result["error"]


def test_get_rule_log_usage_non_dict_200_body_raises(monkeypatch):
    """A 200 response whose JSON body is not a dict (e.g. a bare list) must
    raise LogUsageError, not be returned as-is for callers to crash on."""
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = ["not", "a", "dict"]
    with patch("app.log_usage_client.requests.post", return_value=mock_resp):
        with pytest.raises(log_usage_client.LogUsageError, match="invalid response"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)


def test_get_rule_log_usage_bad_status_non_dict_json_raises(monkeypatch):
    from app import log_usage_client
    monkeypatch.setattr(log_usage_client, "load_log_source_config", lambda: _cfg())
    mock_resp = MagicMock(status_code=422)
    mock_resp.json.return_value = "error message as string"
    mock_resp.text = "error message as string"
    with patch("app.log_usage_client.requests.post", return_value=mock_resp):
        with pytest.raises(log_usage_client.LogUsageError, match="error"):
            log_usage_client.get_rule_log_usage("ADOM", ["FW01"], 1, 30)
