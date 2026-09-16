from unittest.mock import MagicMock, patch

import pytest


def test_load_smtp_config_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr("app.smtp_client._CONFIG_PATH", tmp_path / "smtp_config.json")
    from app import smtp_client
    cfg = smtp_client.load_smtp_config()
    assert cfg["port"] == 25
    assert cfg["tls_mode"] == "none"
    assert cfg["run_history_days"] == 30
    assert cfg["enabled"] is False


def test_save_and_reload_smtp_config(tmp_path, monkeypatch):
    monkeypatch.setattr("app.smtp_client._CONFIG_PATH", tmp_path / "smtp_config.json")
    from app import smtp_client
    smtp_client.save_smtp_config({"host": "mail.internal", "port": 587, "tls_mode": "starttls",
                                   "username": "", "password": "", "from_address": "noreply@x.com",
                                   "run_history_days": 14, "enabled": True})
    cfg = smtp_client.load_smtp_config()
    assert cfg["host"] == "mail.internal"
    assert cfg["port"] == 587
    assert cfg["run_history_days"] == 14


def test_test_connection_returns_error_when_smtp_unreachable(tmp_path, monkeypatch):
    monkeypatch.setattr("app.smtp_client._CONFIG_PATH", tmp_path / "smtp_config.json")
    from app import smtp_client
    smtp_client.save_smtp_config({"host": "127.0.0.1", "port": 19999, "tls_mode": "none",
                                   "username": "", "password": "", "from_address": "test@x.com",
                                   "run_history_days": 30, "enabled": True})
    result = smtp_client.test_connection("dest@x.com")
    assert result["ok"] is False
    assert "error" in result


def test_send_email_raises_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr("app.smtp_client._CONFIG_PATH", tmp_path / "smtp_config.json")
    from app import smtp_client
    smtp_client.save_smtp_config({"host": "mail.internal", "port": 25, "tls_mode": "none",
                                   "username": "", "password": "", "from_address": "",
                                   "run_history_days": 30, "enabled": False})
    with pytest.raises(RuntimeError, match="SMTP not enabled"):
        smtp_client.send_email("x@x.com", "Test", "<p>hi</p>")


def test_parse_recipients_single():
    from app.smtp_client import _parse_recipients
    assert _parse_recipients("a@x.com") == ["a@x.com"]


def test_parse_recipients_comma_separated():
    from app.smtp_client import _parse_recipients
    assert _parse_recipients("a@x.com, b@x.com") == ["a@x.com", "b@x.com"]


def test_parse_recipients_strips_whitespace():
    from app.smtp_client import _parse_recipients
    assert _parse_recipients("  a@x.com ,  b@x.com  ") == ["a@x.com", "b@x.com"]


def test_parse_recipients_filters_empty():
    from app.smtp_client import _parse_recipients
    assert _parse_recipients("a@x.com,") == ["a@x.com"]


def test_send_email_calls_sendmail_with_list(monkeypatch):
    """sendmail() must receive a list of addresses, not a bare string."""
    from app import smtp_client

    cfg = {
        "host": "smtp.test",
        "port": 25,
        "tls_mode": "none",
        "username": "",
        "password": "",
        "from_address": "noreply@test.com",
        "enabled": True,
    }
    monkeypatch.setattr(smtp_client, "load_smtp_config", lambda: cfg)

    mock_conn = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_conn):
        smtp_client.send_email("a@x.com, b@x.com", "subj", "<p>hi</p>")

    call_args = mock_conn.sendmail.call_args
    recipients = call_args[0][1]  # positional arg 1
    assert isinstance(recipients, list)
    assert "a@x.com" in recipients
    assert "b@x.com" in recipients
