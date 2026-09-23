def test_load_log_source_config_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    cfg = log_source.load_log_source_config()
    assert cfg["enabled"] is False
    assert cfg["base_url"] == ""
    assert cfg["token"] == ""
    assert cfg["verify_ssl"] is True


def test_save_and_reload_log_source_config(tmp_path, monkeypatch):
    monkeypatch.setattr("app.log_source._CONFIG_PATH", tmp_path / "log_source_config.json")
    from app import log_source
    log_source.save_log_source_config({
        "enabled": True, "base_url": "https://4tlog.internal:5443",
        "token": "secret-token", "verify_ssl": False,
    })
    cfg = log_source.load_log_source_config()
    assert cfg["enabled"] is True
    assert cfg["base_url"] == "https://4tlog.internal:5443"
    assert cfg["token"] == "secret-token"
    assert cfg["verify_ssl"] is False


def test_load_log_source_config_survives_corrupt_file(tmp_path, monkeypatch):
    path = tmp_path / "log_source_config.json"
    path.write_text("not json")
    monkeypatch.setattr("app.log_source._CONFIG_PATH", path)
    from app import log_source
    cfg = log_source.load_log_source_config()
    assert cfg["enabled"] is False
