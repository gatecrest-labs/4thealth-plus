"""Tests for app/backup_engine.py"""
import time

import pytest
import pyzipper

# ── helpers ──────────────────────────────────────────────────────────────────

def _make_config(tmp_path, **overrides):
    cfg = {
        "password": "testpass123",
        "backup_dir": str(tmp_path / "backups"),
        "max_files": 20,
        "exclude_tls_key": False,
    }
    cfg.update(overrides)
    return cfg


# ── create_backup ─────────────────────────────────────────────────────────────

def test_create_backup_writes_zip(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_BASE_DIR", tmp_path)
    (tmp_path / "users.json").write_text('{"users":[]}')
    (tmp_path / ".env").write_text("SECRET_KEY=test")

    path, filename = engine.create_backup(_make_config(tmp_path))

    assert path.exists()
    assert path.suffix == ".zip"
    assert "BACKUP" in filename
    assert path.name == filename


def test_create_backup_filename_format(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_BASE_DIR", tmp_path)

    _, filename = engine.create_backup(_make_config(tmp_path))

    # SERVERNAME-BACKUP_YYYY-MM-DD_HHmm.zip
    import re
    assert re.match(r".+-BACKUP_\d{4}-\d{2}-\d{2}_\d{4}\.zip", filename)


def test_create_backup_aes256_wrong_password_fails(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_BASE_DIR", tmp_path)
    (tmp_path / "users.json").write_text('{"users":[]}')

    path, _ = engine.create_backup(_make_config(tmp_path, password="correctpass"))

    with pytest.raises(Exception), pyzipper.AESZipFile(path) as zf:
        zf.setpassword(b"wrongpass")
        zf.extractall(tmp_path / "extracted_wrong")


def test_create_backup_correct_password_opens(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_BASE_DIR", tmp_path)
    (tmp_path / "users.json").write_text('{"key":"val"}')

    path, _ = engine.create_backup(_make_config(tmp_path, password="mypassword"))

    with pyzipper.AESZipFile(path) as zf:
        zf.setpassword(b"mypassword")
        names = zf.namelist()
    assert "users.json" in names


def test_create_backup_skips_missing_files(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_BASE_DIR", tmp_path)
    # No files exist at all — should not raise

    path, _ = engine.create_backup(_make_config(tmp_path))
    assert path.exists()


def test_create_backup_exclude_tls_key(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_BASE_DIR", tmp_path)
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "key.pem").write_text("PRIVATE KEY")
    (certs / "cert.pem").write_text("CERTIFICATE")

    path, _ = engine.create_backup(_make_config(tmp_path, exclude_tls_key=True))

    with pyzipper.AESZipFile(path) as zf:
        zf.setpassword(b"testpass123")
        names = zf.namelist()
    assert "certs/key.pem" not in names
    assert "certs/cert.pem" in names


def test_create_backup_includes_tls_key_when_not_excluded(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_BASE_DIR", tmp_path)
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "key.pem").write_text("PRIVATE KEY")

    path, _ = engine.create_backup(_make_config(tmp_path, exclude_tls_key=False))

    with pyzipper.AESZipFile(path) as zf:
        zf.setpassword(b"testpass123")
        names = zf.namelist()
    assert "certs/key.pem" in names


# ── _prune_backups ────────────────────────────────────────────────────────────

def test_prune_keeps_newest_n(tmp_path):
    import app.backup_engine as engine
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    for i in range(21):
        f = backup_dir / f"SERVER-BACKUP_2026-01-{i+1:02d}_0000.zip"
        f.write_bytes(b"fake")
        time.sleep(0.01)  # ensure different mtimes

    engine._prune_backups(backup_dir, 20)

    remaining = list(backup_dir.glob("*-BACKUP_*.zip"))
    assert len(remaining) == 20


def test_prune_deletes_oldest(tmp_path):
    import app.backup_engine as engine
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    oldest = backup_dir / "SERVER-BACKUP_2026-01-01_0000.zip"
    oldest.write_bytes(b"old")
    time.sleep(0.05)

    for i in range(20):
        f = backup_dir / f"SERVER-BACKUP_2026-01-{i+2:02d}_0000.zip"
        f.write_bytes(b"newer")
        time.sleep(0.01)

    engine._prune_backups(backup_dir, 20)
    assert not oldest.exists()


def test_prune_no_op_when_under_limit(tmp_path):
    import app.backup_engine as engine
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    for i in range(5):
        (backup_dir / f"SERVER-BACKUP_2026-01-{i+1:02d}_0000.zip").write_bytes(b"x")

    engine._prune_backups(backup_dir, 20)
    assert len(list(backup_dir.glob("*-BACKUP_*.zip"))) == 5


# ── load_config / save_config ─────────────────────────────────────────────────

def test_load_config_returns_defaults_when_missing(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    cfg = engine.load_config()
    assert cfg["backup_dir"] == "/var/backups/4thealth"
    assert cfg["max_files"] == 20
    assert cfg["exclude_tls_key"] is False


def test_save_config_rejects_empty_password(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    with pytest.raises(ValueError, match="password"):
        engine.save_config({"password": "", "backup_dir": "/var/backups/4thealth"})


def test_save_config_rejects_missing_password_key(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    with pytest.raises(ValueError, match="password"):
        engine.save_config({"backup_dir": "/var/backups/4thealth"})


def test_save_config_roundtrip(tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    cfg = {"password": "secret", "backup_dir": "/var/backups/4thealth",
           "max_files": 20, "exclude_tls_key": True, "ftp": {}, "jobs": []}
    engine.save_config(cfg)
    loaded = engine.load_config()
    assert loaded["exclude_tls_key"] is True
    assert loaded["password"] == "secret"
