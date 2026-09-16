"""Tests for app/routes/backup_routes.py"""
import json
import os
import time
from unittest import mock

import pytest

_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def app():
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
    os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")
    from app import create_app
    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_session(client):
    """Set up an admin session on the client and mock user lookup."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["_csrf_token"] = "test-csrf"
        sess["login_at"] = int(time.time())
    with mock.patch("app.auth._load_users", return_value=_TEST_USERS):
        yield


# ── Request helpers ───────────────────────────────────────────────────────────

def _csrf_headers():
    return {"X-CSRF-Token": "test-csrf"}


def _post(client, url, payload=None):
    kwargs = {"headers": _csrf_headers()}
    if payload is not None:
        kwargs["data"] = json.dumps(payload)
        kwargs["content_type"] = "application/json"
    return client.post(url, **kwargs)


def _put(client, url, payload=None):
    kwargs = {"headers": _csrf_headers()}
    if payload is not None:
        kwargs["data"] = json.dumps(payload)
        kwargs["content_type"] = "application/json"
    return client.put(url, **kwargs)


def _delete(client, url):
    return client.delete(url, headers=_csrf_headers())


# ── Config endpoints ──────────────────────────────────────────────────────────

def test_get_config_masks_password(client, admin_session, tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")
    engine.save_config({
        "password": "supersecret",
        "backup_dir": "/var/backups/4thealth",
        "max_files": 20,
        "exclude_tls_key": False,
        "ftp": {"enabled": False, "protocol": "sftp", "host": "",
                "port": 22, "username": "", "password": "", "remote_dir": "/"},
        "jobs": [],
    })

    resp = client.get("/admin/api/backup/config")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["password"] == "••••••"
    assert data["backup_dir"] == "/var/backups/4thealth"


def test_get_config_requires_admin(client):
    resp = client.get("/admin/api/backup/config")
    assert resp.status_code in (302, 401, 403)


def test_put_config_saves(client, admin_session, tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    payload = {
        "password": "newpassword",
        "backup_dir": "/var/backups/4thealth",
        "max_files": 20,
        "exclude_tls_key": True,
        "ftp": {"enabled": False, "protocol": "sftp", "host": "",
                "port": 22, "username": "", "password": "", "remote_dir": "/"},
    }
    resp = _put(client, "/admin/api/backup/config", payload)
    assert resp.status_code == 200

    cfg = engine.load_config()
    assert cfg["exclude_tls_key"] is True
    assert cfg["password"] == "newpassword"


def test_put_config_rejects_empty_password(client, admin_session, tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    payload = {"password": "", "backup_dir": "/var/backups/4thealth",
               "max_files": 20, "exclude_tls_key": False,
               "ftp": {"enabled": False, "protocol": "sftp", "host": "",
                       "port": 22, "username": "", "password": "", "remote_dir": "/"}}
    resp = _put(client, "/admin/api/backup/config", payload)
    assert resp.status_code == 400


def test_password_mask_preserved_on_put(client, admin_session, tmp_path, monkeypatch):
    """PUT with mask placeholder preserves the stored password."""
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")
    engine.save_config({
        "password": "original_secret",
        "backup_dir": "/var/backups/4thealth",
        "max_files": 20,
        "exclude_tls_key": False,
        "ftp": {"enabled": False, "protocol": "sftp", "host": "",
                "port": 22, "username": "", "password": "", "remote_dir": "/"},
        "jobs": [],
    })
    payload = {
        "password": "••••••",   # mask placeholder — must not overwrite
        "backup_dir": "/var/backups/4thealth",
        "max_files": 30,
        "exclude_tls_key": False,
        "ftp": {"enabled": False, "protocol": "sftp", "host": "",
                "port": 22, "username": "", "password": "••••••", "remote_dir": "/"},
    }
    resp = _put(client, "/admin/api/backup/config", payload)
    assert resp.status_code == 200
    cfg = engine.load_config()
    assert cfg["password"] == "original_secret"
    assert cfg["max_files"] == 30


# ── run-now endpoint ──────────────────────────────────────────────────────────

def test_run_now_returns_zip_download(client, admin_session, tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    fake_zip = tmp_path / "SERVER-BACKUP_2026-08-10_0200.zip"
    fake_zip.write_bytes(b"PK\x03\x04fake")

    with (
        mock.patch("app.routes.backup_routes.backup_engine.create_backup",
                    return_value=(fake_zip, fake_zip.name)),
        mock.patch("app.routes.backup_routes.backup_engine.load_config",
                        return_value={"password": "pw", "backup_dir": str(tmp_path),
                                      "max_files": 20, "exclude_tls_key": False, "ftp": {}}),
    ):
        resp = _post(client, "/admin/api/backup/run-now")

    assert resp.status_code == 200
    assert "zip" in resp.content_type
    assert resp.data == b"PK\x03\x04fake"


def test_run_now_requires_password_configured(client, admin_session, tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")
    # No config saved — load_config() returns default with empty password

    resp = _post(client, "/admin/api/backup/run-now")
    assert resp.status_code == 400
    assert "password" in resp.get_json().get("error", "").lower()


# ── FTP test connection ───────────────────────────────────────────────────────

def test_ftp_test_returns_success(client, admin_session):
    with mock.patch("app.routes.backup_routes.backup_scheduler.test_connection",
                    return_value={"success": True, "message": "Connected"}):
        resp = _post(client, "/admin/api/backup/ftp/test",
                     {"protocol": "sftp", "host": "backup.example.com",
                      "port": 22, "username": "u", "password": "p",
                      "remote_dir": "/"})
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True


def test_ftp_test_returns_failure(client, admin_session):
    with mock.patch("app.routes.backup_routes.backup_scheduler.test_connection",
                    return_value={"success": False, "message": "Connection refused"}):
        resp = _post(client, "/admin/api/backup/ftp/test",
                     {"protocol": "sftp", "host": "bad.host",
                      "port": 22, "username": "u", "password": "p",
                      "remote_dir": "/"})
    assert resp.status_code == 200
    assert resp.get_json()["success"] is False


# ── Job CRUD endpoints ────────────────────────────────────────────────────────

def test_list_jobs_empty(client, admin_session, tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    with mock.patch("app.routes.backup_routes.backup_scheduler.get_all_jobs",
                    return_value=[]):
        resp = client.get("/admin/api/backup/jobs")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_create_job_endpoint(client, admin_session, tmp_path, monkeypatch):
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")

    new_job = {"id": "abc", "name": "Nightly", "days_of_week": ["MON"],
               "time": "02:00", "enabled": True, "runs": []}
    with mock.patch("app.routes.backup_routes.backup_scheduler.create_job",
                    return_value=new_job):
        resp = _post(client, "/admin/api/backup/jobs",
                     {"name": "Nightly", "days_of_week": ["MON"],
                      "time": "02:00", "enabled": True})
    assert resp.status_code == 201
    assert resp.get_json()["name"] == "Nightly"


def test_delete_job_endpoint(client, admin_session):
    with mock.patch("app.routes.backup_routes.backup_scheduler.delete_job"):
        resp = _delete(client, "/admin/api/backup/jobs/some-uuid")
    assert resp.status_code == 200


def test_update_job_endpoint(client, admin_session):
    updated_job = {"id": "abc", "name": "Updated", "days_of_week": ["TUE"],
                   "time": "03:00", "enabled": True, "runs": []}
    with mock.patch("app.routes.backup_routes.backup_scheduler.update_job",
                    return_value=updated_job):
        resp = _put(client, "/admin/api/backup/jobs/abc",
                    {"name": "Updated", "days_of_week": ["TUE"], "time": "03:00"})
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "Updated"


def test_update_job_not_found(client, admin_session):
    with mock.patch("app.routes.backup_routes.backup_scheduler.update_job",
                    side_effect=KeyError("no such job")):
        resp = _put(client, "/admin/api/backup/jobs/missing", {"name": "x"})
    assert resp.status_code == 404


def test_run_job_now_endpoint(client, admin_session):
    with mock.patch("app.routes.backup_routes.backup_scheduler.run_job_now"):
        resp = _post(client, "/admin/api/backup/jobs/abc/run")
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_run_job_now_not_found(client, admin_session, tmp_path, monkeypatch):
    """Route returns 404 when run_job_now raises KeyError for a nonexistent job.

    The real run_job_now is called — it raises KeyError because the job list
    (loaded from an empty config file) contains no matching ID.
    """
    import app.backup_engine as engine
    monkeypatch.setattr(engine, "_CONFIG_PATH", tmp_path / "backup_config.json")
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")
    resp = _post(client, "/admin/api/backup/jobs/nonexistent-uuid/run")
    assert resp.status_code == 404


def test_job_status_endpoint(client, admin_session):
    status = {"id": "abc", "last_run": "2026-08-10T02:00:00", "runs": []}
    with mock.patch("app.routes.backup_routes.backup_scheduler.get_job_status",
                    return_value=status):
        resp = client.get("/admin/api/backup/jobs/abc/status")
    assert resp.status_code == 200
    assert resp.get_json()["id"] == "abc"


def test_job_status_not_found(client, admin_session):
    with mock.patch("app.routes.backup_routes.backup_scheduler.get_job_status",
                    side_effect=KeyError("not found")):
        resp = client.get("/admin/api/backup/jobs/missing/status")
    assert resp.status_code == 404
