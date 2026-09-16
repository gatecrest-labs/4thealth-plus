"""Tests for app/backup_scheduler.py"""
import datetime
import json
from unittest import mock

import pytest


def _make_job(**overrides):
    job = {
        "name": "Test Backup",
        "days_of_week": ["MON"],
        "time": "02:00",
        "enabled": True,
    }
    job.update(overrides)
    return job


# ── Job CRUD ──────────────────────────────────────────────────────────────────

def test_create_job_assigns_uuid(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")
    (tmp_path / "backup_config.json").write_text(json.dumps(
        {"password": "pw", "backup_dir": str(tmp_path), "max_files": 20,
         "exclude_tls_key": False, "ftp": {}, "jobs": []}
    ))

    job = sched.create_job(_make_job())
    assert "id" in job
    assert len(job["id"]) == 36  # UUID


def test_create_job_persists(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")
    (tmp_path / "backup_config.json").write_text(json.dumps(
        {"password": "pw", "backup_dir": str(tmp_path), "max_files": 20,
         "exclude_tls_key": False, "ftp": {}, "jobs": []}
    ))

    sched.create_job(_make_job())
    jobs = sched.get_all_jobs()
    assert len(jobs) == 1
    assert jobs[0]["name"] == "Test Backup"


def test_update_job(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")
    (tmp_path / "backup_config.json").write_text(json.dumps(
        {"password": "pw", "backup_dir": str(tmp_path), "max_files": 20,
         "exclude_tls_key": False, "ftp": {}, "jobs": []}
    ))

    job = sched.create_job(_make_job())
    updated = sched.update_job(job["id"], _make_job(name="Updated", days_of_week=["TUE"]))
    assert updated["name"] == "Updated"
    assert updated["days_of_week"] == ["TUE"]


def test_delete_job(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")
    (tmp_path / "backup_config.json").write_text(json.dumps(
        {"password": "pw", "backup_dir": str(tmp_path), "max_files": 20,
         "exclude_tls_key": False, "ftp": {}, "jobs": []}
    ))

    job = sched.create_job(_make_job())
    sched.delete_job(job["id"])
    assert sched.get_all_jobs() == []


def test_update_job_not_found_raises(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")
    (tmp_path / "backup_config.json").write_text(json.dumps(
        {"password": "pw", "backup_dir": str(tmp_path), "max_files": 20,
         "exclude_tls_key": False, "ftp": {}, "jobs": []}
    ))

    with pytest.raises(KeyError):
        sched.update_job("nonexistent-id", _make_job())


def test_validate_days_rejects_invalid(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")
    (tmp_path / "backup_config.json").write_text(json.dumps(
        {"password": "pw", "backup_dir": str(tmp_path), "max_files": 20,
         "exclude_tls_key": False, "ftp": {}, "jobs": []}
    ))

    with pytest.raises(ValueError):
        sched.create_job(_make_job(days_of_week=["MONDAY"]))


def test_validate_time_rejects_invalid(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")
    (tmp_path / "backup_config.json").write_text(json.dumps(
        {"password": "pw", "backup_dir": str(tmp_path), "max_files": 20,
         "exclude_tls_key": False, "ftp": {}, "jobs": []}
    ))

    with pytest.raises(ValueError):
        sched.create_job(_make_job(time="25:99"))


# ── Run history ───────────────────────────────────────────────────────────────

def test_run_history_pruned_after_30_days(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")

    old_run = {
        "started_at": (datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(days=31)).isoformat() + "Z",
        "status": "success", "filename": "old.zip", "transferred": False,
    }
    recent_run = {
        "started_at": datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z",
        "status": "success", "filename": "new.zip", "transferred": False,
    }
    job_id = "test-id-123"
    (tmp_path / "backup_config.json").write_text(json.dumps({
        "password": "pw", "backup_dir": str(tmp_path), "max_files": 20,
        "exclude_tls_key": False, "ftp": {}, "jobs": [
            {"id": job_id, "name": "T", "days_of_week": ["MON"], "time": "02:00",
             "enabled": True, "runs": [old_run, recent_run]}
        ]
    }))

    sched._prune_runs(job_id)
    jobs = sched.get_all_jobs()
    runs = jobs[0]["runs"]
    assert len(runs) == 1
    assert runs[0]["filename"] == "new.zip"


# ── _execute_job ──────────────────────────────────────────────────────────────

def test_execute_job_calls_create_backup(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    job_id = "exec-test-id"
    (tmp_path / "backup_config.json").write_text(json.dumps({
        "password": "pw", "backup_dir": str(tmp_path / "bk"), "max_files": 20,
        "exclude_tls_key": False,
        "ftp": {"enabled": False, "protocol": "sftp", "host": "", "port": 22,
                "username": "", "password": "", "remote_dir": "/"},
        "jobs": [{"id": job_id, "name": "T", "days_of_week": ["MON"],
                  "time": "02:00", "enabled": True, "runs": []}]
    }))
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")

    fake_path = tmp_path / "bk" / "SERVER-BACKUP_2026-08-10_0200.zip"
    fake_path.parent.mkdir(parents=True, exist_ok=True)
    fake_path.write_bytes(b"fake")

    with mock.patch("app.backup_scheduler.backup_engine.create_backup",
                    return_value=(fake_path, fake_path.name)) as mock_create:
        sched._execute_job(job_id)

    mock_create.assert_called_once()


def test_execute_job_records_success(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    job_id = "record-test-id"
    (tmp_path / "backup_config.json").write_text(json.dumps({
        "password": "pw", "backup_dir": str(tmp_path / "bk"), "max_files": 20,
        "exclude_tls_key": False,
        "ftp": {"enabled": False, "protocol": "sftp", "host": "", "port": 22,
                "username": "", "password": "", "remote_dir": "/"},
        "jobs": [{"id": job_id, "name": "T", "days_of_week": ["MON"],
                  "time": "02:00", "enabled": True, "runs": []}]
    }))
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")

    fake_path = tmp_path / "bk" / "SERVER-BACKUP_2026-08-10_0200.zip"
    fake_path.parent.mkdir(parents=True, exist_ok=True)
    fake_path.write_bytes(b"fake")

    with mock.patch("app.backup_scheduler.backup_engine.create_backup",
                    return_value=(fake_path, fake_path.name)):
        sched._execute_job(job_id)

    import json as j
    cfg = j.loads((tmp_path / "backup_config.json").read_text())
    job = next(jb for jb in cfg["jobs"] if jb["id"] == job_id)
    assert len(job["runs"]) == 1
    assert job["runs"][0]["status"] == "success"


def test_execute_job_records_failure(tmp_path, monkeypatch):
    import app.backup_scheduler as sched
    job_id = "fail-test-id"
    (tmp_path / "backup_config.json").write_text(json.dumps({
        "password": "pw", "backup_dir": str(tmp_path / "bk"), "max_files": 20,
        "exclude_tls_key": False,
        "ftp": {"enabled": False, "protocol": "sftp", "host": "", "port": 22,
                "username": "", "password": "", "remote_dir": "/"},
        "jobs": [{"id": job_id, "name": "T", "days_of_week": ["MON"],
                  "time": "02:00", "enabled": True, "runs": []}]
    }))
    monkeypatch.setattr(sched, "_CONFIG_PATH", tmp_path / "backup_config.json")

    with mock.patch("app.backup_scheduler.backup_engine.create_backup",
                    side_effect=OSError("disk full")):
        sched._execute_job(job_id)

    import json as j
    cfg = j.loads((tmp_path / "backup_config.json").read_text())
    job = next(jb for jb in cfg["jobs"] if jb["id"] == job_id)
    assert job["runs"][0]["status"] == "failed"
    assert "disk full" in job["runs"][0]["detail"]


# ── transfer_file ─────────────────────────────────────────────────────────────

def test_transfer_sftp_calls_paramiko(tmp_path):
    import app.backup_scheduler as sched
    fake_file = tmp_path / "SERVER-BACKUP_2026-08-10_0200.zip"
    fake_file.write_bytes(b"data")

    ftp_cfg = {"protocol": "sftp", "host": "backup.example.com", "port": 22,
               "username": "user", "password": "pass", "remote_dir": "/backups"}

    with mock.patch("paramiko.SSHClient") as mock_ssh_cls:
        mock_ssh = mock.MagicMock()
        mock_ssh_cls.return_value = mock_ssh
        mock_sftp = mock.MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        sched.transfer_file(ftp_cfg, fake_file, fake_file.name)

    mock_ssh.connect.assert_called_once_with(
        "backup.example.com", port=22, username="user", password="pass", timeout=30
    )
    mock_sftp.put.assert_called_once_with(
        str(fake_file), "/backups/SERVER-BACKUP_2026-08-10_0200.zip"
    )


def test_transfer_scp_calls_scpclient(tmp_path):
    import app.backup_scheduler as sched
    fake_file = tmp_path / "SERVER-BACKUP_2026-08-10_0200.zip"
    fake_file.write_bytes(b"data")

    ftp_cfg = {"protocol": "scp", "host": "backup.example.com", "port": 22,
               "username": "user", "password": "pass", "remote_dir": "/backups"}

    with mock.patch("paramiko.SSHClient") as mock_ssh_cls, \
         mock.patch("scp.SCPClient") as mock_scp_cls:
        mock_ssh = mock.MagicMock()
        mock_ssh_cls.return_value = mock_ssh
        mock_scp = mock.MagicMock()
        mock_scp_cls.return_value.__enter__ = lambda s: mock_scp
        mock_scp_cls.return_value.__exit__ = mock.MagicMock(return_value=False)

        sched.transfer_file(ftp_cfg, fake_file, fake_file.name)

    mock_ssh.connect.assert_called_once_with(
        "backup.example.com", port=22, username="user", password="pass", timeout=30
    )
    mock_scp.put.assert_called_once_with(
        str(fake_file), "/backups/SERVER-BACKUP_2026-08-10_0200.zip"
    )


def test_transfer_ftp_calls_ftplib(tmp_path):
    import app.backup_scheduler as sched
    fake_file = tmp_path / "SERVER-BACKUP_2026-08-10_0200.zip"
    fake_file.write_bytes(b"data")

    ftp_cfg = {"protocol": "ftp", "host": "ftp.example.com", "port": 21,
               "username": "user", "password": "pass", "remote_dir": "/backups"}

    with mock.patch("ftplib.FTP") as mock_ftp_cls:
        mock_ftp = mock.MagicMock()
        mock_ftp_cls.return_value.__enter__ = lambda s: mock_ftp
        mock_ftp_cls.return_value.__exit__ = mock.MagicMock(return_value=False)

        sched.transfer_file(ftp_cfg, fake_file, fake_file.name)

    mock_ftp.connect.assert_called_once_with("ftp.example.com", 21, timeout=30)
    mock_ftp.login.assert_called_once_with("user", "pass")
