"""Tests for /api/zone/backup (download) and /api/zone/restore (upload + validate)."""

import io
import json
import time

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def admin_session(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["_csrf_token"] = "test-csrf"
        sess["login_at"] = int(time.time())


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    import app.zone_db as zdb

    path = tmp_path / "policy_db.json"
    path.write_text(json.dumps({"zones": {}, "policies": []}))
    monkeypatch.setattr(zdb, "DB_PATH", path)
    return path


_CSRF = {"X-CSRF-Token": "test-csrf"}


def _upload(client, payload: bytes):
    return client.post(
        "/api/zone/restore",
        headers=_CSRF,
        data={"file": (io.BytesIO(payload), "backup.json")},
        content_type="multipart/form-data",
    )


def test_backup_returns_file_download_and_keeps_server_copy(
    client, admin_session, db_path
):
    resp = client.post("/api/zone/backup", headers=_CSRF)
    assert resp.status_code == 200
    assert "attachment" in resp.headers["Content-Disposition"]
    assert json.loads(resp.data) == {"zones": {}, "policies": []}
    assert len(list((db_path.parent / "backups").glob("policy_db_*.json"))) == 1


def test_restore_overwrites_db_and_backs_up_current(client, admin_session, db_path):
    new_db = {"zones": {"A": {"subnets": []}}, "policies": []}
    resp = _upload(client, json.dumps(new_db).encode())
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
    assert json.loads(db_path.read_text()) == new_db
    prerestore = list((db_path.parent / "backups").glob("*_prerestore.json"))
    assert len(prerestore) == 1
    assert json.loads(prerestore[0].read_text()) == {"zones": {}, "policies": []}


def test_restore_rejects_invalid_json_and_leaves_db_untouched(
    client, admin_session, db_path
):
    resp = _upload(client, b"not json")
    assert resp.status_code == 400
    assert json.loads(db_path.read_text()) == {"zones": {}, "policies": []}


@pytest.mark.parametrize(
    "bad",
    [
        [1, 2],
        {"zones": [], "policies": []},
        {"zones": {"A": "oops"}, "policies": []},
        {"zones": {}, "policies": ["oops"]},
    ],
)
def test_restore_rejects_malformed_database(client, admin_session, db_path, bad):
    resp = _upload(client, json.dumps(bad).encode())
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False
    assert json.loads(db_path.read_text()) == {"zones": {}, "policies": []}


def test_restore_requires_file(client, admin_session, db_path):
    resp = client.post("/api/zone/restore", headers=_CSRF)
    assert resp.status_code == 400
