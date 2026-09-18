"""Tests for /admin/api/rule-policy/* endpoints in admin_routes.py."""
import json
import time
from unittest import mock

import pytest

from app import create_app


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_session(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["_csrf_token"] = "test-csrf"
        sess["login_at"] = int(time.time())
    yield


@pytest.fixture(autouse=True)
def tmp_jobs(tmp_path, monkeypatch):
    """Redirect the scheduler's jobs file to a temp path for test isolation."""
    import app.rule_policy_scheduler as sched
    monkeypatch.setattr(sched, "_JOBS_PATH", tmp_path / "rule_policy_jobs.json")
    yield


# ── Helpers ───────────────────────────────────────────────────────────────────


def _csrf():
    return {"X-CSRF-Token": "test-csrf"}


def _post(client, url, payload=None):
    kwargs = {"headers": _csrf()}
    if payload is not None:
        kwargs["data"] = json.dumps(payload)
        kwargs["content_type"] = "application/json"
    return client.post(url, **kwargs)


def _put(client, url, payload=None):
    kwargs = {"headers": _csrf()}
    if payload is not None:
        kwargs["data"] = json.dumps(payload)
        kwargs["content_type"] = "application/json"
    return client.put(url, **kwargs)


def _delete(client, url):
    return client.delete(url, headers=_csrf())


def _valid_job(**overrides):
    base = {
        "name": "Test RP Job",
        "adom": "Corp",
        "packages": [],
        "schedule_type": "weekly",
        "days_of_week": ["MON"],
        "monthly_position": "beginning",
        "time": "02:00",
        "format": "html",
        "batch_size": 10,
        "email": "test@example.com",
        "enabled": False,
    }
    base.update(overrides)
    return base


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_list_jobs_empty(client, admin_session):
    resp = client.get("/admin/api/rule-policy/jobs")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data == []


def test_create_and_list_job(client, admin_session):
    # Create
    resp = _post(client, "/admin/api/rule-policy/jobs", _valid_job())
    assert resp.status_code == 201
    job = resp.get_json()
    assert job["name"] == "Test RP Job"
    assert "id" in job

    # List
    resp2 = client.get("/admin/api/rule-policy/jobs")
    assert resp2.status_code == 200
    jobs = resp2.get_json()
    assert len(jobs) == 1
    assert jobs[0]["id"] == job["id"]


def test_update_job_not_found(client, admin_session):
    resp = _put(client, "/admin/api/rule-policy/jobs/nonexistent-id", _valid_job(name="Updated"))
    assert resp.status_code == 404
    assert "error" in resp.get_json()


def test_delete_job(client, admin_session):
    # Create a job first
    create_resp = _post(client, "/admin/api/rule-policy/jobs", _valid_job())
    assert create_resp.status_code == 201
    job_id = create_resp.get_json()["id"]

    # Delete it
    del_resp = _delete(client, f"/admin/api/rule-policy/jobs/{job_id}")
    assert del_resp.status_code == 200
    assert del_resp.get_json() == {"ok": True}

    # Confirm it's gone
    list_resp = client.get("/admin/api/rule-policy/jobs")
    assert list_resp.get_json() == []


def test_run_job_starts_thread(client, admin_session):
    # Create a job first
    create_resp = _post(client, "/admin/api/rule-policy/jobs", _valid_job())
    job_id = create_resp.get_json()["id"]

    import app.rule_policy_scheduler as sched
    with mock.patch.object(sched, "run_job_now") as mock_run:
        resp = _post(client, f"/admin/api/rule-policy/jobs/{job_id}/run")
        assert resp.status_code == 202
        data = resp.get_json()
        assert data.get("ok") is True
        mock_run.assert_called_once_with(job_id)
