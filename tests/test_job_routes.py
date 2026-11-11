"""Job endpoints: authorization is the point (Phase 6, Task 4)."""

import json
import time
from unittest.mock import patch

import pytest

from app import job_store
from app.config import Config

_USERS = {
    "admin": {"password_hash": "x", "role": "admin"},
    "alice": {"password_hash": "x", "role": "viewer"},
    "bob": {"password_hash": "x", "role": "viewer"},
}


@pytest.fixture(autouse=True)
def _cfg(monkeypatch):
    monkeypatch.setattr(Config, "JOB_QUEUE", True)
    monkeypatch.setattr(Config, "JOB_MAX_QUEUED_PER_USER", 2)


@pytest.fixture
def app():
    from app import create_app

    return create_app()


def _client(app, user, role="viewer", tabs=("audit_review",)):
    c = app.test_client()
    with c.session_transaction() as s:
        s["user"], s["role"], s["allowed_tabs"] = user, role, list(tabs)
        s["_csrf_token"], s["login_at"] = "t", int(time.time())
    return c


_TABS = {"alice": {"audit_review"}, "bob": {"audit_review"}, "carol": {"versions"}}


@pytest.fixture(autouse=True)
def _users():
    users = {**_USERS, "carol": {"password_hash": "x", "role": "viewer"}}
    with (
        patch("app.auth._load_users", return_value=users),
        patch(
            "app.groups.get_allowed_tabs",
            lambda user, ad_groups=None, role=None: _TABS.get(user, set()),
        ),
    ):
        yield


def _post(c, url, payload=None):
    return c.post(
        url,
        data=json.dumps(payload or {}),
        content_type="application/json",
        headers={"X-CSRF-Token": "t"},
    )


def _allow(monkeypatch, allowed):
    """Restrict non-admin ADOM access to *allowed* (a set)."""
    monkeypatch.setattr(
        "app.groups.user_can_access_adom",
        lambda user, adom, ad_groups=None: adom in allowed,
    )


def test_flag_off_is_503_everywhere(app, monkeypatch):
    monkeypatch.setattr(Config, "JOB_QUEUE", False)
    c = _client(app, "alice")
    assert (
        _post(c, "/api/jobs", {"kind": "device_review", "adom": "A"}).status_code == 503
    )
    assert c.get("/api/jobs").status_code == 503
    assert c.get("/api/jobs/x").status_code == 503
    assert _post(c, "/api/jobs/x/cancel").status_code == 503


def test_requires_login_and_tab(app):
    assert app.test_client().get("/api/jobs").status_code == 401
    c = _client(app, "carol")
    assert c.get("/api/jobs").status_code == 403
    assert (
        _post(c, "/api/jobs", {"kind": "device_review", "adom": "A"}).status_code == 403
    )


def test_create_validates_and_checks_adom_access(app, monkeypatch):
    _allow(monkeypatch, {"A"})
    c = _client(app, "alice")
    assert _post(c, "/api/jobs", {"kind": "bogus", "adom": "A"}).status_code == 400
    assert _post(c, "/api/jobs", {"kind": "device_review"}).status_code == 400
    assert (
        _post(c, "/api/jobs", {"kind": "device_review", "adom": "Other"}).status_code
        == 403
    )
    r = _post(
        c, "/api/jobs", {"kind": "device_review", "adom": "A", "checks": ["ntp_config"]}
    )
    assert r.status_code == 202
    j = job_store.get(r.get_json()["id"])
    assert (
        j["owner"] == "alice"
        and j["adom"] == "A"
        and j["request"]["checks"] == ["ntp_config"]
    )


def test_queue_cap_is_429(app, monkeypatch):
    _allow(monkeypatch, {"A"})
    c = _client(app, "alice")
    for _ in range(2):
        assert (
            _post(c, "/api/jobs", {"kind": "device_review", "adom": "A"}).status_code
            == 202
        )
    assert (
        _post(c, "/api/jobs", {"kind": "device_review", "adom": "A"}).status_code == 429
    )


def test_users_cannot_see_or_cancel_each_others_jobs(app, monkeypatch):
    _allow(monkeypatch, {"A"})
    alice, bob = _client(app, "alice"), _client(app, "bob")
    jid = _post(alice, "/api/jobs", {"kind": "device_review", "adom": "A"}).get_json()[
        "id"
    ]
    assert bob.get(f"/api/jobs/{jid}").status_code == 404
    assert _post(bob, f"/api/jobs/{jid}/cancel").status_code == 404
    assert bob.get("/api/jobs").get_json()["jobs"] == []
    assert job_store.get(jid)["status"] == "queued"  # bob's cancel did nothing
    assert alice.get(f"/api/jobs/{jid}").status_code == 200
    assert [j["id"] for j in alice.get("/api/jobs").get_json()["jobs"]] == [jid]


def test_unknown_id_and_foreign_id_are_indistinguishable(app, monkeypatch):
    _allow(monkeypatch, {"A"})
    alice, bob = _client(app, "alice"), _client(app, "bob")
    jid = _post(alice, "/api/jobs", {"kind": "device_review", "adom": "A"}).get_json()[
        "id"
    ]
    a, b = bob.get(f"/api/jobs/{jid}"), bob.get("/api/jobs/doesnotexist")
    assert a.status_code == b.status_code == 404 and a.get_json() == b.get_json()


def test_admin_sees_and_cancels_everyones_jobs(app, monkeypatch):
    _allow(monkeypatch, {"A"})
    alice, admin = _client(app, "alice"), _client(app, "admin", role="admin")
    jid = _post(alice, "/api/jobs", {"kind": "device_review", "adom": "A"}).get_json()[
        "id"
    ]
    assert [j["id"] for j in admin.get("/api/jobs").get_json()["jobs"]] == [jid]
    assert admin.get(f"/api/jobs/{jid}").status_code == 200
    assert _post(admin, f"/api/jobs/{jid}/cancel").get_json()["state"] == "cancelled"


def test_job_hidden_once_the_adom_is_no_longer_accessible(app, monkeypatch):
    _allow(monkeypatch, {"A"})
    alice = _client(app, "alice")
    jid = _post(alice, "/api/jobs", {"kind": "device_review", "adom": "A"}).get_json()[
        "id"
    ]
    _allow(monkeypatch, set())
    assert alice.get(f"/api/jobs/{jid}").status_code == 404
    assert alice.get("/api/jobs").get_json()["jobs"] == []
    assert _post(alice, f"/api/jobs/{jid}/cancel").status_code == 404


def test_get_returns_result_but_never_the_request_and_list_has_no_blobs(
    app, monkeypatch
):
    _allow(monkeypatch, {"A"})
    alice = _client(app, "alice")
    jid = _post(alice, "/api/jobs", {"kind": "device_review", "adom": "A"}).get_json()[
        "id"
    ]
    job_store.claim_next()
    job_store.finish(jid, {"rows": [1]})
    body = alice.get(f"/api/jobs/{jid}").get_json()
    assert (
        body["status"] == "done"
        and body["result"] == {"rows": [1]}
        and "request" not in body
    )
    listed = alice.get("/api/jobs").get_json()["jobs"][0]
    assert "result" not in listed and "request" not in listed


def test_cancel_states(app, monkeypatch):
    _allow(monkeypatch, {"A"})
    alice = _client(app, "alice")
    jid = _post(alice, "/api/jobs", {"kind": "device_review", "adom": "A"}).get_json()[
        "id"
    ]
    job_store.claim_next()
    assert _post(alice, f"/api/jobs/{jid}/cancel").get_json()["state"] == "requested"
    job_store.finish(jid, {}, cancelled=True)
    assert _post(alice, f"/api/jobs/{jid}/cancel").get_json()["state"] == "finished"
