"""Enqueue through the API, run by the real runner, read the result (Phase 6)."""

import json
import time
from unittest.mock import patch

import pytest

from app import job_runner
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

_USERS = {"admin": {"password_hash": "x", "role": "admin"}}


@pytest.fixture
def rig(monkeypatch):
    for k, v in (
        ("INVENTORY_CACHE", False),
        ("AUDIT_SNAPSHOTS", False),
        ("POLICY_STORE", False),
        ("JOB_QUEUE", True),
        ("JOB_MAX_RUNNING", 2),
    ):
        monkeypatch.setattr(Config, k, v)
    monkeypatch.setattr(job_runner, "_active", 0)
    synth = SyntheticFMG(
        adoms=1, devices=3, packages_per_adom=1, rules_per_package=5, seed=8
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    for mod in (
        "app.routes.audit_review_routes.make_client",
        "app.routes.hygiene_routes.make_client",
        "app.fmg_helpers.make_client",
    ):
        monkeypatch.setattr(mod, lambda: real)
    return next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )


@pytest.fixture
def http():
    from app import create_app

    with (
        create_app().test_client() as c,
        patch("app.auth._load_users", return_value=_USERS),
    ):
        with c.session_transaction() as s:
            s["user"], s["role"], s["_csrf_token"], s["login_at"] = (
                "admin",
                "admin",
                "t",
                int(time.time()),
            )
        yield c


def _post(c, url, payload):
    return c.post(
        url,
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-CSRF-Token": "t"},
    )


def test_device_review_job_end_to_end(rig, http):
    adom = rig
    jid = _post(http, "/api/jobs", {"kind": "device_review", "adom": adom}).get_json()[
        "id"
    ]
    assert http.get(f"/api/jobs/{jid}").get_json()["status"] == "queued"
    assert job_runner.tick(submit=job_runner._run_and_release) == 1
    body = http.get(f"/api/jobs/{jid}").get_json()
    sync = _post(
        http, "/api/audit-review/run", {"adom": adom, "devices": [], "check_params": {}}
    ).get_json()
    assert body["status"] == "done" and body["done"] == body["total"] == 3
    assert (
        body["result"]["rows"] == sync["rows"]
        and body["result"]["total"] == sync["total"] > 0
    )
