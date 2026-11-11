"""Job queue UI hooks (Phase 6, Task 5)."""

import shutil
import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from app.config import Config

_USERS = {"admin": {"password_hash": "x", "role": "admin"}}
_JS = (
    Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "audit_review.js"
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


def test_job_flag_script_only_when_enabled(monkeypatch, http):
    monkeypatch.setattr(Config, "JOB_QUEUE", True)
    assert "window._jobQueue = true" in http.get("/audit-review").get_data(as_text=True)
    monkeypatch.setattr(Config, "JOB_QUEUE", False)
    assert "_jobQueue" not in http.get("/audit-review").get_data(as_text=True)


def test_js_keeps_the_legacy_paths_and_adds_the_job_flow():
    js = _JS.read_text()
    # legacy per-device loop and synchronous hygiene call are still there for flag off
    assert "/api/audit-review/run/device" in js and "fetch('/api/hygiene/run'" in js
    # job flow is gated on the page flag
    assert js.count("window._jobQueue") >= 3 and "/api/jobs" in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_js_parses():
    subprocess.run(["node", "--check", str(_JS)], check=True)


def test_stale_resume_key_is_forgotten_and_scoped_to_the_user():
    js = _JS.read_text()
    poll = js[
        js.index("async function pollJob") : js.index("function jobRowsToCollected")
    ]
    assert "r.status === 404) { forgetJob();" in poll
    assert "window._jobUser" in js
