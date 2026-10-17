"""Tests for the unauthenticated GET /api/health liveness endpoint."""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")

from app import create_app


def test_health_ok_without_session():
    app = create_app()
    app.config["TESTING"] = True
    resp = app.test_client().get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}
