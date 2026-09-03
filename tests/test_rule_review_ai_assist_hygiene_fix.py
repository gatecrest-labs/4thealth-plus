"""Tests for POST /api/rule-review/ai-assist-hygiene-fix."""
import io
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")


@pytest.fixture
def app():
    from app import create_app
    return create_app()


_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def client(app):
    with app.test_client() as c, \
         patch("app.auth._load_users", return_value=_TEST_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def _post_form(client, form, files=None):
    data = {**form}
    if files:
        data.update(files)
    return client.post(
        "/api/rule-review/ai-assist-hygiene-fix",
        data=data,
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": "test-csrf"},
    )


def test_hygiene_fix_disabled_by_default_returns_503(client):
    with patch("app.app_settings.get_setting", return_value=False):
        resp = _post_form(client, {"adom": "OT-ADOM", "pkg": "OT-Package", "findings_text": "[]"})
    assert resp.status_code == 503


def test_hygiene_fix_missing_adom_returns_400(client):
    with patch("app.app_settings.get_setting", return_value=True):
        resp = _post_form(client, {"pkg": "OT-Package", "findings_text": "[]"})
    assert resp.status_code == 400


def test_hygiene_fix_no_findings_returns_400(client):
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.decorators.check_adom_access", return_value=None):
        resp = _post_form(client, {"adom": "OT-ADOM", "pkg": "OT-Package", "findings_text": "[]"})
    assert resp.status_code == 400


def test_hygiene_fix_json_success_returns_fixes_and_narrative(client):
    findings = json.dumps([
        {"policy_id": "10", "policy_name": "r1", "check": "unlogged", "detail": "no logging"},
    ])
    live_policies = [{"policyid": 10, "name": "r1", "logtraffic": "disable", "comments": ""}]

    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.decorators.check_adom_access", return_value=None), \
         patch("app.routes.rule_review_routes.make_client") as mock_make_client, \
         patch("app.llm.get_provider") as mock_get_provider:
        mock_client = MagicMock()
        mock_client.get_policies.return_value = live_policies
        mock_make_client.return_value.__enter__.return_value = mock_client
        mock_get_provider.return_value.narrate.return_value = "Narrative text."

        resp = _post_form(client, {"adom": "OT-ADOM", "pkg": "OT-Package", "findings_text": findings})

    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["fixes"]) == 1
    assert data["fixes"][0]["check"] == "unlogged"
    assert data["stale_findings"] == []
    assert data["narrative"] == "Narrative text."
    assert data["narrative_error"] is None


def test_hygiene_fix_csv_upload_normalizes_check_label_to_key(client):
    csv_text = (
        "Seq,Policy ID,Policy Name,Check,Detail\r\n"
        "1,10,r1,Unlogged Rules (logging disabled),no logging\r\n"
    )
    live_policies = [{"policyid": 10, "name": "r1", "logtraffic": "disable", "comments": ""}]

    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.decorators.check_adom_access", return_value=None), \
         patch("app.routes.rule_review_routes.make_client") as mock_make_client, \
         patch("app.llm.get_provider") as mock_get_provider:
        mock_client = MagicMock()
        mock_client.get_policies.return_value = live_policies
        mock_make_client.return_value.__enter__.return_value = mock_client
        mock_get_provider.return_value.narrate.return_value = "Narrative text."

        resp = _post_form(
            client,
            {"adom": "OT-ADOM", "pkg": "OT-Package"},
            files={"findings_file": (io.BytesIO(csv_text.encode()), "findings.csv")},
        )

    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["fixes"]) == 1
    assert data["fixes"][0]["check"] == "unlogged"


def test_hygiene_fix_narration_failure_still_returns_fixes(client):
    findings = json.dumps([
        {"policy_id": "10", "policy_name": "r1", "check": "unlogged", "detail": "no logging"},
    ])
    live_policies = [{"policyid": 10, "name": "r1", "logtraffic": "disable", "comments": ""}]

    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.decorators.check_adom_access", return_value=None), \
         patch("app.routes.rule_review_routes.make_client") as mock_make_client, \
         patch("app.llm.get_provider", side_effect=RuntimeError("no provider configured")):
        mock_client = MagicMock()
        mock_client.get_policies.return_value = live_policies
        mock_make_client.return_value.__enter__.return_value = mock_client

        resp = _post_form(client, {"adom": "OT-ADOM", "pkg": "OT-Package", "findings_text": findings})

    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["fixes"]) == 1
    assert data["narrative"] is None
    assert "no provider configured" in data["narrative_error"]
