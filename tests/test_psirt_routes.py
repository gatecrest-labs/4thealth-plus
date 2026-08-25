"""Tests for PSIRT extract/assess/report routes."""
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest

from app.llm.base import LLMProvider


class _FakeProvider(LLMProvider):
    """Real LLMProvider so extract_json()'s concrete parsing logic runs for
    real against a canned narrate() response, instead of a bare MagicMock
    stubbing extract_json() itself (which would skip that logic)."""

    def __init__(self, narrate_return):
        self._narrate_return = narrate_return

    def narrate(self, system_prompt, user_prompt):
        return self._narrate_return


@pytest.fixture
def app():
    os.environ.setdefault("SECRET_KEY", "test-secret")
    os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")
    from app import create_app
    return create_app()


_TEST_USERS = {
    "admin": {"password_hash": "$2b$12$placeholder", "role": "admin"},
    "viewer1": {"password_hash": "$2b$12$placeholder", "role": "viewer"},
}


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


def _post(client, url, payload):
    return client.post(url, data=json.dumps(payload), content_type="application/json",
                        headers={"X-CSRF-Token": "test-csrf"})


_VALID_EXTRACTION_JSON = json.dumps({
    "advisory_id": "FG-IR-24-001",
    "cve_ids": ["CVE-2024-12345"],
    "affected_ranges": [{"product": "FortiOS", "max_version": "7.4.4", "fixed_version": "7.4.5"}],
    "workaround_text": "",
})


def test_extract_status_reports_disabled_by_default(client):
    resp = client.get("/api/device-review/psirt/extract-status")
    assert resp.status_code == 200
    assert resp.get_json()["available"] is False


def test_extract_status_reports_enabled(client):
    with patch("app.routes.psirt_routes.get_setting", return_value=True):
        resp = client.get("/api/device-review/psirt/extract-status")
    assert resp.get_json()["available"] is True


def test_extract_returns_503_when_disabled(client):
    resp = _post(client, "/api/device-review/psirt/extract", {"email_text": "some advisory"})
    assert resp.status_code == 503


def test_extract_requires_email_text(client):
    with patch("app.routes.psirt_routes.get_setting", return_value=True):
        resp = _post(client, "/api/device-review/psirt/extract", {"email_text": ""})
    assert resp.status_code == 400


def test_extract_happy_path(client):
    fake_provider = _FakeProvider(_VALID_EXTRACTION_JSON)
    with patch("app.routes.psirt_routes.get_setting", return_value=True), \
         patch("app.routes.psirt_routes.get_provider", return_value=fake_provider):
        resp = _post(client, "/api/device-review/psirt/extract", {"email_text": "PSIRT advisory text"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["advisory"]["advisory_id"] == "FG-IR-24-001"


def test_extract_malformed_llm_output_returns_422(client):
    fake_provider = _FakeProvider('{"advisory_id": ""}')  # missing required fields
    with patch("app.routes.psirt_routes.get_setting", return_value=True), \
         patch("app.routes.psirt_routes.get_provider", return_value=fake_provider):
        resp = _post(client, "/api/device-review/psirt/extract", {"email_text": "garbled text"})
    assert resp.status_code == 422
    data = resp.get_json()
    assert data["field"] == "advisory_id"


def test_assess_device_requires_adom_and_device(client):
    resp = _post(client, "/api/device-review/psirt/assess/device", {"advisory": {}})
    assert resp.status_code == 400


def test_assess_device_happy_path(client):
    fake_fmg = MagicMock()
    fake_fmg.get_devices.return_value = [{"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"}]
    fake_fmg.get_adoms.return_value = [{"name": "Corp"}]
    cm = MagicMock()
    cm.__enter__.return_value = fake_fmg
    cm.__exit__.return_value = False
    advisory_payload = {
        "advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"],
        "affected_ranges": [{"product": "FortiOS", "max_version": "7.4.4", "fixed_version": "7.4.5"}],
        "workaround_text": "", "exploited_in_wild_text": "", "cvss_score": 8.1,
        "advisory_url": "", "published_date": "", "fortinet_severity": "", "description": "",
        "enrichment_degraded": False,
    }
    with patch("app.routes.psirt_routes.make_client", return_value=cm):
        resp = _post(client, "/api/device-review/psirt/assess/device",
                      {"adom": "Corp", "device": "FW01", "advisory": advisory_payload})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["finding"]["device"] == "FW01"
    assert data["finding"]["verdict"] == "upgrade_required"


def test_assess_device_checks_adom_access(client):
    with patch("app.groups.user_can_access_adom", return_value=False), \
         patch("app.groups.get_allowed_tabs", return_value={"device_review"}):
        with client.session_transaction() as sess:
            sess["user"] = "viewer1"
            sess["role"] = "viewer"
        resp = _post(client, "/api/device-review/psirt/assess/device",
                      {"adom": "Restricted", "device": "FW01", "advisory": {}})
    assert resp.status_code == 403


def test_report_returns_html(client):
    advisory_payload = {
        "advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"],
        "affected_ranges": [{"product": "FortiOS", "max_version": "7.4.4", "fixed_version": "7.4.5"}],
        "workaround_text": "", "exploited_in_wild_text": "", "cvss_score": 8.1,
        "advisory_url": "", "published_date": "", "fortinet_severity": "", "description": "",
        "enrichment_degraded": False,
    }
    assessment_payload = {
        "advisory": advisory_payload,
        "findings": [{"device": "FW01", "adom": "Corp", "product": "FortiOS",
                       "current_version": "7.4.2", "in_range": True,
                       "workaround_status": "not_applicable", "verdict": "upgrade_required",
                       "reason": "affected"}],
        "out_of_scope_products": [], "priority": "high", "priority_rationale": "CVSS 8.1",
        "kev_hit": False, "degraded": False, "warnings": [],
    }
    resp = _post(client, "/api/device-review/psirt/report", {"assessment": assessment_payload})
    assert resp.status_code == 200
    assert b"FG-IR-24-001" in resp.data
    assert b"FW01" in resp.data
