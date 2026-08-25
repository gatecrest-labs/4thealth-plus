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


_STAR_ADVISORY_PAYLOAD = {
    "advisory_id": "FG-IR-24-001", "cve_ids": ["CVE-2024-12345"],
    "affected_ranges": [{"product": "FortiOS", "max_version": "7.4.4", "fixed_version": "7.4.5"}],
    "workaround_text": "", "exploited_in_wild_text": "", "cvss_score": 8.1,
    "advisory_url": "", "published_date": "", "fortinet_severity": "", "description": "",
    "enrichment_degraded": False,
}


def test_assess_bulk_star_unrestricted_user_reaches_engine_with_star_scope(client):
    """Finding #9: an unrestricted (admin) user's adom='*' request must
    resolve to a single engine.assess() call with adom_scope='*' and must
    never touch get_allowed_adoms's restricted-list branch."""
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    fake_result = MagicMock()
    fake_result.to_dict.return_value = {"ok": True}
    # admin (the logged-in test user) is unrestricted, so get_allowed_adoms
    # legitimately returns None here — no need to mock it separately.
    with patch("app.routes.psirt_routes.make_client", return_value=cm), \
         patch("app.routes.psirt_routes.psirt_assess", return_value=fake_result) as mock_assess:
        resp = _post(client, "/api/device-review/psirt/assess",
                      {"adom": "*", "advisory": _STAR_ADVISORY_PAYLOAD})
    assert resp.status_code == 200
    mock_assess.assert_called_once()
    args, _kwargs = mock_assess.call_args
    assert args[2] == "*"  # adom_scope


def test_assess_bulk_star_restricted_user_no_adoms_returns_clean_403(client):
    """Finding #2: a restricted user with zero accessible ADOMs must get a
    clean 403 JSON error, not an unhandled 500 from merged.to_dict() on None."""
    with patch("app.groups.get_allowed_adoms", return_value=[]), \
         patch("app.groups.get_allowed_tabs", return_value={"device_review"}):
        with client.session_transaction() as sess:
            sess["user"] = "viewer1"
            sess["role"] = "viewer"
        resp = _post(client, "/api/device-review/psirt/assess",
                      {"adom": "*", "advisory": _STAR_ADVISORY_PAYLOAD})
    assert resp.status_code == 403
    data = resp.get_json()
    assert "error" in data
    assert "no accessible ADOMs" in data["error"]


def test_assess_bulk_star_restricted_user_merges_two_adoms(client):
    """Finding #9: a restricted user with 2 allowed ADOMs must get a
    priority recomputed over the union of both ADOMs' findings.
    Finding #6: enrichment/KEV must happen exactly once (not once per ADOM),
    and a FortiManager finding named by the advisory must appear exactly
    once in the merged findings, not once per ADOM."""
    fake_fmg = MagicMock()
    fake_fmg.get_system_status.return_value = {"Version": "v7.4.5,build2360,240702 (GA)"}

    def _devices(adom):
        return [{"name": f"FW-{adom}", "os_ver": "7.0", "mr": "4", "patch": "2"}]
    fake_fmg.get_devices.side_effect = _devices
    cm = MagicMock()
    cm.__enter__.return_value = fake_fmg
    cm.__exit__.return_value = False

    def _fake_resp(status_code=200, json_data=None, text=""):
        r = MagicMock()
        r.status_code = status_code
        r.json.return_value = json_data or {}
        r.text = text
        return r

    mock_http = MagicMock()
    mock_http.get.side_effect = [
        _fake_resp(text="CVSS Score: 8.1. Severity: High."),  # advisory page
        _fake_resp(json_data={"vulnerabilities": []}),         # KEV feed
    ]

    advisory_payload = dict(_STAR_ADVISORY_PAYLOAD)
    advisory_payload["advisory_url"] = "https://fortiguard.com/psirt/FG-IR-24-001"
    # Advisory also names FortiManager as affected — engine.assess() appends
    # a "FortiManager (primary)" finding on every per-ADOM call unless the
    # route dedupes it in the merge.
    advisory_payload["affected_ranges"] = [
        {"product": "FortiOS", "max_version": "7.4.4", "fixed_version": "7.4.5"},
        {"product": "FortiManager", "max_version": "7.4.4", "fixed_version": "7.4.5"},
    ]

    with patch("app.routes.psirt_routes.make_client", return_value=cm), \
         patch("app.routes.psirt_routes._http_client", return_value=mock_http), \
         patch("app.groups.get_allowed_adoms", return_value=["Corp", "Branch"]), \
         patch("app.groups.get_allowed_tabs", return_value={"device_review"}):
        with client.session_transaction() as sess:
            sess["user"] = "viewer1"
            sess["role"] = "viewer"
        resp = _post(client, "/api/device-review/psirt/assess",
                      {"adom": "*", "advisory": advisory_payload})

    assert resp.status_code == 200
    data = resp.get_json()

    # (a) enrichment happened exactly once: 2 HTTP calls total (page + KEV),
    # not 2 per ADOM (which would be 4 for 2 ADOMs).
    assert mock_http.get.call_count == 2

    # Both ADOMs' FortiOS devices are present in the merge.
    fortios_devices = {f["device"] for f in data["findings"] if f["product"] == "FortiOS"}
    assert fortios_devices == {"FW-Corp", "FW-Branch"}

    # (b) exactly one FortiManager finding survives the merge, not one per ADOM.
    fmg_findings = [f for f in data["findings"] if f["product"] == "FortiManager"]
    assert len(fmg_findings) == 1

    # Priority recomputed over the union — both devices are in range (7.4.2 <
    # 7.4.4), so this must not fall back to "informational".
    assert data["priority"] != "informational"


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
