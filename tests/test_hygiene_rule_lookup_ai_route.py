"""Tests for the Rule Lookup explain routes."""
import json
import time
from unittest.mock import patch

import pytest

URL = "/api/hygiene/adoms/CorpADOM/rule-lookup/explain"
_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}
BODY = {"searched": {"src": "10.0.0.1"}, "rows": [{"policyid": 1}], "skipped_count": 0, "total": 1}


@pytest.fixture
def app():
    from app import create_app
    return create_app()


@pytest.fixture
def client(app):
    with app.test_client() as c, patch("app.auth._load_users", return_value=_TEST_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def _post(client, payload, url=URL):
    return client.post(url, data=json.dumps(payload), content_type="application/json",
                       headers={"X-CSRF-Token": "test-csrf"})


def test_status_reflects_setting(client):
    with patch("app.app_settings.get_setting", return_value=True):
        assert client.get("/api/hygiene/rule-lookup/ai-status").get_json() == {"available": True}
    with patch("app.app_settings.get_setting", return_value=False):
        assert client.get("/api/hygiene/rule-lookup/ai-status").get_json() == {"available": False}


def test_route_503_when_disabled(client):
    with patch("app.app_settings.get_setting", return_value=False), \
         patch("app.routes.hygiene_routes.check_adom_access", return_value=None):
        resp = _post(client, BODY)
    assert resp.status_code == 503
    assert resp.get_json()["error"] == "AI Assist is not enabled"


@pytest.mark.parametrize("bad", [
    {**BODY, "rows": "nope"}, {**BODY, "searched": []}, {**BODY, "skipped_count": "x"},
    [BODY], {**BODY, "rows": [1, 2]},
])
def test_route_400_on_bad_body(client, bad):
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.routes.hygiene_routes.check_adom_access", return_value=None):
        assert _post(client, bad).status_code == 400


def test_route_enforces_adom_access(client):
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.routes.hygiene_routes.check_adom_access",
               return_value=({"error": "no"}, 403)):
        assert _post(client, BODY).status_code == 403


def test_llm_failure_returns_200_with_error(client):
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.routes.hygiene_routes.check_adom_access", return_value=None), \
         patch("app.llm.get_provider", side_effect=RuntimeError("boom")):
        resp = _post(client, BODY)
    assert resp.status_code == 200
    d = resp.get_json()
    assert d["narrative"] is None and "boom" in d["narrative_error"]


def test_success(client):
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.routes.hygiene_routes.check_adom_access", return_value=None), \
         patch("app.rule_lookup_ai.build_lookup_narrative", return_value=("text", None)):
        resp = _post(client, BODY)
    assert resp.get_json() == {"narrative": "text", "narrative_error": None}


def test_malformed_row_fields_do_not_500(client):
    bad_row = {"policyid": 1, "srcaddr": {"a": 1}, "dstaddr": 5, "service": "x", "match": [1]}
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.routes.hygiene_routes.check_adom_access", return_value=None), \
         patch("app.llm.get_provider", side_effect=RuntimeError("boom")):
        resp = _post(client, {**BODY, "rows": [bad_row]})
    assert resp.status_code == 200
    assert resp.get_json()["narrative"] is None


def test_rows_sliced_before_validation_and_remainder_counted(client):
    rows = [{"policyid": i} for i in range(100)] + ["junk"]
    seen = {}

    def fake(adom, searched, result, user):
        seen.update(result)
        return "t", None

    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.routes.hygiene_routes.check_adom_access", return_value=None), \
         patch("app.rule_lookup_ai.build_lookup_narrative", side_effect=fake):
        resp = _post(client, {**BODY, "rows": rows, "total": 0})
    assert resp.status_code == 200
    assert len(seen["rows"]) == 25 and seen["total"] == 101


# ── NL parse route (Task 7) ──────────────────────────────────────────────────
PARSE_URL = "/api/hygiene/rule-lookup/parse"


def test_parse_503_when_ai_disabled(client):
    with patch("app.app_settings.get_setting", return_value=False), \
         patch("app.rule_lookup_ai.parse_nl_query") as p:
        resp = _post(client, {"text": "hi"}, PARSE_URL)
    assert resp.status_code == 503
    assert resp.get_json()["error"] == "AI Assist is not enabled"
    p.assert_not_called()


@pytest.mark.parametrize("bad", [[1], {"text": 5}, {}, {"text": None}])
def test_parse_400_on_bad_body(client, bad):
    with patch("app.app_settings.get_setting", return_value=True):
        assert _post(client, bad, PARSE_URL).status_code == 400


def test_parse_success_never_calls_search(client):
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.rule_lookup_ai.parse_nl_query",
               return_value={"src": "10.0.0.1", "dst": "", "port": "tcp/443"}), \
         patch("app.rule_lookup.search") as s, \
         patch("app.rule_lookup_cache.get_adom") as ge, \
         patch("app.rule_lookup_cache.refresh_adom_async") as ra:
        resp = _post(client, {"text": "from 10.0.0.1 on 443"}, PARSE_URL)
    assert resp.status_code == 200
    assert resp.get_json() == {"src": "10.0.0.1", "dst": "", "port": "tcp/443"}
    s.assert_not_called(); ge.assert_not_called(); ra.assert_not_called()


def test_parse_400_on_value_error(client):
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.rule_lookup_ai.parse_nl_query", side_effect=ValueError("src: bad")):
        resp = _post(client, {"text": "x"}, PARSE_URL)
    assert resp.status_code == 400
    assert "src" in resp.get_json()["error"]


def test_parse_502_on_provider_failure(client):
    from app.llm.base import LLMError
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.rule_lookup_ai.parse_nl_query", side_effect=LLMError("boom")):
        assert _post(client, {"text": "x"}, PARSE_URL).status_code == 502
    with patch("app.app_settings.get_setting", return_value=True), \
         patch("app.rule_lookup_ai.parse_nl_query", side_effect=RuntimeError("boom")):
        assert _post(client, {"text": "x"}, PARSE_URL).status_code == 502
