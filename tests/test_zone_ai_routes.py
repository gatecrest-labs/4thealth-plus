"""Tests for the Zone Policy AI routes."""
import json
import time
from unittest.mock import patch

import pytest

Q = "/api/zone/query/explain"
S = "/api/zone/segmentation-report/summarize"
_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}
RESULT = [{"src": "10.0.0.1", "dst": "10.1.0.1", "service": "", "verdict": "BLOCKED",
           "src_zones": ["A"], "dst_zones": ["B"], "governing": [], "all_policies": []}]
REPORT = {"score": 50.0, "total_zones": 2, "total_pairs": 2, "open_pair_count": 0,
          "open_pairs": [], "trust_mismatches": [], "has_trust_levels": False}


@pytest.fixture
def client():
    from app import create_app
    with create_app().test_client() as c, patch("app.auth._load_users", return_value=_USERS):
        with c.session_transaction() as s:
            s["user"] = "admin"; s["role"] = "admin"
            s["_csrf_token"] = "t"; s["login_at"] = int(time.time())
        yield c


def _post(client, url, body=None):
    return client.post(url, data=json.dumps(body if body is not None else {}),
                       content_type="application/json", headers={"X-CSRF-Token": "t"})


def _ai(on):
    return patch("app.app_settings.get_setting", return_value=on)


def test_status(client):
    with _ai(True):
        assert client.get("/api/zone/ai-status").get_json() == {"available": True}
    with _ai(False):
        assert client.get("/api/zone/ai-status").get_json() == {"available": False}


def test_503_when_ai_disabled(client):
    with _ai(False), patch("app.zone_db.run_query") as rq:
        r = _post(client, Q, {"src": "a", "dst": "b"})
        r2 = _post(client, S)
    assert r.status_code == 503 and r.get_json()["error"] == "AI Assist is not enabled"
    assert r2.status_code == 503
    rq.assert_not_called()


def test_503_when_db_missing(client):
    with _ai(True), patch("app.zone_db.db_available", return_value=False):
        assert _post(client, Q, {"src": "a", "dst": "b"}).status_code == 503
        assert _post(client, S).status_code == 503


@pytest.mark.parametrize("bad", [[], {"src": 5, "dst": "b"}, {"src": "a"}, {"src": "a", "dst": "b", "service": 3},
                                 {"src": ["a", 1], "dst": "b"}, {"src": " ", "dst": "b"}])
def test_400_on_bad_body(client, bad):
    with _ai(True), patch("app.zone_db.db_available", return_value=True):
        assert _post(client, Q, bad).status_code == 400


def test_explain_runs_query_server_side(client):
    seen = {}

    def fake_narr(system_prompt, payload, *, feature, user=None):
        seen["payload"] = payload
        return "text", None

    body = {"src": "10.0.0.1", "dst": "10.1.0.1", "service": "ssh", "verdict": "ALLOWED",
            "results": [{"verdict": "ALLOWED"}]}
    with _ai(True), patch("app.zone_db.db_available", return_value=True), \
         patch("app.routes.zone_routes.zdb.run_query", return_value=RESULT) as rq, \
         patch("app.zone_ai.safe_narrate", fake_narr):
        r = _post(client, Q, body)
    assert r.status_code == 200 and r.get_json() == {"narrative": "text", "narrative_error": None}
    rq.assert_called_once_with(["10.0.0.1"], ["10.1.0.1"], "ssh", verbose=True)
    assert seen["payload"]["results"][0]["verdict"] == "BLOCKED"


def test_never_500_on_llm_error(client):
    with _ai(True), patch("app.zone_db.db_available", return_value=True), \
         patch("app.routes.zone_routes.zdb.run_query", return_value=RESULT), \
         patch("app.routes.zone_routes.zdb.load_db", return_value={"zones": {}, "policies": []}), \
         patch("app.llm.get_provider", side_effect=RuntimeError("boom")):
        for r in (_post(client, Q, {"src": "a", "dst": "b"}), _post(client, S)):
            assert r.status_code == 200
            d = r.get_json()
            assert d["narrative"] is None and "boom" in d["narrative_error"]


def test_segmentation_computes_report_itself(client):
    seen = {}

    def fake_narr(system_prompt, payload, *, feature, user=None):
        seen["p"] = payload
        return "t", None

    with _ai(True), patch("app.zone_db.db_available", return_value=True), \
         patch("app.routes.zone_routes.zdb.load_db", return_value={}), \
         patch("app.routes.zone_routes.zdb.compute_segmentation_report", return_value=REPORT), \
         patch("app.zone_ai.safe_narrate", fake_narr):
        r = _post(client, S, {"score": 100})
    assert r.status_code == 200 and seen["p"]["score"] == 50.0
