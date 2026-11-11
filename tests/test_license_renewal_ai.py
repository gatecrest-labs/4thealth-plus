"""Tests for the license & lifecycle renewal plan."""
import json
import time
from datetime import date
from unittest.mock import patch

import pytest

from app import license_renewal_ai as lr

AS_OF = date(2026, 11, 11)
_USERS = {
    "admin": {"password_hash": "x", "role": "admin"},
    "bob": {"password_hash": "x", "role": "viewer"},
}


def dev(name, adom, status="licensed", expires=None):
    return {"device": name, "adom": adom, "status": status, "expires": expires,
            "firmware": "v7.4.1", "subscriptions": {}}


DEVICES = [
    dev("a-far", "A", expires="2027-12-01"),
    dev("a-30", "A", expires="2026-11-30"),
    dev("a-exp", "A", status="expired", expires="2026-01-01"),
    dev("b-60", "B", expires="2026-12-31"),
    dev("b-90", "B", expires="2027-02-01"),
    dev("b-none", "B", status="unknown"),
]


def test_expired_devices_first_and_tagged():
    b = lr.build_renewal_buckets(DEVICES, [], as_of=AS_OF)
    first = b["adoms"][0]["devices"][0]
    assert first["device"] == "a-exp" and "expired" in first["tags"]


def test_buckets_ordered_soonest_first():
    b = lr.build_renewal_buckets(DEVICES, [], as_of=AS_OF)
    assert [a["adom"] for a in b["adoms"]] == ["A", "B"]
    assert [d["device"] for d in b["adoms"][0]["devices"]] == ["a-exp", "a-30"]
    assert [d["device"] for d in b["adoms"][1]["devices"]] == ["b-60", "b-90"]
    tags = {d["device"]: d["tags"] for a in b["adoms"] for d in a["devices"]}
    assert tags["a-30"] == ["<=30"] and tags["b-60"] == ["<=60"] and tags["b-90"] == ["<=90"]
    assert "a-far" not in tags and "b-none" not in tags


def test_eos_and_license_both_considered():
    devs = [dev("fw1", "C", expires="2026-12-01"), dev("fw2", "C", expires="2029-01-01"),
            dev("fw3", "C", expires="2029-01-01")]
    life = [{"device": "fw1", "adom": "C", "platform": "FortiGate-60F"},
            {"device": "fw2", "adom": "C", "platform": "FortiGate-60F"},
            {"device": "fw3", "adom": "C", "platform": "Unknown-Model"}]
    with patch("app.license_renewal_ai.hw_eos_date",
               lambda m: date(2027, 3, 1) if m == "FortiGate-60F" else None):
        b = lr.build_renewal_buckets(devs, life, as_of=AS_OF)
    by = {d["device"]: d for d in b["adoms"][0]["devices"]}
    assert by["fw1"]["tags"] == ["<=30", "eos_12m"]
    assert by["fw2"]["tags"] == ["eos_12m"]
    assert "fw3" not in by
    assert [d["device"] for d in b["adoms"][0]["devices"]] == ["fw1", "fw2"]


def test_as_of_injection_is_deterministic():
    a = lr.build_renewal_buckets(DEVICES, [], as_of=AS_OF)
    assert a == lr.build_renewal_buckets(DEVICES, [], as_of=AS_OF)
    later = lr.build_renewal_buckets(DEVICES, [], as_of=date(2026, 12, 15))
    t = {d["device"]: d["tags"] for x in later["adoms"] for d in x["devices"]}
    assert t["a-30"] == ["expired"]


def test_malformed_devices_ignored():
    b = lr.build_renewal_buckets([None, 3, {"adom": "A"}, dev("x", "A", expires="garbage")], [None], as_of=AS_OF)
    assert b["total_devices"] == 0


def _many(n):
    return lr.build_renewal_buckets(
        [dev(f"d{i}", "A", expires="2026-11-20") for i in range(n)], [], as_of=AS_OF)


def test_caps_40_devices_with_remainder_count():
    seen = {}

    def fake(system, payload, *, feature, user=None):
        seen.update(payload=payload, feature=feature, system=system)
        return "n", None

    with patch("app.license_renewal_ai.safe_narrate", fake):
        assert lr.build_renewal_plan(_many(55)) == ("n", None)
    p = seen["payload"]
    assert sum(len(a["devices"]) for a in p["adoms"]) == 40
    assert p["devices_not_shown"] == 15
    assert seen["feature"] == "license_renewal_plan"
    low = seen["system"].lower()
    assert "price" in low and "data" in low


def test_plan_empty_buckets_skips_llm():
    with patch("app.license_renewal_ai.safe_narrate", side_effect=AssertionError):
        assert lr.build_renewal_plan(_many(0)) == (None, None)


# ---- routes -------------------------------------------------------------

P = "/api/devices/all/license/renewal-plan"
LATEST = {"all_devices": [dev("a1", "Allowed", expires="2026-11-20"),
                          dev("s1", "Secret", expires="2026-11-20")],
          "collected_at": "x"}


@pytest.fixture
def make_client():
    from app import create_app

    def _mk(user="admin", role="admin"):
        c = create_app().test_client()
        with c.session_transaction() as s:
            s["user"] = user; s["role"] = role
            s["_csrf_token"] = "t"; s["login_at"] = int(time.time()); s["allowed_tabs"] = ["versions"]
        return c
    with patch("app.auth._load_users", return_value=_USERS):
        yield _mk


def _post(c, body=None):
    return c.post(P, data=json.dumps(body if body is not None else {}),
                  content_type="application/json", headers={"X-CSRF-Token": "t"})


def _ai(on):
    return patch("app.app_settings.get_setting", return_value=on)


def _common():
    return [patch("app.license_status_cache.get_latest", return_value=LATEST),
            patch("app.pending_status_cache.get_all_cached_devices", return_value={})]


def _run(c, body, ai=True, allowed=None, narr=("txt", None)):
    from contextlib import ExitStack
    with ExitStack() as st:
        st.enter_context(_ai(ai))
        for p in _common():
            st.enter_context(p)
        st.enter_context(patch("app.groups.get_allowed_adoms", return_value=allowed))
        st.enter_context(patch("app.groups.get_allowed_tabs", return_value=["versions"]))
        st.enter_context(patch("app.routes.api_routes.check_adom_access",
                               side_effect=lambda a: None if allowed is None or a in allowed else ({"error": "x"}, 403)))
        st.enter_context(patch("app.license_renewal_ai.safe_narrate", return_value=narr))
        return _post(c, body)


def test_status_route(make_client):
    c = make_client()
    with _ai(True):
        assert c.get("/api/devices/all/license/ai-status").get_json() == {"available": True}
    with _ai(False):
        assert c.get("/api/devices/all/license/ai-status").get_json() == {"available": False}


def test_adom_filter_respects_access(make_client):
    r = _run(make_client("bob", "viewer"), {}, allowed=["Allowed"])
    assert r.status_code == 200
    adoms = [a["adom"] for a in r.get_json()["buckets"]["adoms"]]
    assert adoms == ["Allowed"]


def test_explicit_adom_checks_access(make_client):
    r = _run(make_client("bob", "viewer"), {"adom": "Secret"}, allowed=["Allowed"])
    assert r.status_code == 403
    r = _run(make_client("bob", "viewer"), {"adom": "Allowed"}, allowed=["Allowed"])
    assert r.status_code == 200 and r.get_json()["narrative"] == "txt"


@pytest.mark.parametrize("bad", [{"adom": 5}, {"adom": ["A"]}, [], "x"])
def test_400_on_bad_body(make_client, bad):
    assert _run(make_client(), bad).status_code == 400


def test_ai_off_returns_buckets_without_llm(make_client):
    from contextlib import ExitStack
    with ExitStack() as st:
        st.enter_context(_ai(False))
        for p in _common():
            st.enter_context(p)
        st.enter_context(patch("app.groups.get_allowed_adoms", return_value=None))
        st.enter_context(patch("app.license_renewal_ai.safe_narrate", side_effect=AssertionError))
        r = _post(make_client())
    d = r.get_json()
    assert r.status_code == 200 and d["narrative"] is None and d["narrative_error"] is None
    assert len(d["buckets"]["adoms"]) == 2


def test_llm_failure_keeps_buckets(make_client):
    r = _run(make_client(), {}, narr=(None, "boom"))
    d = r.get_json()
    assert r.status_code == 200 and d["narrative_error"] == "boom" and d["buckets"]["adoms"]
