"""Tests for the Rule Lookup API endpoints."""

import ipaddress
import json
import os
import time
from unittest.mock import patch

import pytest

from app.planner.matching import ServiceCatalog
from app.rule_lookup import Context

N = ipaddress.ip_network


@pytest.fixture
def app():
    os.environ.setdefault("SECRET_KEY", "test-secret")
    os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")
    from app import create_app

    return create_app()


_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def client(app):
    with (
        app.test_client() as c,
        patch("app.auth._load_users", return_value=_TEST_USERS),
    ):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def _post(client, url, payload):
    return client.post(
        url,
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf"},
    )


URL = "/api/hygiene/adoms/Ent/rule-lookup"


def _rule(name, **kw):
    base = {
        "adom": "Ent",
        "package": "PkgA",
        "firewalls": ["fw1 / root"],
        "policyid": 1,
        "name": name,
        "status": "enable",
        "action": "accept",
        "srcintf": [],
        "dstintf": [],
        "srcaddr": [],
        "dstaddr": [],
        "service": [],
        "srcaddr_negate": False,
        "dstaddr_negate": False,
        "comment": "",
        "policy_block": "",
    }
    base.update(kw)
    return base


def _entry(rules):
    ctx = Context(
        addr={
            "corp": frozenset({N("10.1.0.0/16")}),
            "other": frozenset({N("9.9.0.0/16")}),
        },
        svc=ServiceCatalog(
            [{"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}], []
        ),
        svc_names={"https": "HTTPS"},
    )
    return {
        "rules": rules,
        "ctx": ctx,
        "last_updated": "2026-10-29T12:00:00+00:00",
        "status": "ok",
        "error": None,
        "package_errors": [],
    }


def _seed(rules):
    return patch("app.rule_lookup_cache.get_adom", return_value=_entry(rules))


def test_blank_search_is_400(client):
    with _seed([]):
        r = _post(client, URL, {"src": "", "dst": "", "port": ""})
    assert r.status_code == 400


@pytest.mark.parametrize("bad", ["10.1.1.300", "10.1.1.0/33", "10.*.1.1"])
def test_bad_ip_is_400_not_500(client, bad):
    with _seed([]):
        r = _post(client, URL, {"src": bad})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_unknown_service_name_is_400(client):
    with _seed([]):
        r = _post(client, URL, {"port": "no-such-svc"})
    assert r.status_code == 400


def test_source_search_returns_labelled_rows(client):
    rules = [_rule("hit", srcaddr=["corp"]), _rule("miss", srcaddr=["other"])]
    with _seed(rules):
        r = _post(client, URL, {"src": "10.1.1.5"})
    body = r.get_json()
    assert r.status_code == 200
    assert [x["name"] for x in body["rows"]] == ["hit"]
    assert body["rows"][0]["match"]["src"]["label"] == "broader"
    assert body["total"] == 1
    assert body["last_updated"] == "2026-10-29T12:00:00+00:00"


def test_name_pattern_and_service_name(client):
    rules = [_rule("hit", srcaddr=["corp"], service=["HTTPS"])]
    with _seed(rules):
        r = _post(client, URL, {"src": "cor*", "port": "https"})
    body = r.get_json()
    assert body["rows"][0]["match"]["src"]["label"] == "name"
    assert body["rows"][0]["match"]["port"]["label"] == "exact"


def test_port_only_toggle(client):
    rules = [_rule("p", srcaddr=["other"], service=["HTTPS"])]
    with _seed(rules):
        a = _post(client, URL, {"src": "10.1.1.5", "port": "tcp/443"}).get_json()
        b = _post(
            client,
            URL,
            {"src": "10.1.1.5", "port": "tcp/443", "include_port_only": True},
        ).get_json()
    assert a["rows"] == [] and a["port_only_count"] == 1
    assert [x["name"] for x in b["rows"]] == ["p"]


def test_no_cache_returns_202_and_starts_refresh(client):
    with (
        patch("app.rule_lookup_cache.get_adom", return_value=None),
        patch("app.rule_lookup_cache.refresh_adom_async") as refresh,
    ):
        r = _post(client, URL, {"src": "10.1.1.5"})
    assert r.status_code == 202
    assert r.get_json()["status"] == "warming"
    refresh.assert_called_once_with("Ent")


def test_adom_access_denied(client):
    with patch(
        "app.routes.hygiene_routes.check_adom_access",
        return_value=({"error": "no"}, 403),
    ):
        r = _post(client, URL, {"src": "10.1.1.5"})
    assert r.status_code == 403


def test_refresh_endpoint(client):
    with patch("app.rule_lookup_cache.refresh_adom_async") as refresh:
        r = _post(client, URL + "/refresh", {})
    assert r.status_code == 202
    refresh.assert_called_once_with("Ent")


def test_page_renders_rule_lookup_section_with_every_js_id(client):
    import re
    from pathlib import Path

    html = client.get("/hygiene").get_data(as_text=True)
    js = Path("app/static/js/rule_lookup.js").read_text()
    ids = set(re.findall(r"\$rl\('([A-Za-z]+)'\)", js)) | set(
        re.findall(r"\['(rl[A-Za-z]+)'(?:, '(rl[A-Za-z]+)')*", js)[0]
    )
    ids |= {"rlSrc", "rlDst", "rlPort", "rlFilter"}
    missing = [i for i in ids if i and f'id="{i}"' not in html]
    assert not missing
    assert html.index("Rule Lookup") < html.index("Object Lookup")
    assert "js/rule_lookup.js" in html


@pytest.mark.parametrize(
    "payload", [{"src": ["10.1.1.1"]}, {"src": 123}, {"port": {"a": 1}}, [1], "str"]
)
def test_non_string_fields_are_400_not_500(client, payload):
    with _seed([]):
        r = _post(client, URL, payload)
    assert r.status_code == 400


@pytest.mark.parametrize("port", ["all", "icmp", "tcp/99999", "tcp/443-80"])
def test_unsearchable_ports_are_400(client, port):
    with _seed([]):
        assert _post(client, URL, {"port": port}).status_code == 400


def test_system_adom_is_404(client):
    with patch("app.rule_lookup_cache.refresh_adom_async") as refresh:
        r = _post(
            client,
            "/api/hygiene/adoms/FortiManager_Managed/rule-lookup",
            {"src": "10.1.1.1"},
        )
        r2 = _post(
            client, "/api/hygiene/adoms/FortiManager_Managed/rule-lookup/refresh", {}
        )
    assert r.status_code == 404 and r2.status_code == 404
    refresh.assert_not_called()
