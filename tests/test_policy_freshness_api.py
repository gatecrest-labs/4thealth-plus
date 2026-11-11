"""Policy store freshness API, page hooks and load check (Phase 4, Task 9)."""

import importlib.util
import json
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from app import policy_cache, policy_store
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

_USERS = {
    "admin": {"password_hash": "$2b$12$placeholder", "role": "admin"},
    "viewer": {"password_hash": "$2b$12$placeholder", "role": "viewer"},
}
_SCRIPT = (
    Path(__file__).resolve().parent.parent / "scripts" / "verify_policy_store_load.py"
)


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    monkeypatch.setattr(Config, "POLICY_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_MAX_AGE_SECS", 0)
    monkeypatch.setattr(Config, "POLICY_REFRESH_MIN_INTERVAL_SECS", 30)
    policy_cache._empty_list_seen.clear()
    synth = SyntheticFMG(
        adoms=2, devices=8, packages_per_adom=3, rules_per_package=10, seed=2
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    policy_cache.refresh_objects(real)
    policy_cache.refresh_once(real)
    adoms = [
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    ]
    return synth, real, adoms


def _client(user="admin", tabs=("rule_hygiene", "audit_review")):
    from app import create_app

    c = create_app().test_client()
    with c.session_transaction() as sess:
        sess["user"] = user
        sess["role"] = _USERS[user]["role"]
        sess["_csrf_token"] = "t"
        sess["login_at"] = int(time.time())
        sess["allowed_tabs"] = list(tabs)
    return c


def _req(user, method, url, payload=None, tabs=("rule_hygiene", "audit_review")):
    with patch("app.auth._load_users", return_value=_USERS):
        c = _client(user, tabs)
        if method == "get":
            return c.get(url)
        return c.post(
            url,
            data=json.dumps(payload or {}),
            content_type="application/json",
            headers={"X-CSRF-Token": "t"},
        )


def test_status_requires_login():
    from app import create_app

    assert (
        create_app().test_client().get("/api/policy-store/status?adom=A").status_code
        == 401
    )


def test_status_disabled_when_flag_off(monkeypatch, rig):
    _, _, adoms = rig
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    body = _req("admin", "get", f"/api/policy-store/status?adom={adoms[0]}").get_json()
    assert body["enabled"] is False and body["packages"] == []


def test_status_lists_packages_with_age_count_and_flags(rig):
    _, _, adoms = rig
    adom = adoms[0]
    metas = policy_store.package_meta(adom)
    policy_store._set_fetched_at_for_test(
        "policy_pkg",
        (adom, metas[0]["pkg"]),
        (datetime.now(UTC) - timedelta(hours=40)).isoformat(),
    )
    policy_store.mark_policies_error(adom, metas[1]["pkg"], "fmg down")
    body = _req("admin", "get", f"/api/policy-store/status?adom={adom}").get_json()
    assert body["enabled"] is True and body["adom"] == adom
    rows = {r["pkg"]: r for r in body["packages"]}
    assert len(rows) == 3
    assert rows[metas[0]["pkg"]]["stale"] is True
    assert rows[metas[1]["pkg"]]["status"] == "error"
    assert (
        rows[metas[2]["pkg"]]["stale"] is False
        and rows[metas[2]["pkg"]]["policy_count"] == 10
    )
    assert body["objects"]["fetched_at"] and body["objects"]["stale"] is False


def test_status_requires_a_hygiene_or_audit_tab_and_adom_access(monkeypatch, rig):
    _, _, adoms = rig
    assert (
        _req(
            "viewer",
            "get",
            f"/api/policy-store/status?adom={adoms[0]}",
            tabs=("map_view",),
        ).status_code
        == 403
    )
    monkeypatch.setattr(
        "app.routes.api_routes.check_adom_access",
        lambda a: ({"error": "not permitted"}, 403) if a == adoms[1] else None,
    )
    assert (
        _req("admin", "get", f"/api/policy-store/status?adom={adoms[1]}").status_code
        == 403
    )
    assert (
        _req("admin", "get", f"/api/policy-store/status?adom={adoms[0]}").status_code
        == 200
    )


def test_status_requires_adom_param(rig):
    assert _req("admin", "get", "/api/policy-store/status").status_code == 400


def test_refresh_enqueues_throttles_and_the_collector_serves_it(monkeypatch, rig):
    synth, real, adoms = rig
    adom = adoms[0]
    pkg = policy_store.package_meta(adom)[0]["pkg"]
    resp = _req(
        "admin", "post", "/api/policy-store/refresh", {"adom": adom, "pkg": pkg}
    )
    assert resp.status_code == 202 and resp.get_json() == {"requested": True}
    again = _req(
        "admin", "post", "/api/policy-store/refresh", {"adom": adom, "pkg": pkg}
    )
    assert (
        again.status_code == 429
        and 0 < again.get_json()["retry_after"] <= 30
        and again.headers["Retry-After"]
    )
    real_policies = synth._policies
    synth._policies = lambda a, p: (
        [{**r, "name": "fresh"} for r in real_policies(a, p)]
        if p == pkg
        else real_policies(a, p)
    )
    assert policy_cache.process_refresh_requests(real) == 1
    assert policy_store.get_policies(adom, pkg)["policies"][0]["name"] == "fresh"


def test_refresh_validates_input_and_flag(monkeypatch, rig):
    _, _, adoms = rig
    assert (
        _req(
            "admin",
            "post",
            "/api/policy-store/refresh",
            {"adom": adoms[0], "pkg": "no-such-package"},
        ).status_code
        == 404
    )
    assert (
        _req(
            "admin", "post", "/api/policy-store/refresh", {"adom": "", "pkg": ""}
        ).status_code
        == 400
    )
    assert (
        _req(
            "viewer",
            "post",
            "/api/policy-store/refresh",
            {"adom": adoms[0], "pkg": "p"},
            tabs=("map_view",),
        ).status_code
        == 403
    )
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    assert (
        _req(
            "admin", "post", "/api/policy-store/refresh", {"adom": adoms[0], "pkg": "p"}
        ).status_code
        == 503
    )


@pytest.mark.parametrize(
    ("url", "mount"),
    [("/hygiene", "pvFreshness"), ("/audit-review", "hygieneFreshness")],
)
def test_pages_include_policy_freshness_hooks_only_when_enabled(
    monkeypatch, rig, url, mount
):
    on = _req("admin", "get", url).get_data(as_text=True)
    assert "policy_freshness.js" in on and f'id="{mount}"' in on
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    off = _req("admin", "get", url).get_data(as_text=True)
    assert "policy_freshness.js" not in off and f'id="{mount}"' not in off


def _load_script():
    spec = importlib.util.spec_from_file_location("verify_policy_store_load", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verify_policy_store_load"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_verify_policy_store_load_small_run_passes(tmp_path):
    mod = _load_script()
    result = mod.run(
        adoms=1,
        packages=3,
        rules=8,
        readers=1,
        db_path=tmp_path / "load.db",
        read_seconds=1.0,
    )
    assert result["errors"] == []
    assert (
        result["packages"] == 3
        and result["write_seconds"] > 0
        and result["db_bytes"] > 0
    )
    assert result["reads"] > 0 and result["read_p95_ms"] >= result["read_p50_ms"] >= 0
    assert (
        result["rule_lookup"]["rules"] == 3 * 8
        and result["rule_lookup"]["build_seconds"] >= 0
    )
