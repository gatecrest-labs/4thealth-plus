"""Interactive hygiene routes read the policy store (Phase 4, Task 7)."""
# ruff: noqa: RUF059

import json
import time
from unittest.mock import patch

import pytest

from app import policies, policy_cache, policy_store
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}
_BLOCKED = ("/pm/config/adom/", "/pm/config/global/", "/pm/pkg/")


class GuardClient(FMGClient):
    """Blocks ADOM-scoped policy/package/object reads; per-device reads still go through."""

    def __init__(self, synth):
        super().__init__(host="fmg.example", token="t")
        self.blocked: list[str] = []
        self.proxy: list[str] = []

        def post(body, timeout=None):
            url = body["params"][0]["url"]
            if url.startswith(_BLOCKED):
                self.blocked.append(url)
                raise AssertionError(f"unexpected FMG policy/object read: {url}")
            if url == "/sys/proxy/json":
                self.proxy.append(url)
            return synth.post(body, timeout)

        self._post = post


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    monkeypatch.setattr(Config, "POLICY_PACKAGE_TTL_HOURS", 6)
    monkeypatch.setattr(Config, "POLICY_MAX_AGE_SECS", 0)
    policy_cache._empty_list_seen.clear()
    policies.reset_counters()
    synth = SyntheticFMG(
        adoms=1,
        devices=8,
        packages_per_adom=3,
        rules_per_package=20,
        blocks_per_package=1,
        seed=4,
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    path = real.get_policy_packages(adom)[0]["path"]
    return synth, real, adom, path


def _use(monkeypatch, client):
    monkeypatch.setattr("app.routes.hygiene_routes.make_client", lambda: client)
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)


def _prime(monkeypatch, real):
    monkeypatch.setattr(Config, "POLICY_STORE", True)
    policy_cache.refresh_objects(real)
    policy_cache.refresh_once(real)


@pytest.fixture
def http():
    from app import create_app

    app = create_app()
    with app.test_client() as c, patch("app.auth._load_users", return_value=_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "t"
            sess["login_at"] = int(time.time())
        yield c


def _call(c, method, url, payload=None):
    if method == "get":
        return c.get(url)
    return c.post(
        url,
        data=json.dumps(payload or {}),
        content_type="application/json",
        headers={"X-CSRF-Token": "t"},
    )


def _norm(resp):
    body = resp.get_json()
    if isinstance(body, dict):
        body = {
            k: v
            for k, v in body.items()
            if k not in ("data_as_of", "last_updated", "checked_at")
        }
    return resp.status_code, json.dumps(body, sort_keys=True, default=str)


def _endpoints(adom, path):
    return {
        "packages": ("get", f"/api/hygiene/adoms/{adom}/packages", None),
        "policies": ("post", "/api/hygiene/policies", {"adom": adom, "path": path}),
        "pblocks": (
            "post",
            "/api/hygiene/policies/pblocks",
            {"adom": adom, "names": ["blk-0"]},
        ),
        "objects": ("post", "/api/hygiene/policies/objects", {"adom": adom}),
        "object_lookup": (
            "post",
            f"/api/hygiene/adoms/{adom}/objects/lookup",
            {"query": "addr-1"},
        ),
        "where_used_addr": (
            "post",
            f"/api/hygiene/adoms/{adom}/objects/where-used",
            {"name": "addr-3", "category": "address"},
        ),
        "where_used_svc": (
            "post",
            f"/api/hygiene/adoms/{adom}/objects/where-used",
            {"name": "svc-2", "category": "service"},
        ),
        "nat_lookup": (
            "post",
            f"/api/hygiene/adoms/{adom}/nat/lookup",
            {"ip": "203.0.113.5"},
        ),
        "run": (
            "post",
            "/api/hygiene/run",
            {
                "adom": adom,
                "path": path,
                "checks": [
                    "unnamed",
                    "unlogged",
                    "disabled",
                    "shadow",
                    "redundant",
                    "broken_refs",
                ],
            },
        ),
        "unused_all": (
            "get",
            f"/api/hygiene/unused-objects?adom={adom}&pkg={path}&scope=all",
            None,
        ),
        "unused_local": (
            "get",
            f"/api/hygiene/unused-objects?adom={adom}&pkg={path}&scope=local",
            None,
        ),
        "unused_global": (
            "get",
            f"/api/hygiene/unused-objects?adom={adom}&pkg={path}&scope=global",
            None,
        ),
    }


@pytest.mark.parametrize(
    "name",
    [
        "packages",
        "policies",
        "pblocks",
        "objects",
        "object_lookup",
        "where_used_addr",
        "where_used_svc",
        "nat_lookup",
        "run",
        "unused_all",
        "unused_local",
        "unused_global",
    ],
)
def test_endpoint_same_json_from_store_zero_policy_calls(monkeypatch, rig, http, name):
    synth, real, adom, path = rig
    method, url, payload = _endpoints(adom, path)[name]
    _use(monkeypatch, real)
    monkeypatch.setattr(Config, "POLICY_STORE", False)
    legacy = _norm(_call(http, method, url, payload))
    assert legacy[0] == 200, legacy
    _prime(monkeypatch, real)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    cached = _norm(_call(http, method, url, payload))
    assert guard.blocked == [], guard.blocked
    assert cached == legacy
    assert policies.counters()["fallbacks"] == 0


def test_where_used_scans_all_packages_from_store(monkeypatch, rig, http):
    synth, real, adom, path = rig
    _prime(monkeypatch, real)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    method, url, payload = _endpoints(adom, path)["where_used_addr"]
    body = _call(http, method, url, payload).get_json()
    assert body["packages_scanned"] == 3 and guard.blocked == []


def test_run_hygiene_unhit_overlay_still_live(monkeypatch, rig, http):
    synth, real, adom, path = rig
    _prime(monkeypatch, real)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    resp = _call(
        http,
        "post",
        "/api/hygiene/run",
        {"adom": adom, "path": path, "checks": ["unhit"]},
    )
    assert resp.status_code == 200
    assert guard.blocked == []  # policies and package scope came from the store
    assert guard.proxy  # per-device hit counts are still a live read


def test_package_endpoints_report_data_as_of_only_when_the_store_is_on(
    monkeypatch, rig, http
):
    synth, real, adom, path = rig
    _use(monkeypatch, real)
    off = _call(
        http, "post", "/api/hygiene/policies", {"adom": adom, "path": path}
    ).get_json()
    assert "data_as_of" not in off
    _prime(monkeypatch, real)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    on = _call(
        http, "post", "/api/hygiene/policies", {"adom": adom, "path": path}
    ).get_json()
    assert on["data_as_of"] == policies.data_as_of(adom, path)


def test_restricted_user_gets_403_for_other_adom_with_store_on(monkeypatch, rig, http):
    synth, real, adom, path = rig
    _prime(monkeypatch, real)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    monkeypatch.setattr(
        "app.routes.hygiene_routes.check_adom_access",
        lambda a: ({"error": "not permitted"}, 403) if a != adom else None,
    )
    assert _call(http, "get", "/api/hygiene/adoms/Other/packages").status_code == 403
    assert _call(http, "get", f"/api/hygiene/adoms/{adom}/packages").status_code == 200
    assert guard.blocked == []


def test_flag_off_calls_fmg_exactly_as_before(monkeypatch, rig, http):
    synth, real, adom, path = rig

    def nope(*a, **k):
        raise AssertionError("policy store touched with POLICY_STORE off")

    for fn in (
        "get_packages",
        "get_policies",
        "get_objects",
        "get_block",
        "package_meta",
    ):
        monkeypatch.setattr(policy_store, fn, nope)
    _use(monkeypatch, real)
    synth.calls.clear()
    assert (
        _call(
            http, "post", "/api/hygiene/policies", {"adom": adom, "path": path}
        ).status_code
        == 200
    )
    assert any("/firewall/policy" in k for k in synth.calls)
