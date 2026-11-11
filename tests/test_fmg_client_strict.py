"""Strict policy/object fetchers (Phase 4, Task 1)."""

import pytest

from app.fmg_client import FMGClient, FMGError
from app.synthetic_fmg import SyntheticFMG

ERR = {"result": [{"status": {"code": -11, "message": "No permission"}, "url": "x"}]}

GETTERS = [
    ("get_policy_packages", ("A",)),
    ("get_pkg_settings", ("A", "pkg")),
    ("get_pkg_scope_members", ("A", "pkg")),
    ("get_address_objects", ("A",)),
    ("get_address_groups", ("A",)),
    ("get_service_objects", ("A",)),
    ("get_service_groups", ("A",)),
    ("get_vip_objects", ("A",)),
    ("get_ippool_objects", ("A",)),
]


def _client(post):
    c = FMGClient(host="fmg.example", token="t")
    c._post = post
    return c


@pytest.mark.parametrize(("name", "args"), GETTERS)
def test_default_calls_still_swallow_errors(name, args):
    c = _client(lambda body, timeout=None: ERR)
    assert getattr(c, name)(*args) in ([], {})


@pytest.mark.parametrize(("name", "args"), GETTERS)
def test_strict_raises_on_fmg_error_status(name, args):
    c = _client(lambda body, timeout=None: ERR)
    with pytest.raises(FMGError):
        getattr(c, name)(*args, strict=True)


@pytest.mark.parametrize(("name", "args"), GETTERS)
def test_strict_raises_on_transport_exception(name, args):
    def boom(body, timeout=None):
        raise ConnectionError("down")

    with pytest.raises(FMGError):
        getattr(_client(boom), name)(*args, strict=True)


def _ok(data):
    return {
        "result": [{"status": {"code": 0, "message": "OK"}, "data": data, "url": "x"}]
    }


@pytest.mark.parametrize(
    "name",
    [
        "get_policy_packages",
        "get_address_objects",
        "get_address_groups",
        "get_service_objects",
        "get_service_groups",
        "get_vip_objects",
        "get_ippool_objects",
    ],
)
def test_strict_raises_on_wrong_shape(name):
    c = _client(lambda body, timeout=None: _ok("not-a-list"))
    with pytest.raises(FMGError):
        getattr(c, name)("A", strict=True)


def test_strict_accepts_a_missing_data_key_as_an_empty_list():
    """FMG omits ``data`` for an empty table; that is an answer, not a failure."""
    empty = {"result": [{"status": {"code": 0, "message": "OK"}, "url": "x"}]}
    c = _client(lambda body, timeout=None: empty)
    assert c.get_address_objects("A", strict=True) == []
    assert c.get_vip_objects("A", strict=True) == []
    assert c.get_policy_packages("A", strict=True) == []


def test_strict_pkg_settings_and_scope_raise_when_package_missing():
    c = _client(lambda body, timeout=None: _ok([]))
    with pytest.raises(FMGError):
        c.get_pkg_settings("A", "nope", strict=True)
    with pytest.raises(FMGError):
        c.get_pkg_scope_members("A", "nope", strict=True)


@pytest.fixture
def synth_client():
    synth = SyntheticFMG(adoms=1, devices=10, packages_per_adom=2, rules_per_package=5)
    c = _client(synth.post)
    return (
        synth,
        c,
        next(
            a["name"]
            for a in c.get_adoms()
            if not a["name"].lower().startswith("forti")
        ),
    )


def _urls(synth):
    return sorted(synth.calls)


@pytest.mark.parametrize(
    ("getter", "local", "glob"),
    [
        ("get_address_objects", "obj/firewall/address", "global/obj/firewall/address"),
        ("get_address_groups", "obj/firewall/addrgrp", "global/obj/firewall/addrgrp"),
        ("get_vip_objects", "obj/firewall/vip", "global/obj/firewall/vip"),
        ("get_ippool_objects", "obj/firewall/ippool", "global/obj/firewall/ippool"),
    ],
)
def test_scope_local_and_global_fetch_only_their_urls(
    synth_client, getter, local, glob
):
    synth, c, adom = synth_client
    synth.calls.clear()
    getattr(c, getter)(adom, scope="local")
    assert [k for k in synth.calls if "global" in k] == [] and synth.calls
    synth.calls.clear()
    getattr(c, getter)(adom, scope="global")
    assert [k for k in synth.calls if "/adom/" in k] == [] and synth.calls


def test_services_have_no_global_pool(synth_client):
    _, c, adom = synth_client
    assert c.get_service_objects(adom, scope="global", strict=True) == []
    assert c.get_service_groups(adom, scope="global", strict=True) == []


@pytest.mark.parametrize("getter", ["get_vip_objects", "get_ippool_objects"])
def test_vip_and_ippool_scope_all_is_local_then_global(synth_client, getter):
    _, c, adom = synth_client
    both = getattr(c, getter)(adom)
    assert both == getattr(c, getter)(adom, scope="local") + getattr(c, getter)(
        adom, scope="global"
    )


@pytest.mark.parametrize(
    "getter",
    [
        "get_address_objects",
        "get_address_groups",
        "get_service_objects",
        "get_service_groups",
        "get_vip_objects",
        "get_ippool_objects",
    ],
)
def test_strict_success_returns_same_data_as_default(synth_client, getter):
    _, c, adom = synth_client
    assert getattr(c, getter)(adom, strict=True) == getattr(c, getter)(adom)


def test_strict_packages_settings_scope_equal_default(synth_client):
    _, c, adom = synth_client
    pkgs = c.get_policy_packages(adom)
    assert c.get_policy_packages(adom, strict=True) == pkgs and pkgs
    path = pkgs[0]["path"]
    assert c.get_pkg_settings(adom, path, strict=True) == c.get_pkg_settings(adom, path)
    assert c.get_pkg_scope_members(adom, path, strict=True) == c.get_pkg_scope_members(
        adom, path
    )
