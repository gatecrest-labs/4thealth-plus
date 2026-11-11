"""Shared device-data fetch (Phase 5, Task 1)."""

import pytest

from app import device_data
from app.device_review import CHECKS_META
from app.fmg_client import FMGClient

KEYS = [k for k in device_data.DATA_KEYS]


def _envelope(results, http_status=200, rpc_code=0, wrapper_status=None):
    wrapper = {"response": {"http_status": http_status, "results": results}}
    if wrapper_status is not None:
        wrapper = {"status": wrapper_status}
    return {
        "result": [{"status": {"code": rpc_code, "message": "x"}, "data": [wrapper]}]
    }


def _client(post):
    c = FMGClient(host="fmg.example", token="t")
    c._post = post
    return c


def _echo_post(body, timeout=None):
    """Answers every proxy read with something that depends on the resource asked for."""
    resource = body["params"][0]["data"]["resource"]
    if "interface" in resource:
        return _envelope(
            [{"vdom": "root", "results": [{"name": "port1", "vdom": "root"}]}]
        )
    return _envelope({"resource": resource})


def test_data_keys_cover_every_check_data_key():
    needed = {k for c in CHECKS_META for k in c["data_keys"]}
    assert needed <= set(device_data.DATA_KEYS) | {"device_meta"}


def test_fifteen_proxy_backed_keys():
    assert (
        len(device_data.DATA_KEYS) == 15 and "device_meta" not in device_data.DATA_KEYS
    )


@pytest.mark.parametrize("key", KEYS)
def test_fetch_returns_each_getter_result(key):
    c = _client(_echo_post)
    getter = device_data.DATA_KEYS[key][0]
    expected = getattr(c, getter)("A", "fw1")
    assert device_data.fetch_device_data(c, "A", "fw1", {key}) == {key: expected}


@pytest.mark.parametrize("key", KEYS)
def test_fetch_returns_the_empty_value_when_the_getter_raises(key):
    c = _client(_echo_post)
    getter = device_data.DATA_KEYS[key][0]
    setattr(c, getter, lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    out = device_data.fetch_device_data(c, "A", "fw1", {key})
    assert out == {key: device_data.DATA_KEYS[key][1]()}


def test_fetch_only_asks_for_the_requested_keys_and_passes_device_meta_through():
    calls = []

    def post(body, timeout=None):
        calls.append(body["params"][0]["data"]["resource"])
        return _echo_post(body)

    c = _client(post)
    out = device_data.fetch_device_data(
        c, "A", "fw1", {"ntp", "device_meta"}, {"os_ver": 7}
    )
    assert set(out) == {"ntp", "device_meta"} and out["device_meta"] == {"os_ver": 7}
    assert len(calls) == 1 and "ntp" in calls[0]
    assert device_data.fetch_device_data(c, "A", "fw1", {"device_meta"}) == {
        "device_meta": {}
    }


def test_checked_marks_only_the_failed_key():
    def post(body, timeout=None):
        resource = body["params"][0]["data"]["resource"]
        if "ntp" in resource:
            return _envelope(
                {}, wrapper_status={"code": -20055, "message": "No tunnel 80"}
            )
        return _echo_post(body)

    out = device_data.fetch_device_data_checked(
        _client(post), "A", "fw1", {"ntp", "dns"}
    )
    assert out["ntp"][0] == {} and out["ntp"][1] and "No tunnel" in out["ntp"][1]
    assert out["dns"][1] is None and out["dns"][0]


def test_checked_empty_but_ok_is_not_a_failure():
    out = device_data.fetch_device_data_checked(
        _client(lambda body, timeout=None: _envelope({}, http_status=404)),
        "A",
        "fw1",
        {"ha_status"},
    )
    assert out["ha_status"] == ({}, None)


def test_checked_reports_a_raised_exception_as_a_failure():
    def boom(body, timeout=None):
        raise ConnectionError("down")

    out = device_data.fetch_device_data_checked(_client(boom), "A", "fw1", {"ntp"})
    assert out["ntp"][0] == {} and "down" in out["ntp"][1]


def test_route_function_is_a_thin_alias():
    from app.routes import audit_review_routes as routes

    c = _client(_echo_post)
    assert routes._fetch_device_data(
        c, "A", "fw1", {"ntp", "dns"}
    ) == device_data.fetch_device_data(c, "A", "fw1", {"ntp", "dns"})
