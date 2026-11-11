"""FMGClient.capture_proxy_failures (Phase 5, Task 1)."""

import threading

from app.fmg_client import FMGClient


def _envelope(http_status=200, results=None, wrapper_status=None, rpc_code=0):
    wrapper = {
        "response": {
            "http_status": http_status,
            "results": results if results is not None else [],
        }
    }
    if wrapper_status is not None:  # tunnel down: status on the wrapper, no response
        wrapper = {"status": wrapper_status}
    return {
        "result": [{"status": {"code": rpc_code, "message": "x"}, "data": [wrapper]}]
    }


def _client(post):
    c = FMGClient(host="fmg.example", token="t")
    c._post = post
    return c


def test_capture_records_tunnel_down():
    c = _client(
        lambda body, timeout=None: _envelope(
            wrapper_status={"code": -20055, "message": "No tunnel 80"}
        )
    )
    with c.capture_proxy_failures() as failures:
        c.get_device_ntp("A", "fw1")
    assert len(failures) == 1 and "No tunnel" in failures[0]


def test_capture_records_fmg_rpc_error():
    c = _client(lambda body, timeout=None: _envelope(rpc_code=-11))
    with c.capture_proxy_failures() as failures:
        c.get_device_ntp("A", "fw1")
    assert len(failures) == 1 and "-11" in failures[0]


def test_capture_records_a_raised_transport_exception_and_still_raises_to_the_getter():
    def boom(body, timeout=None):
        raise ConnectionError("fmg down")

    c = _client(boom)
    with c.capture_proxy_failures() as failures:
        assert (
            c.get_device_ntp("A", "fw1") == {}
        )  # the getter still swallows, as before
    assert len(failures) == 1 and "fmg down" in failures[0]


def test_capture_ignores_a_404_answer_from_the_device():
    c = _client(lambda body, timeout=None: _envelope(http_status=404, results={}))
    with c.capture_proxy_failures() as failures:
        c.get_device_ha_status("A", "fw1")
    assert failures == []


def test_capture_ignores_a_normal_answer():
    c = _client(lambda body, timeout=None: _envelope(results={"ntpsync": "enable"}))
    with c.capture_proxy_failures() as failures:
        assert c.get_device_ntp("A", "fw1") == {"ntpsync": "enable"}
    assert failures == []


def test_nothing_is_recorded_outside_a_capture():
    c = _client(lambda body, timeout=None: _envelope(rpc_code=-11))
    c.get_device_ntp("A", "fw1")  # must not raise or leak state
    with c.capture_proxy_failures() as failures:
        pass
    assert failures == []


def test_capture_is_thread_local():
    c = _client(lambda body, timeout=None: _envelope(rpc_code=-11))
    seen = {}
    gate = threading.Event()

    def worker():
        with c.capture_proxy_failures() as failures:
            gate.wait(2)
            seen["other"] = list(failures)

    t = threading.Thread(target=worker)
    t.start()
    with c.capture_proxy_failures() as mine:
        c.get_device_ntp("A", "fw1")
    gate.set()
    t.join()
    assert len(mine) == 1 and seen["other"] == []


def test_captures_nest_and_inner_failures_reach_the_outer_one():
    c = _client(lambda body, timeout=None: _envelope(rpc_code=-11))
    with c.capture_proxy_failures() as outer, c.capture_proxy_failures() as inner:
        c.get_device_ntp("A", "fw1")
    assert len(inner) == 1 and len(outer) == 1


def test_capture_records_a_device_http_error_on_a_config_read():
    for status in (403, 500):
        c = _client(lambda body, timeout=None, st=status: _envelope(http_status=st, results={}))
        with c.capture_proxy_failures() as failures:
            c.get_device_ntp("A", "fw1")
        assert failures and str(status) in failures[0]
