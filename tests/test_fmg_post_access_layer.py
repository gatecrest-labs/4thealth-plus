"""F1: the real FMGClient._post with a scripted fake HTTP session."""

import threading

import pytest
import requests
import urllib3

from app import fmg_access
from app.config import Config
from app.fmg_client import FMGClient

GET = {"id": 1, "method": "get", "params": [{"url": "/sys/status"}]}
EXEC = {
    "id": 2,
    "method": "exec",
    "params": [{"url": "/securityconsole/install/package"}],
}
OK_BODY = {"result": [{"status": {"code": 0, "message": "OK"}}]}


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else OK_BODY

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, script):
        self.script = list(script)
        self.posts = 0
        self.closed = False

    def post(self, *a, **kw):
        self.posts += 1
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


def refused():
    return requests.ConnectionError(
        urllib3.exceptions.NewConnectionError(
            None, "Failed to establish a new connection"
        )
    )


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    fmg_access.reset()
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 4)
    monkeypatch.setattr(Config, "FMG_RETRIES", 2)
    monkeypatch.setattr(fmg_access, "sleep", lambda s: None)
    yield
    fmg_access.reset()


def client(script):
    c = FMGClient(host="fmg.example", token="t")
    c._http = FakeSession(script)
    return c


def test_get_retried_on_503_then_succeeds():
    c = client([Resp(503), Resp(503), Resp(200)])
    assert c._post(GET) == OK_BODY
    assert c._http.posts == 3


def test_get_gives_up_after_retries_and_raises():
    c = client([Resp(503), Resp(503), Resp(503)])
    with pytest.raises(requests.HTTPError):
        c._post(GET)
    assert c._http.posts == 3


def test_exec_not_retried_on_503():
    c = client([Resp(503), Resp(200)])
    with pytest.raises(requests.HTTPError):
        c._post(EXEC)
    assert c._http.posts == 1


def test_exec_not_retried_on_read_timeout():
    c = client([requests.ReadTimeout("slow"), Resp(200)])
    with pytest.raises(requests.ReadTimeout):
        c._post(EXEC)
    assert c._http.posts == 1


def test_exec_not_retried_on_midflight_connection_reset():
    c = client([requests.ConnectionError("Connection aborted: reset"), Resp(200)])
    with pytest.raises(requests.ConnectionError):
        c._post(EXEC)
    assert c._http.posts == 1


def test_exec_retried_on_connection_refused_before_send():
    c = client([refused(), Resp(200)])
    assert c._post(EXEC) == OK_BODY
    assert c._http.posts == 2


def test_get_retried_on_read_timeout():
    c = client([requests.ReadTimeout("slow"), Resp(200)])
    assert c._post(GET) == OK_BODY
    assert c._http.posts == 2


def test_fmg_level_error_code_not_retried():
    err = {"result": [{"status": {"code": -11, "message": "No permission"}}]}
    c = client([Resp(200, err), Resp(200)])
    assert c._post(GET) == err
    assert c._http.posts == 1


def test_retries_zero_disables_retry(monkeypatch):
    monkeypatch.setattr(Config, "FMG_RETRIES", 0)
    c = client([Resp(503), Resp(200)])
    with pytest.raises(requests.HTTPError):
        c._post(GET)
    assert c._http.posts == 1


def test_backoff_sleep_happens_outside_the_slot(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 1)
    a = client([Resp(503), Resp(200)])
    b = client([Resp(200)])
    finished = []

    def sleeper(_s):
        t = threading.Thread(target=lambda: finished.append(b._post(GET)), daemon=True)
        t.start()
        t.join(2.0)

    monkeypatch.setattr(fmg_access, "sleep", sleeper)
    assert a._post(GET) == OK_BODY
    assert finished == [OK_BODY]


def test_backoff_delay_bounds():
    for attempt in range(1, 8):
        for _ in range(50):
            d = fmg_access.backoff_delay(attempt)
            assert 0.25 <= d <= 8.0
    assert max(fmg_access.backoff_delay(1) for _ in range(50)) <= 0.5


def test_exit_does_not_close_shared_session():
    c = FMGClient(host="fmg.example", token="t")
    shared = c._http
    assert shared is fmg_access.get_session(c.verify_ssl)
    closed = []
    shared.close = lambda: closed.append(1)
    with c:
        pass
    assert closed == []
    assert fmg_access.get_session(c.verify_ssl) is shared


def test_inflight_zero_restores_unlimited_behaviour(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 0)
    c = client([Resp(200)])
    assert c._post(GET) == OK_BODY
