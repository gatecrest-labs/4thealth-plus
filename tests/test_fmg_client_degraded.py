import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import MagicMock

import pytest

NO_PERMISSION = {
    "result": [
        {
            "url": "/sys/resource/performance",
            "status": {"code": -11, "message": "No permission for the resource"},
        }
    ]
}
OK = {"result": [{"status": {"code": 0, "message": "OK"}, "data": {"cpu": 12}}]}


def _client(response):
    from app.fmg_client import FMGClient

    c = FMGClient(host="fmg.example.com", token="tok")
    c._post = MagicMock(return_value=response)
    return c


def test_get_raises_fmgerror_carrying_the_fmg_status_code():
    from app.fmg_client import FMGError

    c = _client(NO_PERMISSION)
    with pytest.raises(FMGError) as exc:
        c._get("/sys/resource/performance")
    assert exc.value.code == -11


def test_fmgerror_code_defaults_to_none():
    from app.fmg_client import FMGError

    assert FMGError("plain").code is None


def test_swallowed_performance_failure_is_recorded_but_still_returns_empty():
    c = _client(NO_PERMISSION)
    assert c.get_performance() == {}
    entry = c.degraded["get_performance"]
    assert entry["code"] == -11
    assert entry["url"] == "/sys/resource/performance"
    assert "No permission" in entry["message"]


def test_swallowed_resource_usage_failure_is_recorded():
    c = _client(NO_PERMISSION)
    assert c.get_resource_usage() == {}
    assert c.degraded["get_resource_usage"]["code"] == -11


def test_audit_log_non_zero_status_is_recorded_not_silent():
    c = _client(NO_PERMISSION)
    assert c.get_audit_log(24) == []
    assert c.degraded["get_audit_log"]["code"] == -11


def test_audit_log_network_exception_is_recorded_with_no_code():
    from app.fmg_client import FMGClient

    c = FMGClient(host="fmg.example.com", token="tok")
    c._post = MagicMock(side_effect=ConnectionError("down"))
    assert c.get_audit_log(24) == []
    assert c.degraded["get_audit_log"]["code"] is None
    assert "down" in c.degraded["get_audit_log"]["message"]


def test_successful_calls_leave_degraded_empty():
    c = _client(OK)
    assert c.get_performance() == {"cpu": 12}
    assert c.degraded == {}
