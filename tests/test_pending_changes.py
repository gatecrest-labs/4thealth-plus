import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")

import json as _json
from unittest.mock import patch

import pytest

from app.fmg_client import FMGClient, FMGError

# ── get_devices_with_sync_status ─────────────────────────────────────────────

def _make_client():
    return FMGClient(host="fmg.example.com", token="tok")


def test_get_devices_with_sync_status_returns_normalized_conf_status():
    client = _make_client()
    raw_devices = [
        {"name": "FW1", "ip": "10.0.0.1", "conf_status": 1, "platform_str": "FGT", "os_ver": 700, "mr": 4, "patch": 1, "sn": "FGT001"},
        {"name": "FW2", "ip": "10.0.0.2", "conf_status": 2, "platform_str": "FGT", "os_ver": 700, "mr": 4, "patch": 1, "sn": "FGT002"},
        {"name": "FW3", "ip": "10.0.0.3", "conf_status": 0, "platform_str": "FGT", "os_ver": 700, "mr": 4, "patch": 1, "sn": "FGT003"},
    ]
    with patch.object(client, "_get", return_value=raw_devices):
        result = client.get_devices_with_sync_status("MyADOM")
    assert len(result) == 3
    assert result[0]["conf_status"] == "insync"
    assert result[1]["conf_status"] == "outofsync"
    assert result[2]["conf_status"] == "unknown"


def test_get_devices_with_sync_status_empty_adom():
    client = _make_client()
    with patch.object(client, "_get", return_value=[]):
        result = client.get_devices_with_sync_status("EmptyADOM")
    assert result == []


# ── get_package_status ────────────────────────────────────────────────────────

def test_get_package_info_returns_name_and_status():
    # FMG 7.4.x returns "pkg" and "status" (string), not "name"/"db_status"
    client = _make_client()
    with patch.object(client, "_get", return_value={"pkg": "PROD/LMR/Device_Policy", "status": "modified"}):
        info = client.get_package_info("MyADOM", "FW1")
    assert info["pkg_name"] == "PROD/LMR/Device_Policy"
    assert info["pkg_status"] == "modified"

def test_get_package_info_returns_nomod_for_installed():
    client = _make_client()
    with patch.object(client, "_get", return_value={"pkg": "Pkg1", "status": "installed"}):
        assert client.get_package_info("MyADOM", "FW1")["pkg_status"] == "nomod"

def test_get_package_info_returns_empty_for_unassigned():
    client = _make_client()
    with patch.object(client, "_get", return_value={"status": "unassigned"}):
        info = client.get_package_info("MyADOM", "FW1")
    assert info == {"pkg_name": "", "pkg_status": ""}

def test_get_package_info_returns_empty_on_error():
    client = _make_client()
    with patch.object(client, "_get", side_effect=FMGError("not found")):
        info = client.get_package_info("MyADOM", "FW1")
    assert info == {"pkg_name": "", "pkg_status": ""}

def test_get_package_status_delegates_to_get_package_info():
    client = _make_client()
    with patch.object(client, "_get", return_value={"pkg": "Pkg", "status": "modified"}):
        assert client.get_package_status("MyADOM", "FW1") == "modified"


# ── get_install_preview ───────────────────────────────────────────────────────
#
# New chained workflow (7 _post calls for happy path):
#   1. POST securityconsole/install/package  → stage task ID
#   2. GET  task/task/<stage_id>             → stage done
#   3. POST securityconsole/install/preview  → preview task ID
#   4. GET  task/task/<preview_id>           → preview done
#   5. POST securityconsole/preview/result   → diff text
#   6. POST securityconsole/package/cancel/install → cleanup (best-effort)

def _task_response(percent, state=0, num_err=0):
    return {"result": [{"status": {"code": 0}, "data": [{"percent": percent, "state": state, "num_err": num_err}]}]}


def _trigger_response(taskid=42):
    return {"result": [{"status": {"code": 0}, "data": {"task": taskid}}]}


def _preview_result_response(device_name, diff_text):
    return {
        "result": [{
            "status": {"code": 0},
            "data": {"message": _json.dumps([{"name": device_name, "result": diff_text}])}
        }]
    }


def _cancel_response():
    return {"result": [{"status": {"code": 0}, "data": {}}]}


def _happy_path_responses(diff_text, stage_taskid=10, preview_taskid=20, device="FW1"):
    """Build the standard 6-call response sequence for a successful preview."""
    return [
        _trigger_response(taskid=stage_taskid),          # 1. install/package
        _task_response(100),                              # 2. stage poll done
        _trigger_response(taskid=preview_taskid),         # 3. install/preview
        _task_response(100),                              # 4. preview poll done
        _preview_result_response(device, diff_text),      # 5. preview/result
        _cancel_response(),                               # 6. cancel/install
    ]


_PKG_INFO_MOCK = {"pkg_name": "PROD/LMR/Device_Policy", "pkg_status": "modified"}
_PKG_INFO_NONE = {"pkg_name": "", "pkg_status": ""}


def test_get_install_preview_returns_diff_text():
    client = _make_client()
    diff = "config firewall policy\n    edit 1\n        set action accept\n    next\nend\n"
    vdoms = [{"name": "root"}]
    responses = _happy_path_responses(diff)
    with patch.object(client, "get_device_vdoms", return_value=vdoms), \
         patch.object(client, "get_package_info", return_value=_PKG_INFO_MOCK), \
         patch.object(client, "_post", side_effect=responses), \
         patch("time.sleep"):
        result = client.get_install_preview("MyADOM", "FW1")
    assert result == diff


def test_get_install_preview_polls_until_complete():
    client = _make_client()
    diff = "config system global\nend\n"
    vdoms = [{"name": "root"}]
    responses = [
        _trigger_response(taskid=5),   # 1. install/package
        _task_response(33),            # 2a. stage poll — not done
        _task_response(100),           # 2b. stage poll done
        _trigger_response(taskid=6),   # 3. install/preview
        _task_response(50),            # 4a. preview poll — not done
        _task_response(100),           # 4b. preview poll done
        _preview_result_response("FW1", diff),  # 5. result
        _cancel_response(),            # 6. cancel
    ]
    with patch.object(client, "get_device_vdoms", return_value=vdoms), \
         patch.object(client, "get_package_info", return_value=_PKG_INFO_MOCK), \
         patch.object(client, "_post", side_effect=responses), \
         patch("time.sleep"):
        result = client.get_install_preview("MyADOM", "FW1")
    assert result == diff


def test_get_install_preview_raises_on_timeout(monkeypatch):
    client = _make_client()
    monkeypatch.setattr("app.fmg_client.PREVIEW_TIMEOUT_SECS", 0)
    vdoms = [{"name": "root"}]

    call_count = [0]
    def side_effect(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _trigger_response(taskid=7)  # install/package accepted
        return _task_response(50)               # all polls → 50% → timeout

    with patch.object(client, "get_device_vdoms", return_value=vdoms), \
         patch.object(client, "get_package_info", return_value=_PKG_INFO_MOCK), \
         patch.object(client, "_post", side_effect=side_effect), \
         patch("time.sleep"), pytest.raises(FMGError, match="timed out"):
        client.get_install_preview("MyADOM", "FW1")


def test_get_install_preview_returns_empty_string_when_no_changes():
    client = _make_client()
    vdoms = [{"name": "root"}]
    responses = [
        _trigger_response(taskid=3),   # install/package
        _task_response(100),           # stage done
        _trigger_response(taskid=4),   # install/preview
        _task_response(100),           # preview done
        {"result": [{"status": {"code": 0}, "data": {"message": "[]"}}]},
        _cancel_response(),            # cancel
    ]
    with patch.object(client, "get_device_vdoms", return_value=vdoms), \
         patch.object(client, "get_package_info", return_value=_PKG_INFO_MOCK), \
         patch.object(client, "_post", side_effect=responses), \
         patch("time.sleep"):
        result = client.get_install_preview("MyADOM", "FW1")
    assert result == ""


def test_get_install_preview_returns_empty_when_both_stage_and_preview_fail():
    """In-sync device: both install/package and install/preview rejected → empty string."""
    client = _make_client()
    vdoms = [{"name": "root"}]
    responses = [
        {"result": [{"status": {"code": -6}, "data": {}}]},  # install/package rejected
        {"result": [{"status": {"code": -6}, "data": {}}]},  # install/preview also rejected
    ]
    with patch.object(client, "get_device_vdoms", return_value=vdoms), \
         patch.object(client, "get_package_info", return_value=_PKG_INFO_MOCK), \
         patch.object(client, "_post", side_effect=responses), \
         patch("time.sleep"):
        result = client.get_install_preview("MyADOM", "FW1")
    assert result == ""


def test_get_install_preview_returns_empty_when_no_pkg_name():
    """No pkg assigned: nothing to stage, so no FMG calls are made at all."""
    client = _make_client()
    vdoms = [{"name": "root"}]
    with patch.object(client, "get_device_vdoms", return_value=vdoms), \
         patch.object(client, "get_package_info", return_value=_PKG_INFO_NONE), \
         patch.object(client, "_post", side_effect=AssertionError("should not be called")), \
         patch("time.sleep"):
        result = client.get_install_preview("MyADOM", "FW1")
    assert result == ""


def test_get_install_preview_raises_on_task_error_state():
    """Task accepted but fails mid-run (num_err > 0) — must propagate, not return empty."""
    client = _make_client()
    vdoms = [{"name": "root"}]
    responses = [
        _trigger_response(taskid=10),    # install/package accepted
        _task_response(100, num_err=1),  # stage task fails with num_err
        _cancel_response(),              # finally: cancel staging lock
    ]
    with patch.object(client, "get_device_vdoms", return_value=vdoms), \
         patch.object(client, "get_package_info", return_value=_PKG_INFO_MOCK), \
         patch.object(client, "_post", side_effect=responses), \
         patch("time.sleep"), pytest.raises(FMGError, match="Stage:.*task 10 for FW1 failed"):
        client.get_install_preview("MyADOM", "FW1")


def test_get_install_preview_cleanup_runs_even_if_result_fails():
    """Cancel/install must be called even when preview/result returns an error."""
    client = _make_client()
    vdoms = [{"name": "root"}]
    responses = [
        _trigger_response(taskid=10),
        _task_response(100),
        _trigger_response(taskid=11),
        _task_response(100),
        {"result": [{"status": {"code": -1}, "data": {}}]},  # result fails
        _cancel_response(),
    ]
    post_calls = []
    def tracking_post(body):
        post_calls.append(body)
        return responses[len(post_calls) - 1]

    with patch.object(client, "get_device_vdoms", return_value=vdoms), \
         patch.object(client, "get_package_info", return_value=_PKG_INFO_MOCK), \
         patch.object(client, "_post", side_effect=tracking_post), \
         patch("time.sleep"):
        result = client.get_install_preview("MyADOM", "FW1")

    urls = [c.get("params", [{}])[0].get("url", "") for c in post_calls]
    assert any("cancel" in u for u in urls), "cancel/install was not called"
    assert result == ""


# ── parse_preview_diff ────────────────────────────────────────────────────────

def test_parse_preview_diff_empty():
    from app.fmg_client import parse_preview_diff
    result = parse_preview_diff("")
    assert result["summary"] == {"firewall_policy": 0, "routing": 0, "address": 0, "service": 0, "system": 0, "other": 0}
    assert result["vdoms"] == [{"name": "root", "changes": []}]


def test_parse_preview_diff_categorises_firewall_policy():
    from app.fmg_client import parse_preview_diff
    raw = "config firewall policy\n    edit 1\n        set action accept\n    next\nend\n"
    result = parse_preview_diff(raw)
    assert result["summary"]["firewall_policy"] == 1
    assert result["summary"]["routing"] == 0
    assert len(result["vdoms"]) == 1
    assert result["vdoms"][0]["name"] == "root"
    assert len(result["vdoms"][0]["changes"]) > 0


def test_parse_preview_diff_categorises_routing():
    from app.fmg_client import parse_preview_diff
    raw = "config router static\n    edit 1\n        set dst 10.0.0.0 255.0.0.0\n    next\nend\n"
    result = parse_preview_diff(raw)
    assert result["summary"]["routing"] == 1


def test_parse_preview_diff_splits_vdoms():
    from app.fmg_client import parse_preview_diff
    raw = (
        "vdom root\nconfig firewall policy\n    edit 1\nend\n"
        "vdom dmz\nconfig system global\nend\n"
    )
    result = parse_preview_diff(raw)
    names = [v["name"] for v in result["vdoms"]]
    assert "root" in names
    assert "dmz" in names


def test_parse_preview_diff_raw_preserved():
    from app.fmg_client import parse_preview_diff
    raw = "config firewall policy\nend\n"
    result = parse_preview_diff(raw)
    assert result["raw"] == raw


def test_parse_preview_diff_nested_config_vdom_format():
    """FMG wraps each vdom's diff in 'config vdom / edit <name>' blocks."""
    from app.fmg_client import parse_preview_diff
    raw = (
        "config vdom\n"
        "    edit root\n"
        "    config firewall address\n"
        "        edit \"host-1\"\n"
        "            set subnet 10.0.0.1 255.255.255.255\n"
        "        next\n"
        "    end\n"
        "    next\n"
        "end\n"
        "config vdom\n"
        "    edit LOHOEX99\n"
        "    config firewall policy\n"
        "        edit 10033\n"
        "            set action accept\n"
        "        next\n"
        "    end\n"
        "    next\n"
        "end\n"
    )
    result = parse_preview_diff(raw)
    names = [v["name"] for v in result["vdoms"]]
    assert "root" in names
    assert "LOHOEX99" in names
    # LOHOEX99 block should have firewall policy changes
    loho = next(v for v in result["vdoms"] if v["name"] == "LOHOEX99")
    assert len(loho["changes"]) > 0


def test_parse_preview_diff_nested_single_vdom():
    """Single config vdom block falls back correctly."""
    from app.fmg_client import parse_preview_diff
    raw = (
        "config vdom\n"
        "    edit PROD\n"
        "    config system global\n"
        "        set hostname myfw\n"
        "    end\n"
        "    next\n"
        "end\n"
    )
    result = parse_preview_diff(raw)
    assert result["vdoms"][0]["name"] == "PROD"
    assert len(result["vdoms"][0]["changes"]) > 0


# ── Route smoke tests ─────────────────────────────────────────────────────────

@pytest.fixture
def app():
    os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")
    from app import create_app
    return create_app()

@pytest.fixture
def client(app):
    return app.test_client()

def test_pending_changes_page_redirects_unauthenticated(client):
    resp = client.get("/pending-changes")
    assert resp.status_code in (302, 401)

def test_pending_changes_adoms_redirects_unauthenticated(client):
    resp = client.get("/api/pending-changes/adoms")
    assert resp.status_code in (302, 401)

def test_pending_changes_devices_redirects_unauthenticated(client):
    resp = client.get("/api/pending-changes/adoms/MyADOM/devices")
    assert resp.status_code in (302, 401)


# ── Task store / async preview ────────────────────────────────────────────────

def test_pending_changes_preview_returns_task_id_unauthenticated(client):
    """POST preview rejects unauthenticated requests (not 404/405).
    400 is also valid — CSRF check fires before auth redirect for POST."""
    resp = client.post(
        "/api/pending-changes/adoms/MyADOM/device/FW1/preview",
        json={},
    )
    assert resp.status_code in (302, 400, 401)


def test_pending_changes_task_poll_unauthenticated(client):
    """GET /api/pending-changes/task/<id> redirects unauthenticated users."""
    resp = client.get("/api/pending-changes/task/nonexistent-task-id")
    assert resp.status_code in (302, 401)
