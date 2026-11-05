import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")

import threading
import time
from unittest.mock import patch

import pytest

from app.fmg_client import FMGClient, FMGError

HOST = "https://fmg.example.com/jsonrpc"


@pytest.fixture(autouse=True)
def _lock_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("app.fmg_client._PREVIEW_LOCK_DIR", str(tmp_path))


# ── the lock itself ──────────────────────────────────────────────────────────


def test_same_adom_is_mutually_exclusive():
    from app.fmg_client import _adom_preview_lock

    with (
        _adom_preview_lock(HOST, "root", wait_secs=5),
        pytest.raises(FMGError, match="another install preview"),
        _adom_preview_lock(HOST, "root", wait_secs=0.3),
    ):
        pytest.fail("second holder must not get the lock")


def test_different_adom_or_host_does_not_block():
    from app.fmg_client import _adom_preview_lock

    with (
        _adom_preview_lock(HOST, "root", wait_secs=5),
        _adom_preview_lock(HOST, "other", wait_secs=0.3),
        _adom_preview_lock("https://fmg2.example.com/jsonrpc", "root", wait_secs=0.3),
    ):
        pass


def test_lock_is_released_after_normal_exit_and_after_exception():
    from app.fmg_client import _adom_preview_lock

    with _adom_preview_lock(HOST, "root", wait_secs=1):
        pass
    with pytest.raises(RuntimeError), _adom_preview_lock(HOST, "root", wait_secs=1):
        raise RuntimeError("boom")
    with _adom_preview_lock(HOST, "root", wait_secs=0.3):
        pass  # would raise FMGError if either earlier holder leaked the lock


def test_waiter_proceeds_once_holder_releases():
    from app.fmg_client import _adom_preview_lock

    order = []
    holding = threading.Event()

    def holder():
        with _adom_preview_lock(HOST, "root", wait_secs=5):
            holding.set()
            time.sleep(0.4)
            order.append("holder-done")

    t = threading.Thread(target=holder)
    t.start()
    holding.wait(2)
    with _adom_preview_lock(HOST, "root", wait_secs=5):
        order.append("waiter-in")
    t.join()
    assert order == ["holder-done", "waiter-in"]


def test_adom_names_with_odd_characters_are_safe_in_lock_filename(tmp_path):
    from app.fmg_client import _adom_preview_lock

    with _adom_preview_lock(HOST, "../../etc/Enterprise Services", wait_secs=1):
        pass
    assert all(p.parent == tmp_path for p in tmp_path.rglob("*"))


# ── configuration ────────────────────────────────────────────────────────────


def test_env_int_reads_valid_value_and_falls_back_on_bad_input(monkeypatch):
    from app.fmg_client import _env_int

    monkeypatch.setenv("X_TEST", "240")
    assert _env_int("X_TEST", 120) == 240
    monkeypatch.setenv("X_TEST", "abc")
    assert _env_int("X_TEST", 120) == 120
    monkeypatch.setenv("X_TEST", "0")
    assert _env_int("X_TEST", 120) == 120  # non-positive is rejected
    monkeypatch.delenv("X_TEST")
    assert _env_int("X_TEST", 120) == 120


def test_defaults_are_unchanged():
    from app import fmg_client

    assert fmg_client.PREVIEW_TIMEOUT_SECS == 120 or os.environ.get(
        "FMG_PREVIEW_TIMEOUT_SECS"
    )


# ── get_install_preview uses the lock ────────────────────────────────────────

_PKG = {"pkg_name": "PKG", "pkg_status": "modified"}


def _client():
    return FMGClient(host="fmg.example.com", token="tok")


def test_get_install_preview_waits_behind_another_preview_in_same_adom(monkeypatch):
    from app.fmg_client import _adom_preview_lock

    monkeypatch.setattr("app.fmg_client.PREVIEW_LOCK_WAIT_SECS", 0.3)
    c = _client()
    with (
        patch.object(c, "get_device_vdoms", return_value=[{"name": "root"}]),
        patch.object(c, "get_package_info", return_value=_PKG),
        patch.object(c, "_post") as post,
    ):
        with (
            _adom_preview_lock(c.base_url, "MyADOM", wait_secs=5),
            pytest.raises(FMGError, match="another install preview"),
        ):
            c.get_install_preview("MyADOM", "FW1")
        # Nothing was staged on the FMG while the lock was unavailable.
        post.assert_not_called()


def test_get_install_preview_releases_lock_when_it_fails(monkeypatch):
    from app.fmg_client import _adom_preview_lock

    c = _client()
    with (
        patch.object(c, "get_device_vdoms", return_value=[{"name": "root"}]),
        patch.object(c, "get_package_info", return_value=_PKG),
        patch.object(c, "_post", side_effect=ConnectionError("down")),
        pytest.raises(Exception),
    ):
        c.get_install_preview("MyADOM", "FW1")
    with _adom_preview_lock(c.base_url, "MyADOM", wait_secs=0.3):
        pass


def test_get_install_preview_with_nothing_to_stage_does_not_take_the_lock():
    from app.fmg_client import _adom_preview_lock

    c = _client()
    with (
        patch.object(c, "get_device_vdoms", return_value=[{"name": "root"}]),
        patch.object(
            c, "get_package_info", return_value={"pkg_name": "", "pkg_status": ""}
        ),
        _adom_preview_lock(c.base_url, "MyADOM", wait_secs=5),
    ):
        # Returns without waiting on the held lock: nothing needed staging.
        assert c.get_install_preview("MyADOM", "FW1") == ""


# ── observability ────────────────────────────────────────────────────────────


def test_timeout_message_mentions_possible_queueing_and_the_setting(monkeypatch):
    monkeypatch.setattr("app.fmg_client.PREVIEW_TIMEOUT_SECS", 0)
    c = _client()
    trigger = {"result": [{"status": {"code": 0}, "data": {"task": 7}}]}
    running = {
        "result": [{"status": {"code": 0}, "data": [{"percent": 50, "num_err": 0}]}]
    }
    seq = iter([trigger] + [running] * 5)
    with (
        patch.object(c, "get_device_vdoms", return_value=[{"name": "root"}]),
        patch.object(c, "get_package_info", return_value=_PKG),
        patch.object(c, "_post", side_effect=lambda *a, **k: next(seq)),
        patch("time.sleep"),
        pytest.raises(FMGError) as exc,
    ):
        c.get_install_preview("MyADOM", "FW1")
    assert "FMG_PREVIEW_TIMEOUT_SECS" in str(exc.value)


def test_result_log_names_which_task_id_supplied_the_diff():
    c = _client()
    logs = []
    trigger = lambda t: {"result": [{"status": {"code": 0}, "data": {"task": t}}]}
    done = {
        "result": [{"status": {"code": 0}, "data": [{"percent": 100, "num_err": 0}]}]
    }
    import json

    def result(msg):
        return {"result": [{"status": {"code": 0}, "data": {"message": msg}}]}

    empty = json.dumps([{"name": "FW1", "result": "=== No preview result ==="}])
    full = json.dumps([{"name": "FW1", "result": "config system global\nend\n"}])
    cancel = {"result": [{"status": {"code": 0}, "data": {}}]}
    # preview-task id yields nothing, stage-task id yields the diff (the 7.6/8.0 behaviour)
    seq = iter(
        [trigger(10), done, trigger(20), done, result(empty), result(full), cancel]
    )
    with (
        patch.object(c, "get_device_vdoms", return_value=[{"name": "root"}]),
        patch.object(c, "get_package_info", return_value=_PKG),
        patch.object(c, "_post", side_effect=lambda *a, **k: next(seq)),
        patch(
            "app.app_logger.app_log",
            side_effect=lambda lvl, comp, msg, **k: logs.append(msg),
        ),
        patch("time.sleep"),
    ):
        out = c.get_install_preview("MyADOM", "FW1")
    assert "config system global" in out
    assert any("diff_source=stage_task" in m and "taskid=10" in m for m in logs), logs
