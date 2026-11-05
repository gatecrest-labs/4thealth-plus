"""Run the real FMGClient / self-test against recorded FortiManager answers.

One fixture directory per FMG release under tests/fixtures/fmg_<version>/,
captured with scripts/record_fmg_fixture.py. Dropping a new directory in is
enough to put that release under test (add its expectations to EXPECTED).
"""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from pathlib import Path

import pytest

from app.fmg_client import FMGClient, parse_preview_diff
from app.fmg_helpers import format_fortios_version
from app.fmg_recorder import ReplayTransport
from app.fmg_selftest import run_selftest

FIXTURES = Path(__file__).parent / "fixtures"

# fixture dir -> (train, self-test summary). The lab token for 8.0.2 had no
# permission on performance/usage/audit-log, hence 3 denied (FMG code -11).
EXPECTED = {
    "fmg_8.0.2": ("8.0", {"ok": 14, "denied": 3, "error": 0, "skipped": 0}),
}


def _client(name):
    c = FMGClient(host="fmg.invalid", token="fixture")
    c._post = ReplayTransport(
        FIXTURES / name / "exchanges.json",
        loose_urls=("/sys/audit-log",),  # query window is relative to "now"
    ).post
    return c


def test_every_fixture_directory_has_expectations():
    found = {p.parent.name for p in FIXTURES.glob("fmg_*/exchanges.json")}
    assert found == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_version_is_detected(name):
    assert _client(name).version.train == EXPECTED[name][0]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_selftest_passes_offline_with_expected_summary(name):
    report = run_selftest(_client(name))
    assert report["summary"] == EXPECTED[name][1], [
        (c["id"], c["status"], c["message"]) for c in report["checks"]
    ]
    assert report["train"] == EXPECTED[name][0]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_denied_checks_are_permission_errors_not_empty_data(name):
    report = run_selftest(_client(name))
    denied = {c["id"] for c in report["checks"] if c["status"] == "denied"}
    assert denied <= {"resource_performance", "resource_usage", "audit_log"}


def test_8_0_2_device_record_renders_as_v8_0_2():
    c = _client("fmg_8.0.2")
    devices = c.get_devices("root")  # the ADOM the capture sampled
    versions = {format_fortios_version(d) for d in devices if d.get("os_ver")}
    assert "v8.0.2" in versions


def _preview(monkeypatch, logs=None):
    import app.fmg_client as fc

    monkeypatch.setattr(fc.time, "sleep", lambda *_: None)
    if logs is not None:
        import app.app_logger as al

        monkeypatch.setattr(
            al, "app_log", lambda level, src, msg, *a, **k: logs.append(msg)
        )
    return _client("fmg_8.0.2").get_install_preview("root", "FortiWiFi-71G")


def test_8_0_2_install_preview_returns_the_diff(monkeypatch):
    raw = _preview(monkeypatch)
    assert "=== Preview result ===" in raw
    assert "config firewall policy\n    delete 6\nend" in raw


def test_8_0_2_diff_comes_from_the_stage_task_not_the_preview_task(monkeypatch):
    # FMG 7.4.x answers on the preview task; 7.6.7 and 8.0.2 only on the stage task.
    logs = []
    _preview(monkeypatch, logs)
    assert any("diff_source=stage_task" in m for m in logs), logs


def test_8_0_2_preview_parses_into_a_removed_policy_line(monkeypatch):
    parsed = parse_preview_diff(_preview(monkeypatch))
    removed = [
        c["line"]
        for v in parsed["vdoms"]
        for c in v["changes"]
        if c["type"] == "remove"
    ]
    assert any("delete 6" in line for line in removed), parsed["vdoms"]
    assert parsed["summary"]["firewall_policy"] >= 1


def test_8_0_2_preview_cancels_the_pending_install_lock(monkeypatch):
    # The fixture only replays; this asserts the chain the client walks ends in cancel.
    import app.fmg_client as fc

    urls = []
    transport = ReplayTransport(FIXTURES / "fmg_8.0.2" / "exchanges.json").post

    def spy(body):
        urls.append(body["params"][0]["url"])
        return transport(body)

    monkeypatch.setattr(fc.time, "sleep", lambda *_: None)
    c = FMGClient(host="fmg.invalid", token="fixture")
    c._post = spy
    c.get_install_preview("root", "FortiWiFi-71G")
    assert urls[-1] == "/securityconsole/package/cancel/install"
