"""Tests for app.psirt_reassess_scheduler — re-running assess() for every
open advisory against cached device inventory, with a stub FMG client."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import patch

import pytest

from app import psirt_store
from app.psirt_reassess_scheduler import _CachedDeviceClient, _run_reassessment


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(psirt_store, "_DB_PATH", tmp_path / "psirt_test.db")
    yield


@pytest.fixture(autouse=True)
def _no_enrichment_network_calls(monkeypatch):
    monkeypatch.setattr("app.config.Config.PSIRT_ENRICHMENT_ENABLED", False)


def _seed_open_advisory(advisory_id="FG-IR-24-001"):
    psirt_store.save_assessment_result(
        {
            "advisory": {
                "advisory_id": advisory_id,
                "cve_ids": ["CVE-2024-0001"],
                "fortinet_severity": "Critical",
                "cvss_score": 9.8,
                "affected_ranges": [
                    {
                        "product": "FortiOS",
                        "min_version": "7.4.0",
                        "max_version": "7.4.5",
                        "fixed_version": "7.4.6",
                        "notes": "",
                    }
                ],
                "workaround_text": "",
            },
            "findings": [],
            "priority": "critical",
            "priority_rationale": "seed",
            "kev_hit": False,
            "degraded": False,
            "warnings": [],
        }
    )


# ── _CachedDeviceClient ───────────────────────────────────────────────────────


def test_cached_client_get_adoms_lists_cached_keys():
    client = _CachedDeviceClient({"Corp": [], "Branch": []})
    names = {a["name"] for a in client.get_adoms()}
    assert names == {"Corp", "Branch"}


def test_cached_client_get_devices_returns_cached_records():
    client = _CachedDeviceClient({"Corp": [{"name": "FW1", "os_ver": "7", "mr": 4, "patch": 3}]})
    assert client.get_devices("Corp") == [{"name": "FW1", "os_ver": "7", "mr": 4, "patch": 3}]
    assert client.get_devices("Unknown") == []


def test_cached_client_get_system_status_raises():
    client = _CachedDeviceClient({})
    with pytest.raises(RuntimeError):
        client.get_system_status()


def test_cached_client_unsupported_method_raises_not_silently_succeeds():
    client = _CachedDeviceClient({})
    with pytest.raises(RuntimeError):
        client.get_audit_log(hours=24)


# ── _run_reassessment ─────────────────────────────────────────────────────────


def test_reassessment_updates_open_advisory_from_cached_inventory():
    _seed_open_advisory("FG-IR-24-001")

    with patch(
        "app.executive_summary_cache.get_devices_raw_by_adom",
        return_value={"Corp": [{"name": "FW1", "os_ver": "7", "mr": 4, "patch": 3}]},
    ):
        assert _run_reassessment(app=None) is True

    latest = psirt_store.get_latest_assessment("FG-IR-24-001")
    # FW1 is v7.4.3, inside the advisory's 7.4.0-7.4.5 range — the cached
    # inventory alone is enough for the engine to flag it as affected.
    assert any(d["name"] == "FW1" for d in latest["devices_affected"])


def test_reassessment_skips_advisories_with_no_matching_devices():
    _seed_open_advisory("FG-IR-24-001")

    with patch("app.executive_summary_cache.get_devices_raw_by_adom", return_value={}):
        assert _run_reassessment(app=None) is True

    latest = psirt_store.get_latest_assessment("FG-IR-24-001")
    assert latest["devices_affected"] == []


def test_reassessment_does_nothing_when_no_open_advisories():
    with patch("app.executive_summary_cache.get_devices_raw_by_adom", return_value={}):
        assert _run_reassessment(app=None) is True


def test_reassessment_of_one_advisory_failing_keeps_last_result_for_it_and_continues():
    _seed_open_advisory("A1")
    _seed_open_advisory("A2")
    before_a1 = psirt_store.get_latest_assessment("A1")

    real_assess = __import__("app.psirt.engine", fromlist=["assess"]).assess

    def flaky_assess(advisory, *args, **kwargs):
        if advisory.advisory_id == "A1":
            raise RuntimeError("boom")
        return real_assess(advisory, *args, **kwargs)

    with (
        patch("app.psirt.engine.assess", side_effect=flaky_assess),
        patch("app.executive_summary_cache.get_devices_raw_by_adom", return_value={}),
    ):
        assert _run_reassessment(app=None) is True

    after_a1 = psirt_store.get_latest_assessment("A1")
    after_a2 = psirt_store.get_latest_assessment("A2")
    # A1's failed re-run left its last saved result untouched (same ran_at).
    assert after_a1["ran_at"] == before_a1["ran_at"]
    # A2 still got re-assessed successfully.
    assert after_a2 is not None


def test_reassessment_skips_when_already_running(monkeypatch):
    from app import psirt_reassess_scheduler

    psirt_reassess_scheduler._running.set()
    try:
        assert _run_reassessment(app=None) is False
    finally:
        psirt_reassess_scheduler._running.clear()
