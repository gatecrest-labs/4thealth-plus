"""Tests for app.license_status_cache's pure aggregation logic."""

from app.license_status_cache import _classify_devices


def test_classify_devices_counts_and_details():
    devices_by_adom = {
        "Corp": [
            {
                "name": "fw-licensed",
                "license": {"status": "licensed", "expires": "2027-01-01"},
            },
            {"name": "fw-expired", "license": {"status": "expired", "expires": None}},
            {"name": "fw-unknown", "license": {"status": "unknown", "expires": None}},
        ]
    }

    result = _classify_devices(devices_by_adom)

    assert result["devices_licensed"] == 1
    assert result["devices_expired"] == 1
    assert result["devices_unknown"] == 1
    assert result["details"] == [
        {"device": "fw-expired", "adom": "Corp", "status": "expired", "expires": None},
        {"device": "fw-unknown", "adom": "Corp", "status": "unknown", "expires": None},
    ]


def test_classify_devices_details_excludes_licensed():
    devices_by_adom = {
        "Corp": [
            {"name": "fw-a", "license": {"status": "licensed", "expires": "2027-01-01"}}
        ]
    }

    result = _classify_devices(devices_by_adom)

    assert result["devices_licensed"] == 1
    assert result["details"] == []


def test_classify_devices_multiple_adoms():
    devices_by_adom = {
        "Corp": [
            {"name": "fw-a", "license": {"status": "licensed", "expires": "2027-01-01"}}
        ],
        "Branch": [{"name": "fw-b", "license": {"status": "expired", "expires": None}}],
    }

    result = _classify_devices(devices_by_adom)

    assert result["devices_licensed"] == 1
    assert result["devices_expired"] == 1
    assert result["details"] == [
        {"device": "fw-b", "adom": "Branch", "status": "expired", "expires": None}
    ]


def test_classify_devices_empty_input():
    result = _classify_devices({})
    assert result == {
        "devices_licensed": 0,
        "devices_expired": 0,
        "devices_unknown": 0,
        "details": [],
    }


def test_classify_devices_skips_entries_missing_name():
    devices_by_adom = {"Corp": [{"license": {"status": "expired", "expires": None}}]}
    result = _classify_devices(devices_by_adom)
    assert result == {
        "devices_licensed": 0,
        "devices_expired": 0,
        "devices_unknown": 0,
        "details": [],
    }


import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from app.license_status_cache import (
    _run_sweep,
    _should_skip_startup_sweep,
    get_latest,
)


def test_get_latest_returns_none_when_no_file(tmp_path, monkeypatch):
    fake_path = tmp_path / "license_status.json"
    monkeypatch.setattr("app.license_status_cache._STORE_PATH", fake_path)
    assert get_latest() is None


def test_get_latest_reads_persisted_record(tmp_path, monkeypatch):
    fake_path = tmp_path / "license_status.json"
    fake_path.write_text(
        json.dumps({"devices_licensed": 5, "collected_at": "2026-09-16T03:00:00Z"})
    )
    monkeypatch.setattr("app.license_status_cache._STORE_PATH", fake_path)
    result = get_latest()
    assert result["devices_licensed"] == 5


def test_run_sweep_persists_classified_result(tmp_path, monkeypatch):
    fake_path = tmp_path / "license_status.json"
    monkeypatch.setattr("app.license_status_cache._STORE_PATH", fake_path)

    fake_client = MagicMock()
    fake_client.get_adoms.return_value = [{"name": "Corp"}]
    fake_client.get_devices.return_value = [{"name": "fw-a"}]
    fake_client.get_device_license_status.return_value = {
        "forticare": {
            "support": {"enhanced": {"status": "licensed", "expires": 9999999999}}
        }
    }
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)

    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        result = _run_sweep(app=None)

    assert result is True
    persisted = json.loads(fake_path.read_text())
    assert persisted["devices_licensed"] == 1
    assert persisted["devices_expired"] == 0
    assert "collected_at" in persisted


def test_run_sweep_skips_forti_prefixed_adoms(tmp_path, monkeypatch):
    fake_path = tmp_path / "license_status.json"
    monkeypatch.setattr("app.license_status_cache._STORE_PATH", fake_path)

    fake_client = MagicMock()
    fake_client.get_adoms.return_value = [
        {"name": "FortiManager_Managed_Devices"},
        {"name": "Corp"},
    ]
    fake_client.get_devices.return_value = []
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)

    with patch("app.fmg_helpers.make_client", return_value=fake_client):
        _run_sweep(app=None)

    # get_devices should only be called for the non-forti* ADOM
    fake_client.get_devices.assert_called_once_with("Corp")


def test_run_sweep_overlap_returns_false():
    from app.license_status_cache import _running

    _running.set()
    try:
        assert _run_sweep(app=None) is False
    finally:
        _running.clear()


def test_should_skip_startup_sweep_no_prior_record():
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    assert _should_skip_startup_sweep(None, now) is False


def test_should_skip_startup_sweep_recent_record():
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    latest = {"collected_at": (now - timedelta(hours=2)).isoformat()}
    assert _should_skip_startup_sweep(latest, now) is True


def test_should_skip_startup_sweep_stale_record():
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    latest = {"collected_at": (now - timedelta(hours=13)).isoformat()}
    assert _should_skip_startup_sweep(latest, now) is False


def test_should_skip_startup_sweep_missing_collected_at():
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    assert _should_skip_startup_sweep({"devices_licensed": 1}, now) is False


def test_should_skip_startup_sweep_unparseable_collected_at():
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    latest = {"collected_at": "not-a-timestamp"}
    assert _should_skip_startup_sweep(latest, now) is False
