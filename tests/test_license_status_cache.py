"""Tests for app.license_status_cache's pure aggregation logic."""

from datetime import date

from app.license_status_cache import (
    _build_firmware_version,
    _classify_devices,
    compute_expiring_soon,
)


def test_classify_devices_counts_and_details():
    devices_by_adom = {
        "Corp": [
            {
                "name": "fw-licensed",
                "license": {"status": "licensed", "expires": "2027-01-01"},
                "firmware": "v7.4.5",
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


def test_classify_devices_all_devices_includes_every_status_with_firmware():
    devices_by_adom = {
        "Corp": [
            {
                "name": "fw-licensed",
                "license": {
                    "status": "licensed",
                    "expires": "2027-01-01",
                    "subscriptions": {
                        "antivirus": {"status": "licensed", "expires": None}
                    },
                },
                "firmware": "v7.4.5",
            },
            {
                "name": "fw-expired",
                "license": {"status": "expired", "expires": None},
                "firmware": "v7.2.1",
            },
        ]
    }

    result = _classify_devices(devices_by_adom)

    assert result["all_devices"] == [
        {
            "device": "fw-licensed",
            "adom": "Corp",
            "status": "licensed",
            "expires": "2027-01-01",
            "firmware": "v7.4.5",
            "subscriptions": {"antivirus": {"status": "licensed", "expires": None}},
        },
        {
            "device": "fw-expired",
            "adom": "Corp",
            "status": "expired",
            "expires": None,
            "firmware": "v7.2.1",
            "subscriptions": {},
        },
    ]


def test_classify_devices_all_devices_defaults_firmware_to_na():
    devices_by_adom = {
        "Corp": [{"name": "fw-a", "license": {"status": "licensed", "expires": None}}]
    }
    result = _classify_devices(devices_by_adom)
    assert result["all_devices"][0]["firmware"] == "n/a"


def test_classify_devices_all_devices_defaults_subscriptions_to_empty_dict():
    devices_by_adom = {
        "Corp": [{"name": "fw-a", "license": {"status": "licensed", "expires": None}}]
    }
    result = _classify_devices(devices_by_adom)
    assert result["all_devices"][0]["subscriptions"] == {}


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
        "all_devices": [],
    }


def test_classify_devices_skips_entries_missing_name():
    devices_by_adom = {"Corp": [{"license": {"status": "expired", "expires": None}}]}
    result = _classify_devices(devices_by_adom)
    assert result == {
        "devices_licensed": 0,
        "devices_expired": 0,
        "devices_unknown": 0,
        "details": [],
        "all_devices": [],
    }


def test_build_firmware_version_major_mr_patch():
    assert _build_firmware_version({"os_ver": 700, "mr": 4, "patch": 5}) == "v7.4.5"


def test_build_firmware_version_major_mr_only():
    assert _build_firmware_version({"os_ver": 700, "mr": 4, "patch": None}) == "v7.4"


def test_build_firmware_version_missing_fields():
    assert _build_firmware_version({}) == "n/a"


_AS_OF = date(2026, 9, 16)


def test_compute_expiring_soon_buckets_are_cumulative():
    all_devices = [
        {
            "device": "fw-10d",
            "adom": "Corp",
            "status": "licensed",
            "expires": "2026-09-26",
        },
        {
            "device": "fw-45d",
            "adom": "Corp",
            "status": "licensed",
            "expires": "2026-10-31",
        },
        {
            "device": "fw-75d",
            "adom": "Corp",
            "status": "licensed",
            "expires": "2026-11-30",
        },
    ]
    result = compute_expiring_soon(all_devices, as_of=_AS_OF)
    assert result["devices_expiring_30"] == 1
    assert result["devices_expiring_60"] == 2
    assert result["devices_expiring_90"] == 3
    assert [d["device"] for d in result["expiring_soon"]] == [
        "fw-10d",
        "fw-45d",
        "fw-75d",
    ]
    assert result["expiring_soon"][0]["days_until"] == 10


def test_compute_expiring_soon_excludes_beyond_90_days():
    all_devices = [
        {
            "device": "fw-far",
            "adom": "Corp",
            "status": "licensed",
            "expires": "2027-06-01",
        }
    ]
    result = compute_expiring_soon(all_devices, as_of=_AS_OF)
    assert result == {
        "devices_expiring_30": 0,
        "devices_expiring_60": 0,
        "devices_expiring_90": 0,
        "expiring_soon": [],
    }


def test_compute_expiring_soon_ignores_non_licensed_and_missing_expiry():
    all_devices = [
        {"device": "fw-expired", "adom": "Corp", "status": "expired", "expires": None},
        {"device": "fw-unknown", "adom": "Corp", "status": "unknown", "expires": None},
        {"device": "fw-no-date", "adom": "Corp", "status": "licensed", "expires": None},
    ]
    result = compute_expiring_soon(all_devices, as_of=_AS_OF)
    assert result["expiring_soon"] == []


def test_compute_expiring_soon_ignores_malformed_expiry():
    all_devices = [
        {
            "device": "fw-bad",
            "adom": "Corp",
            "status": "licensed",
            "expires": "not-a-date",
        }
    ]
    result = compute_expiring_soon(all_devices, as_of=_AS_OF)
    assert result["expiring_soon"] == []


def test_compute_expiring_soon_empty_input():
    assert compute_expiring_soon([], as_of=_AS_OF) == {
        "devices_expiring_30": 0,
        "devices_expiring_60": 0,
        "devices_expiring_90": 0,
        "expiring_soon": [],
    }


import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from app.license_status_cache import (
    _run_sweep,
    _should_skip_startup_sweep,
    get_latest,
    is_running,
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
    from app.license_status import FORTIGUARD_SUBSCRIPTION_KEYS

    no_subs = {
        key: {"status": "unknown", "expires": None}
        for key in FORTIGUARD_SUBSCRIPTION_KEYS
    }
    assert persisted["all_devices"] == [
        {
            "device": "fw-a",
            "adom": "Corp",
            "status": "licensed",
            "expires": "2286-11-20",
            "firmware": "n/a",
            "subscriptions": no_subs,
        }
    ]


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


def test_is_running_reflects_running_event():
    from app.license_status_cache import _running

    assert is_running() is False
    _running.set()
    try:
        assert is_running() is True
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
