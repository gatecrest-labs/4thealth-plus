"""Tests for app.device_backup_cache's pure aggregation logic."""

from app.device_backup_cache import _STALE_SECONDS, _classify_devices


def test_classify_devices_buckets_ok_stale_never():
    now = 2_000_000
    devices_by_adom = {
        "root": [
            {"name": "fresh-dev"},
            {"name": "stale-dev"},
            {"name": "never-dev"},
        ]
    }
    revisions_by_adom = {
        "root": [
            {"name": "fresh-dev-New_x", "created_time": now - 1000},
            {"name": "stale-dev-New_x", "created_time": now - _STALE_SECONDS - 1000},
        ]
    }

    result = _classify_devices(devices_by_adom, revisions_by_adom, now)

    assert result == {
        "devices_backup_ok": 1,
        "devices_backup_stale_7d": 1,
        "devices_backup_never": 1,
    }


def test_classify_devices_boundary_is_ok_not_stale():
    now = 2_000_000
    devices_by_adom = {"root": [{"name": "dev"}]}
    revisions_by_adom = {
        "root": [{"name": "dev-New_x", "created_time": now - _STALE_SECONDS}]
    }

    result = _classify_devices(devices_by_adom, revisions_by_adom, now)

    assert result["devices_backup_ok"] == 1
    assert result["devices_backup_stale_7d"] == 0


def test_classify_devices_multiple_adoms_and_missing_device_name():
    now = 1000
    devices_by_adom = {
        "a": [{"name": "dev-a"}],
        "b": [{"name": "dev-b"}, {"no_name": "skip"}],
    }
    revisions_by_adom = {
        "a": [{"name": "dev-a-New_x", "created_time": now}],
        "b": [],
    }

    result = _classify_devices(devices_by_adom, revisions_by_adom, now)

    assert result == {
        "devices_backup_ok": 1,
        "devices_backup_stale_7d": 0,
        "devices_backup_never": 1,
    }


def test_classify_devices_empty_input():
    result = _classify_devices({}, {}, 1000)
    assert result == {
        "devices_backup_ok": 0,
        "devices_backup_stale_7d": 0,
        "devices_backup_never": 0,
    }
