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
