"""Tests for app.license_status's shared FortiOS license-response parser."""

import time

from app.license_status import parse_license_payload


def test_licensed_with_future_expiry():
    future_ts = int(time.time()) + 86400 * 30
    payload = {
        "forticare": {"support": {"enhanced": {"status": "licensed", "expires": future_ts}}}
    }
    result = parse_license_payload(payload)
    assert result["status"] == "licensed"
    assert result["expires"] is not None


def test_licensed_but_expiry_in_past_is_expired():
    past_ts = int(time.time()) - 86400
    payload = {
        "forticare": {"support": {"enhanced": {"status": "licensed", "expires": past_ts}}}
    }
    result = parse_license_payload(payload)
    assert result == {"status": "expired", "expires": None}


def test_missing_forticare_block_is_unknown():
    assert parse_license_payload({}) == {"status": "unknown", "expires": None}


def test_none_payload_is_unknown():
    assert parse_license_payload(None) == {"status": "unknown", "expires": None}


def test_status_not_licensed_is_unknown():
    payload = {
        "forticare": {"support": {"enhanced": {"status": "unlicensed", "expires": 123}}}
    }
    assert parse_license_payload(payload) == {"status": "unknown", "expires": None}


def test_licensed_status_without_expires_is_unknown():
    payload = {"forticare": {"support": {"enhanced": {"status": "licensed"}}}}
    assert parse_license_payload(payload) == {"status": "unknown", "expires": None}
