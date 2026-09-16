"""Tests for app.license_status's shared FortiOS license-response parser."""

import time

from app.license_status import FORTIGUARD_SUBSCRIPTION_KEYS, parse_license_payload

_NO_SUBS = {
    key: {"status": "unknown", "expires": None} for key in FORTIGUARD_SUBSCRIPTION_KEYS
}


def test_licensed_with_future_expiry():
    future_ts = int(time.time()) + 86400 * 30
    payload = {
        "forticare": {
            "support": {"enhanced": {"status": "licensed", "expires": future_ts}}
        }
    }
    result = parse_license_payload(payload)
    assert result["status"] == "licensed"
    assert result["expires"] is not None
    assert result["subscriptions"] == _NO_SUBS


def test_licensed_but_expiry_in_past_is_expired():
    past_ts = int(time.time()) - 86400
    payload = {
        "forticare": {
            "support": {"enhanced": {"status": "licensed", "expires": past_ts}}
        }
    }
    result = parse_license_payload(payload)
    assert result == {"status": "expired", "expires": None, "subscriptions": _NO_SUBS}


def test_missing_forticare_block_is_unknown():
    assert parse_license_payload({}) == {
        "status": "unknown",
        "expires": None,
        "subscriptions": _NO_SUBS,
    }


def test_none_payload_is_unknown():
    assert parse_license_payload(None) == {
        "status": "unknown",
        "expires": None,
        "subscriptions": _NO_SUBS,
    }


def test_status_not_licensed_is_unknown():
    payload = {
        "forticare": {"support": {"enhanced": {"status": "unlicensed", "expires": 123}}}
    }
    assert parse_license_payload(payload) == {
        "status": "unknown",
        "expires": None,
        "subscriptions": _NO_SUBS,
    }


def test_licensed_status_without_expires_is_unknown():
    payload = {"forticare": {"support": {"enhanced": {"status": "licensed"}}}}
    assert parse_license_payload(payload) == {
        "status": "unknown",
        "expires": None,
        "subscriptions": _NO_SUBS,
    }


def test_forticare_not_a_dict_is_unknown():
    assert parse_license_payload({"forticare": []}) == {
        "status": "unknown",
        "expires": None,
        "subscriptions": _NO_SUBS,
    }


def test_support_not_a_dict_is_unknown():
    payload = {"forticare": {"support": None}}
    assert parse_license_payload(payload) == {
        "status": "unknown",
        "expires": None,
        "subscriptions": _NO_SUBS,
    }


def test_enhanced_not_a_dict_is_unknown():
    payload = {"forticare": {"support": {"enhanced": []}}}
    assert parse_license_payload(payload) == {
        "status": "unknown",
        "expires": None,
        "subscriptions": _NO_SUBS,
    }


def test_non_numeric_expires_is_unknown():
    payload = {
        "forticare": {
            "support": {"enhanced": {"status": "licensed", "expires": "2027-01-01"}}
        }
    }
    assert parse_license_payload(payload) == {
        "status": "unknown",
        "expires": None,
        "subscriptions": _NO_SUBS,
    }


def test_subscription_licensed_with_future_expiry():
    future_ts = int(time.time()) + 86400 * 30
    payload = {"antivirus": {"status": "licensed", "expires": future_ts}}
    result = parse_license_payload(payload)
    assert result["subscriptions"]["antivirus"]["status"] == "licensed"
    assert result["subscriptions"]["antivirus"]["expires"] is not None
    other_keys = [k for k in FORTIGUARD_SUBSCRIPTION_KEYS if k != "antivirus"]
    for key in other_keys:
        assert result["subscriptions"][key] == {"status": "unknown", "expires": None}


def test_subscription_licensed_with_past_expiry_is_expired():
    past_ts = int(time.time()) - 86400
    payload = {"ips": {"status": "licensed", "expires": past_ts}}
    result = parse_license_payload(payload)
    assert result["subscriptions"]["ips"] == {"status": "expired", "expires": None}


def test_subscription_licensed_without_expires_stays_licensed():
    payload = {"web_filtering": {"status": "licensed"}}
    result = parse_license_payload(payload)
    assert result["subscriptions"]["web_filtering"] == {
        "status": "licensed",
        "expires": None,
    }


def test_subscription_no_license_is_none_status():
    payload = {"appctrl": {"status": "no_license"}}
    result = parse_license_payload(payload)
    assert result["subscriptions"]["appctrl"] == {"status": "none", "expires": None}


def test_subscription_free_license_is_none_status():
    payload = {"firmware_updates": {"status": "free_license"}}
    result = parse_license_payload(payload)
    assert result["subscriptions"]["firmware_updates"] == {
        "status": "none",
        "expires": None,
    }


def test_subscription_malformed_entry_is_unknown():
    payload = {"antispam": "not-a-dict"}
    result = parse_license_payload(payload)
    assert result["subscriptions"]["antispam"] == {"status": "unknown", "expires": None}


def test_subscription_missing_entry_is_unknown():
    result = parse_license_payload({})
    assert result["subscriptions"]["outbreak_prevention"] == {
        "status": "unknown",
        "expires": None,
    }
