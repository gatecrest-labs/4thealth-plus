"""Tests for FMGClient's device-config revision-history methods.

Endpoint confirmed live against a lab FMG-VM64-KVM (v7.6.7-build3737) on
2026-09-11 — see app.fmg_client.FMGClient.get_adom_revisions() docstring.
"""

from unittest.mock import patch

from app.fmg_client import FMGClient


def _make_client():
    c = FMGClient.__new__(FMGClient)
    c.base_url = "https://fmg.test/jsonrpc"
    c.token = "tok"
    c.session = None
    c.verify_ssl = False
    c._req_id = 0
    return c


def test_get_adom_revisions_returns_list():
    client = _make_client()
    data = [
        {
            "oid": 182,
            "version": 1,
            "name": "FortiWiFi-71G-New_2026-08-27-07-03-18-PDT",
            "created_by": "adminakw",
            "created_time": 1787839429,
        }
    ]
    with patch.object(client, "_get", return_value=data):
        result = client.get_adom_revisions("root")
    assert result == data


def test_get_adom_revisions_graceful_empty_on_none():
    client = _make_client()
    with patch.object(client, "_get", return_value=None):
        result = client.get_adom_revisions("root")
    assert result == []


def test_get_device_last_revision_matches_by_name_prefix():
    client = _make_client()
    data = [
        {"name": "FortiWiFi-71G-New_2026-08-27-07-03-18-PDT", "created_time": 100},
        {"name": "FortiWiFi-71G-New_2026-09-01-00-00-00-PDT", "created_time": 200},
        {"name": "OtherDevice-New_2026-09-05-00-00-00-PDT", "created_time": 999},
    ]
    with patch.object(client, "_get", return_value=data):
        result = client.get_device_last_revision("root", "FortiWiFi-71G")
    assert result["created_time"] == 200


def test_get_device_last_revision_no_match_returns_none():
    client = _make_client()
    data = [{"name": "OtherDevice-New_2026-09-05-00-00-00-PDT", "created_time": 999}]
    with patch.object(client, "_get", return_value=data):
        result = client.get_device_last_revision("root", "FortiWiFi-71G")
    assert result is None


def test_get_device_last_revision_avoids_prefix_collision():
    """A device named "device1" must not match a revision belonging to
    "device10" (or vice versa) — the prefix match requires the trailing
    "-" delimiter."""
    client = _make_client()
    data = [{"name": "device10-New_2026-09-05-00-00-00-PDT", "created_time": 999}]
    with patch.object(client, "_get", return_value=data):
        result = client.get_device_last_revision("root", "device1")
    assert result is None
