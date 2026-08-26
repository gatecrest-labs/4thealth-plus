"""Tests for the PSIRT workaround-pattern registry and FMG-backed checks."""
from unittest.mock import MagicMock

from app.psirt.workaround_checks import check_workaround, match_workaround_pattern


def test_match_workaround_pattern_http_admin_access():
    assert match_workaround_pattern("Disable HTTP/HTTPS admin access on all interfaces") \
        == "disable_http_https_admin_access"


def test_match_workaround_pattern_internet_facing():
    assert match_workaround_pattern("Disable GUI on internet-facing interfaces") \
        == "disable_gui_internet_facing"


def test_match_workaround_pattern_trusted_hosts():
    assert match_workaround_pattern("Configure trusted hosts to restrict management access") \
        == "configure_trusted_hosts"


def test_match_workaround_pattern_unrecognized_returns_none():
    assert match_workaround_pattern("Contact support for a hotfix") is None


def test_match_workaround_pattern_empty_returns_none():
    assert match_workaround_pattern("") is None


def test_check_workaround_unregistered_pattern_returns_manual():
    client = MagicMock()
    assert check_workaround("not_a_real_pattern", client, "Corp", "FW01") == "manual_verification_required"


def test_check_disable_http_https_admin_access_in_place():
    """No interface allows http/https admin access → in_place."""
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "port1", "allowaccess": "ping"},
        {"name": "wan1", "allowaccess": "ping ssh"},
    ]
    status = check_workaround("disable_http_https_admin_access", client, "Corp", "FW01")
    assert status == "in_place"


def test_check_disable_http_https_admin_access_not_in_place():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "port1", "allowaccess": "ping"},
        {"name": "wan1", "allowaccess": "ping https"},
    ]
    status = check_workaround("disable_http_https_admin_access", client, "Corp", "FW01")
    assert status == "not_in_place"


def test_check_disable_http_https_admin_access_no_interfaces_is_manual():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = []
    status = check_workaround("disable_http_https_admin_access", client, "Corp", "FW01")
    assert status == "manual_verification_required"


def test_check_disable_gui_internet_facing_public_ip_allows_https_not_in_place():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "wan1", "ip": "203.0.113.5/24", "allowaccess": "https ping"},
        {"name": "port1", "ip": "10.1.1.1/24", "allowaccess": "https ping"},  # private, ignored
    ]
    status = check_workaround("disable_gui_internet_facing", client, "Corp", "FW01")
    assert status == "not_in_place"


def test_check_disable_gui_internet_facing_public_ip_no_gui_in_place():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "wan1", "ip": "203.0.113.5/24", "allowaccess": "ping"},
    ]
    status = check_workaround("disable_gui_internet_facing", client, "Corp", "FW01")
    assert status == "in_place"


def test_check_disable_gui_internet_facing_no_public_interfaces_is_manual():
    client = MagicMock()
    client.get_device_interfaces_all_vdoms.return_value = [
        {"name": "port1", "ip": "10.1.1.1/24", "allowaccess": "https"},
    ]
    status = check_workaround("disable_gui_internet_facing", client, "Corp", "FW01")
    assert status == "manual_verification_required"


def test_check_trusted_hosts_in_place_when_all_admins_restricted():
    """Real check (upgraded from the source's permanent stub) — reuses the
    same unrestricted-trusthost detection as app.device_review._run_trusted_hosts."""
    client = MagicMock()
    client.get_device_admins.return_value = [
        {"name": "admin", "trusthost1": "10.1.1.0 255.255.255.0"},
    ]
    status = check_workaround("configure_trusted_hosts", client, "Corp", "FW01")
    assert status == "in_place"


def test_check_trusted_hosts_not_in_place_when_any_admin_unrestricted():
    client = MagicMock()
    client.get_device_admins.return_value = [
        {"name": "admin", "trusthost1": "10.1.1.0 255.255.255.0"},
        {"name": "backup_admin", "trusthost1": "0.0.0.0 0.0.0.0"},
    ]
    status = check_workaround("configure_trusted_hosts", client, "Corp", "FW01")
    assert status == "not_in_place"


def test_check_trusted_hosts_no_admin_data_is_manual():
    client = MagicMock()
    client.get_device_admins.return_value = "not-a-list"
    status = check_workaround("configure_trusted_hosts", client, "Corp", "FW01")
    assert status == "manual_verification_required"
