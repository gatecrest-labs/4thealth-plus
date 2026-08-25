"""Tests for device-group-aware policy package matching in FMGClient."""
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


def test_get_device_group_names_returns_set():
    client = _make_client()
    data = [{"name": "GroupA"}, {"name": "GroupB"}, {"not_name": "skip"}]

    with patch.object(client, "_get", return_value=data):
        result = client.get_device_group_names("TestADOM")

    assert result == {"GroupA", "GroupB"}


def test_get_device_group_names_graceful_on_error():
    client = _make_client()

    with patch.object(client, "_get", side_effect=Exception("FMG unreachable")):
        result = client.get_device_group_names("TestADOM")

    assert result == set()


def test_get_device_group_members_returns_names():
    client = _make_client()
    resp = {
        "result": [
            {
                "data": {
                    "object member": [
                        {"name": "FW01"},
                        {"name": "FW02"},
                        {"not_name": "skip"},
                    ]
                }
            }
        ]
    }

    with patch.object(client, "_post", return_value=resp):
        result = client.get_device_group_members("TestADOM", "GroupA")

    assert result == ["FW01", "FW02"]


def test_get_device_group_members_graceful_on_error():
    client = _make_client()

    with patch.object(client, "_post", side_effect=Exception("FMG unreachable")):
        result = client.get_device_group_members("TestADOM", "GroupA")

    assert result == []


def test_get_device_policy_package_matches_direct_device():
    client = _make_client()
    packages = [
        {"name": "Corp-Policy", "scope member": [{"name": "FW01", "vdom": "root"}]},
    ]

    with patch.object(client, "get_policy_packages", return_value=packages):
        result = client.get_device_policy_package("TestADOM", "FW01")

    assert result == [{"name": "Corp-Policy", "vdom": "root"}]


def test_get_device_policy_package_matches_via_device_group():
    """A device reached only through a device-group scope member must resolve."""
    client = _make_client()
    packages = [
        {"name": "Branch-Policy", "scope member": [{"name": "Branch-Group", "vdom": "root"}]},
    ]

    with patch.object(client, "get_policy_packages", return_value=packages), \
         patch.object(client, "get_device_group_names", return_value={"Branch-Group"}), \
         patch.object(client, "get_device_group_members", return_value=["FW01", "FW02"]):
        result = client.get_device_policy_package("TestADOM", "FW01")

    assert result == [{"name": "Branch-Policy", "vdom": "root"}]


def test_get_device_policy_package_no_match_for_unrelated_device():
    client = _make_client()
    packages = [
        {"name": "Branch-Policy", "scope member": [{"name": "Branch-Group", "vdom": "root"}]},
    ]

    with patch.object(client, "get_policy_packages", return_value=packages), \
         patch.object(client, "get_device_group_names", return_value={"Branch-Group"}), \
         patch.object(client, "get_device_group_members", return_value=["FW01", "FW02"]):
        result = client.get_device_policy_package("TestADOM", "FW99")

    assert result == []


def test_get_device_policy_package_skips_group_resolution_when_names_match_directly():
    """No unmatched scope members means get_device_group_names must not be called."""
    client = _make_client()
    packages = [
        {"name": "Corp-Policy", "scope member": [{"name": "FW01", "vdom": "root"}]},
    ]

    with patch.object(client, "get_policy_packages", return_value=packages), \
         patch.object(client, "get_device_group_names") as mock_groups:
        result = client.get_device_policy_package("TestADOM", "FW01")

    mock_groups.assert_not_called()
    assert result == [{"name": "Corp-Policy", "vdom": "root"}]


def test_get_device_policy_package_graceful_on_error():
    client = _make_client()

    with patch.object(client, "get_policy_packages", side_effect=Exception("FMG unreachable")):
        result = client.get_device_policy_package("TestADOM", "FW01")

    assert result == []
