from unittest.mock import MagicMock, patch

import pytest


def _mock_client(policies, addr_objects=None, addr_groups=None,
                  svc_objects=None, svc_groups=None, scope=None):
    client = MagicMock()
    client.get_policies.return_value = policies
    client.get_address_objects.return_value = addr_objects or []
    client.get_address_groups.return_value = addr_groups or []
    client.get_service_objects.return_value = svc_objects or []
    client.get_service_groups.return_value = svc_groups or []
    client.get_pkg_scope_members.return_value = (
        scope if scope is not None else [{"name": "FW01", "vdom": "root"}]
    )
    client.get_device_group_names.return_value = set()
    client.get_device_group_members.return_value = []
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    return client


def test_check_rule_log_usage_rule_not_found_raises():
    from app.log_hygiene import LogHygieneError, check_rule_log_usage
    client = _mock_client(policies=[{"policyid": 1, "name": "Other"}])
    with patch("app.log_hygiene.make_client", return_value=client):
        with pytest.raises(LogHygieneError, match="not found"):
            check_rule_log_usage("ADOM", "pkg", 999, 30)


def test_check_rule_log_usage_no_device_scope_raises():
    from app.log_hygiene import LogHygieneError, check_rule_log_usage
    client = _mock_client(policies=[{"policyid": 1, "name": "Rule1"}], scope=[])
    with patch("app.log_hygiene.make_client", return_value=client):
        with pytest.raises(LogHygieneError, match="not installed on any device"):
            check_rule_log_usage("ADOM", "pkg", 1, 30)


def test_check_rule_log_usage_days_clamped_high():
    from app.log_hygiene import check_rule_log_usage
    client = _mock_client(policies=[{"policyid": 1, "name": "Rule1", "srcaddr": [], "dstaddr": [], "service": []}])
    usage = {"srcips": [], "dstips": [], "dstports": [], "time_range": {}, "log_count": 0,
              "truncated": False, "devices_queried": ["FW01"], "devices_not_found": []}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage) as mock_get:
        check_rule_log_usage("ADOM", "pkg", 1, 999)
    assert mock_get.call_args.args[3] == 60


def test_check_rule_log_usage_days_clamped_low():
    from app.log_hygiene import check_rule_log_usage
    client = _mock_client(policies=[{"policyid": 1, "name": "Rule1", "srcaddr": [], "dstaddr": [], "service": []}])
    usage = {"srcips": [], "dstips": [], "dstports": [], "time_range": {}, "log_count": 0,
              "truncated": False, "devices_queried": ["FW01"], "devices_not_found": []}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage) as mock_get:
        check_rule_log_usage("ADOM", "pkg", 1, -5)
    assert mock_get.call_args.args[3] == 1


def test_check_rule_log_usage_full_diff():
    from app.log_hygiene import check_rule_log_usage
    policies = [{
        "policyid": 42, "name": "Allow-DC-to-App",
        "srcaddr": [{"name": "srv1"}, {"name": "srv2"}],
        "dstaddr": [{"name": "srv3"}],
        "service": [{"name": "svc-https"}],
    }]
    addr_objects = [
        {"name": "srv1", "subnet": "10.1.1.5 255.255.255.255"},
        {"name": "srv2", "subnet": "10.1.1.6 255.255.255.255"},
        {"name": "srv3", "subnet": "10.2.2.10 255.255.255.255"},
    ]
    svc_objects = [{"name": "svc-https", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}]
    client = _mock_client(policies=policies, addr_objects=addr_objects, svc_objects=svc_objects)
    usage = {
        "srcips": ["10.1.1.5"], "dstips": ["10.2.2.10"], "dstports": [443],
        "time_range": {"start": "a", "end": "b"}, "log_count": 10, "truncated": False,
        "devices_queried": ["FW01"], "devices_not_found": [],
    }
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage):
        result = check_rule_log_usage("ADOM", "pkg", 42, 30)

    assert result["rule"] == {"policy_id": 42, "name": "Allow-DC-to-App"}
    assert result["truncated"] is False
    assert result["log_count"] == 10
    src_by_name = {e["name"]: e["status"] for e in result["source"]["evaluated"]}
    assert src_by_name == {"srv1": "used", "srv2": "unused"}
    assert result["destination"]["evaluated"][0]["status"] == "used"
    assert result["service"]["evaluated"][0]["status"] == "used"


def test_check_rule_log_usage_propagates_truncated_flag():
    """truncated must reach the top-level result unchanged -- Review Focus item."""
    from app.log_hygiene import check_rule_log_usage
    policies = [{"policyid": 1, "name": "R", "srcaddr": [], "dstaddr": [], "service": []}]
    client = _mock_client(policies=policies)
    usage = {"srcips": [], "dstips": [], "dstports": [], "time_range": {}, "log_count": 5000,
              "truncated": True, "devices_queried": ["FW01"], "devices_not_found": ["FW02"]}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage):
        result = check_rule_log_usage("ADOM", "pkg", 1, 30)
    assert result["truncated"] is True
    assert result["devices_not_found"] == ["FW02"]


def test_check_rule_log_usage_empty_devices_queried_raises():
    """If 4tlog couldn't match any device from the package's scope, raise
    rather than silently marking every evaluated member 'unused'."""
    from app.log_hygiene import LogHygieneError, check_rule_log_usage
    policies = [{"policyid": 1, "name": "R", "srcaddr": [], "dstaddr": [], "service": []}]
    client = _mock_client(policies=policies)
    usage = {"srcips": [], "dstips": [], "dstports": [], "time_range": {}, "log_count": 0,
              "truncated": False, "devices_queried": [], "devices_not_found": ["FW01"]}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage):
        with pytest.raises(LogHygieneError, match="No devices could be queried"):
            check_rule_log_usage("ADOM", "pkg", 1, 30)


def test_check_rule_log_usage_string_dstports_normalized():
    """4tlog returning port numbers as strings must still match an int-typed
    evaluated port instead of silently showing every service as unused."""
    from app.log_hygiene import check_rule_log_usage
    policies = [{
        "policyid": 1, "name": "R",
        "srcaddr": [], "dstaddr": [],
        "service": [{"name": "svc-https"}],
    }]
    svc_objects = [{"name": "svc-https", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}]
    client = _mock_client(policies=policies, svc_objects=svc_objects)
    usage = {"srcips": [], "dstips": [], "dstports": ["443"], "time_range": {}, "log_count": 1,
              "truncated": False, "devices_queried": ["FW01"], "devices_not_found": []}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage):
        result = check_rule_log_usage("ADOM", "pkg", 1, 30)
    assert result["service"]["evaluated"][0]["status"] == "used"


def test_check_rule_log_usage_expands_device_group_scope():
    """A device-group name in the package scope must be expanded to its
    member devices before being sent to 4tlog."""
    from app.log_hygiene import check_rule_log_usage
    policies = [{"policyid": 1, "name": "R", "srcaddr": [], "dstaddr": [], "service": []}]
    client = _mock_client(
        policies=policies, scope=[{"name": "BranchGroup", "vdom": "root"}]
    )
    client.get_device_group_names.return_value = {"BranchGroup"}
    client.get_device_group_members.return_value = ["FW01", "FW02"]
    usage = {"srcips": [], "dstips": [], "dstports": [], "time_range": {}, "log_count": 0,
              "truncated": False, "devices_queried": ["FW01", "FW02"], "devices_not_found": []}
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", return_value=usage) as mock_get:
        check_rule_log_usage("ADOM", "pkg", 1, 30)
    assert mock_get.call_args.args[1] == ["FW01", "FW02"]


def test_check_rule_log_usage_log_usage_error_propagates():
    from app.log_hygiene import check_rule_log_usage
    from app.log_usage_client import LogUsageError
    policies = [{"policyid": 1, "name": "R", "srcaddr": [], "dstaddr": [], "service": []}]
    client = _mock_client(policies=policies)
    with patch("app.log_hygiene.make_client", return_value=client), \
         patch("app.log_hygiene.get_rule_log_usage", side_effect=LogUsageError("unreachable")):
        with pytest.raises(LogUsageError, match="unreachable"):
            check_rule_log_usage("ADOM", "pkg", 1, 30)
