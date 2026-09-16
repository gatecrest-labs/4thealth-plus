"""Tests for app.planner.fetch — device snapshot and zone verdict fetching."""

from unittest.mock import MagicMock, patch

import pytest

from app.planner.fetch import (
    DeviceSnapshot,
    fetch_device_snapshot,
    fetch_zone_domains,
    fetch_zone_verdict,
    resolve_default_route_interface,
    resolve_interfaces,
)
from app.planner.models import PlannerDataError
from app.planner.zone_adapter import ZoneDBAdapter


def _client_stub(**overrides):
    client = MagicMock()
    client.get_devices.return_value = [{"name": "FW-A"}]
    client.get_policy_packages.return_value = [{"name": "OT-Pkg", "scope member": []}]
    client.get_address_objects.return_value = []
    client.get_address_groups.return_value = []
    client.get_service_objects.return_value = []
    client.get_service_groups.return_value = []
    client.get_policies.return_value = []
    client.get_device_interfaces.return_value = [
        {"name": "port1", "ip": "10.1.1.1 255.255.255.0"},
    ]
    client.get_device_routes.return_value = [
        {"ip_mask": "0.0.0.0/0", "interface": "port2", "status": "enable"},
    ]
    for k, v in overrides.items():
        getattr(client, k).return_value = v
    return client


def test_fetch_device_snapshot_happy_path():
    client = _client_stub()
    snapshot = fetch_device_snapshot(client, "OT-ADOM", "FW-A")
    assert isinstance(snapshot, DeviceSnapshot)
    assert snapshot.device == "FW-A"
    assert snapshot.degraded is False
    assert snapshot.packages == ["OT-Pkg"]
    assert len(snapshot.interfaces) == 1
    assert len(snapshot.routing_table) == 1


def test_fetch_device_snapshot_unknown_device_raises():
    client = _client_stub()
    with pytest.raises(PlannerDataError) as exc_info:
        fetch_device_snapshot(client, "OT-ADOM", "NOT-A-DEVICE")
    assert exc_info.value.source == "fortimanager"


def test_fetch_device_snapshot_uses_package_path_not_name():
    """Packages inside an FMG folder must be addressed by their full path,
    not just their name — get_policies()'s second arg must be pkg['path']."""
    client = _client_stub(
        get_policy_packages=[
            {"name": "MyPackage", "path": "MyFolder/MyPackage", "scope member": []}
        ],
    )
    fetch_device_snapshot(client, "OT-ADOM", "FW-A")
    called_args = [c.args for c in client.get_policies.call_args_list]
    assert ("OT-ADOM", "MyFolder/MyPackage") in called_args
    assert ("OT-ADOM", "MyPackage") not in called_args


def test_fetch_device_snapshot_falls_back_to_name_when_no_path():
    """A package dict with no 'path' key still works (falls back to 'name')."""
    client = _client_stub(
        get_policy_packages=[{"name": "Pkg1", "scope member": []}],
    )
    snapshot = fetch_device_snapshot(client, "OT-ADOM", "FW-A")
    assert snapshot.packages == ["Pkg1"]


def test_fetch_device_snapshot_degrades_on_package_fetch_failure():
    client = _client_stub()
    client.get_policies.side_effect = RuntimeError("boom")
    snapshot = fetch_device_snapshot(client, "OT-ADOM", "FW-A")
    assert snapshot.degraded is True
    assert "OT-Pkg" in snapshot.failures[0]


def test_fetch_zone_verdict_returns_verdict_shape():
    zc = MagicMock(spec=ZoneDBAdapter)
    zc.query.return_value = [
        {
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "service": "tcp/443",
            "verdict": "ALLOWED",
            "src_zones": ["DMZ"],
            "dst_zones": ["Internet"],
            "governing": [{"policy_set": "Corp"}],
            "all_policies": [],
        }
    ]
    result = fetch_zone_verdict(zc, "10.0.0.5", "8.8.8.8", "tcp/443")
    assert result["verdict"] == "ALLOWED"
    assert result["src_zones"] == ["DMZ"]
    assert result["dst_zones"] == ["Internet"]
    assert result["notes"] == []


def test_fetch_zone_verdict_applies_internet_default_when_unresolved():
    zc = MagicMock(spec=ZoneDBAdapter)
    zc.query.return_value = [
        {
            "src": "1.2.3.4",
            "dst": "10.0.0.5",
            "service": "tcp/443",
            "verdict": "UNKNOWN",
            "src_zones": [],
            "dst_zones": ["DMZ"],
            "governing": [],
            "all_policies": [],
        }
    ]
    zc.zones.return_value = {"zones": [{"name": "Internet", "domain": "Default"}]}
    with (
        patch("app.zone_db.find_matching_policies", return_value=[]),
        patch("app.zone_db.evaluate", return_value=("ALLOWED", [])),
    ):
        zc.policies.return_value = []
        result = fetch_zone_verdict(zc, "1.2.3.4", "10.0.0.5", "tcp/443")
    assert result["src_zones"] == ["Internet"]
    assert any("catch-all" in n for n in result["notes"])


def test_fetch_zone_domains_maps_names_to_domains():
    zc = MagicMock(spec=ZoneDBAdapter)
    zc.zones.return_value = {
        "zones": [
            {"name": "DMZ", "domain": "Default"},
            {"name": "OT-Plant1", "domain": "OT"},
        ]
    }
    result = fetch_zone_domains(zc)
    assert result == {"DMZ": "Default", "OT-Plant1": "OT"}


def test_resolve_interfaces_connected_subnet_match():
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=MagicMock(),
        svc_catalog=MagicMock(),
        interfaces=[{"name": "port1", "ip": "10.1.1.1 255.255.255.0"}],
        routing_table=[],
    )
    srcintf, dstintf, warnings = resolve_interfaces(snapshot, "10.1.1.50", "10.1.1.60")
    assert srcintf == "port1"
    assert dstintf == "port1"
    assert warnings == []


def test_resolve_interfaces_routing_table_fallback():
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=MagicMock(),
        svc_catalog=MagicMock(),
        interfaces=[{"name": "port1", "ip": "10.1.1.1 255.255.255.0"}],
        routing_table=[
            {"ip_mask": "0.0.0.0/0", "interface": "port2", "status": "enable"}
        ],
    )
    srcintf, dstintf, warnings = resolve_interfaces(snapshot, "10.1.1.50", "8.8.8.8")
    assert srcintf == "port1"
    assert dstintf == "port2"
    assert any("routing table" in w for w in warnings)


def test_resolve_interfaces_unresolvable_warns():
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=MagicMock(),
        svc_catalog=MagicMock(),
        interfaces=[],
        routing_table=[],
    )
    srcintf, dstintf, warnings = resolve_interfaces(snapshot, "10.1.1.50", "8.8.8.8")
    assert srcintf == ""
    assert dstintf == ""
    assert len(warnings) == 2


def test_resolve_default_route_interface_finds_enabled_default_route():
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=MagicMock(),
        svc_catalog=MagicMock(),
        interfaces=[],
        routing_table=[
            {"ip_mask": "0.0.0.0/0", "interface": "wan1", "status": "enable"},
        ],
    )
    name, warnings = resolve_default_route_interface(snapshot)
    assert name == "wan1"
    assert warnings == []


def test_resolve_default_route_interface_ignores_disabled_route():
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=MagicMock(),
        svc_catalog=MagicMock(),
        interfaces=[],
        routing_table=[
            {"ip_mask": "0.0.0.0/0", "interface": "wan1", "status": "disable"},
        ],
    )
    name, warnings = resolve_default_route_interface(snapshot)
    assert name == ""
    assert any("No enabled default route" in w for w in warnings)


def test_resolve_default_route_interface_ignores_non_default_route():
    """A specific static route (even one that happens to cover a sentinel
    IP like 8.8.8.8) must never be mistaken for the default route."""
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=MagicMock(),
        svc_catalog=MagicMock(),
        interfaces=[],
        routing_table=[
            {"ip_mask": "8.8.8.8/32", "interface": "wan2", "status": "enable"},
        ],
    )
    name, warnings = resolve_default_route_interface(snapshot)
    assert name == ""
    assert any("No enabled default route" in w for w in warnings)


def test_resolve_default_route_interface_accepts_alias_field_names():
    """network/prefix and dev/ifname are accepted as aliases for
    ip_mask/interface, matching app.rule_review's own route parsing."""
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=MagicMock(),
        svc_catalog=MagicMock(),
        interfaces=[],
        routing_table=[
            {"network": "0.0.0.0/0", "dev": "wan1", "status": "enable"},
        ],
    )
    name, warnings = resolve_default_route_interface(snapshot)
    assert name == "wan1"
    assert warnings == []


def test_resolve_default_route_interface_no_routes():
    snapshot = DeviceSnapshot(
        device="FW-A",
        adom="OT-ADOM",
        packages=[],
        policies_by_package={},
        addr_catalog=MagicMock(),
        svc_catalog=MagicMock(),
        interfaces=[],
        routing_table=[],
    )
    name, warnings = resolve_default_route_interface(snapshot)
    assert name == ""
    assert len(warnings) == 1
