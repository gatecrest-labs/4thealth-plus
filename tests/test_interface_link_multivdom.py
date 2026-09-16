"""Tests for multi-VDOM interface link status bug fix.

Verifies that _assemble_health correctly maps live link state for interfaces
that live in non-root VDOMs when the monitor endpoint returns vdom=* envelope.
"""
import os

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")


def _make_raw(interfaces_monitor_payload):
    """Build a minimal raw dict as returned by fmg_client.get_device_health_raw()."""
    def _wrap(p):
        return {"payload": p, "rpc_code": 0, "http_status": 200}

    return {
        "system_status": _wrap({"hostname": "fw1", "serial": "S1", "version": "v7.4.0"}),
        "cpu": _wrap({"cpu": [{"current": 5}]}),
        "mem": _wrap({"mem": [{"current": 30}]}),
        "interfaces": _wrap(interfaces_monitor_payload),
        "interfaces_cfg": _wrap([
            {"name": "wan1",  "vdom": "root", "ip": "10.0.0.1 255.255.255.0", "type": "physical", "status": "up", "allowaccess": "ping https ssh"},
            {"name": "lan3",  "vdom": "IT",   "ip": "10.63.14.65 255.255.255.240", "type": "physical", "status": "up", "allowaccess": "ping"},
        ]),
        "ha_status": _wrap({}),
        "ipv4_routes": _wrap([]),
        "performance": _wrap({}),
    }


def _call_assemble(raw):
    from app.routes.api_routes import _assemble_health
    dev_rec = {
        "os_ver": 700, "mr": 4, "patch": 11,
        "sn": "FR70FBTK23001361",
        "hostname": "NMTRCOFRWANX01",
        "platform_str": "FortiGateRugged-70F",
        "ip": "10.223.36.122",
        "conn_status": 1,
        "ha_mode": "",
    }
    vdoms_raw = [
        {"name": "root",  "opmode": 1},
        {"name": "IT",    "opmode": 1},
        {"name": "OT",    "opmode": 1},
    ]
    return _assemble_health("Enterprise-SDWAN", "NMTRCOFRWANX01", dev_rec, vdoms_raw, raw)


def _iface(result, name):
    return next((i for i in result["interfaces"] if i["name"] == name), None)


class TestVdomStarEnvelope:
    """Monitor returns {vdom: {iface_name: {link: bool}}} (vdom=* shape)."""

    def test_root_vdom_interface_up(self):
        raw = _make_raw({
            "root": {"wan1": {"link": True, "speed": 1000, "rx_errors": 0, "tx_errors": 0}},
            "IT":   {"lan3": {"link": False, "speed": 0,    "rx_errors": 0, "tx_errors": 0}},
        })
        result = _call_assemble(raw)
        iface = _iface(result, "wan1")
        assert iface is not None
        assert iface["link"] is True

    def test_non_root_vdom_interface_down(self):
        """Core regression: lan3 in IT VDOM is physically down — must not show link=True."""
        raw = _make_raw({
            "root": {"wan1": {"link": True,  "speed": 1000, "rx_errors": 0, "tx_errors": 0}},
            "IT":   {"lan3": {"link": False, "speed": 0,    "rx_errors": 0, "tx_errors": 0}},
        })
        result = _call_assemble(raw)
        iface = _iface(result, "lan3")
        assert iface is not None
        assert iface["link"] is False, "lan3 physical link is down but was reported as up"

    def test_non_root_vdom_interface_up(self):
        raw = _make_raw({
            "root": {"wan1": {"link": True, "speed": 1000, "rx_errors": 0, "tx_errors": 0}},
            "IT":   {"lan3": {"link": True, "speed": 100,  "rx_errors": 0, "tx_errors": 0}},
        })
        result = _call_assemble(raw)
        iface = _iface(result, "lan3")
        assert iface is not None
        assert iface["link"] is True

    def test_interface_absent_from_monitor_has_none_link(self):
        """Interface in CMDB but missing from monitor → link is None, not defaulted to True."""
        raw = _make_raw({
            "root": {"wan1": {"link": True, "speed": 1000, "rx_errors": 0, "tx_errors": 0}},
            # lan3 absent from monitor entirely
        })
        result = _call_assemble(raw)
        iface = _iface(result, "lan3")
        assert iface is not None
        assert iface["link"] is None


class TestFlatDict:
    """Monitor returns flat {iface_name: {link: bool}} (legacy vdom=root shape)."""

    def test_flat_dict_still_works(self):
        raw = _make_raw({
            "wan1": {"link": True,  "speed": 1000, "rx_errors": 0, "tx_errors": 0},
            "lan3": {"link": False, "speed": 0,    "rx_errors": 0, "tx_errors": 0},
        })
        result = _call_assemble(raw)
        assert _iface(result, "wan1")["link"] is True
        assert _iface(result, "lan3")["link"] is False


class TestFlatDictFirstInterfaceDown:
    """Regression: flat monitor response whose FIRST interface has link=False.

    The old heuristic used `not first_val.get("link")` to detect nested format.
    That expression is True when link=False, so a down interface at the front of
    a flat response caused the code to misidentify the format as nested, empty
    monitor_map, and fall back to CMDB status="up" for every interface.
    """

    def test_flat_dict_first_interface_down_shows_link_false(self):
        """lan3 is first in the flat dict and is physically down — must not show link=True."""
        raw = _make_raw({
            "lan3": {"link": False, "speed": 0,    "rx_errors": 0, "tx_errors": 0},
            "wan1": {"link": True,  "speed": 1000, "rx_errors": 0, "tx_errors": 0},
        })
        result = _call_assemble(raw)
        iface = _iface(result, "lan3")
        assert iface is not None
        assert iface["link"] is False, (
            "lan3 is first in flat dict with link=False — heuristic must not mistake "
            "this for nested format and lose all monitor data"
        )

    def test_flat_dict_first_interface_down_other_interface_still_correct(self):
        """wan1 must still show link=True when lan3 is first and down."""
        raw = _make_raw({
            "lan3": {"link": False, "speed": 0,    "rx_errors": 0, "tx_errors": 0},
            "wan1": {"link": True,  "speed": 1000, "rx_errors": 0, "tx_errors": 0},
        })
        result = _call_assemble(raw)
        iface = _iface(result, "wan1")
        assert iface is not None
        assert iface["link"] is True

    def test_flat_dict_all_interfaces_down_shows_all_link_false(self):
        """When every interface is down, all must show link=False (not fall back to CMDB up)."""
        raw = _make_raw({
            "lan3": {"link": False, "speed": 0, "rx_errors": 0, "tx_errors": 0},
            "wan1": {"link": False, "speed": 0, "rx_errors": 0, "tx_errors": 0},
        })
        result = _call_assemble(raw)
        assert _iface(result, "lan3")["link"] is False
        assert _iface(result, "wan1")["link"] is False


class TestFlatList:
    """Monitor returns a list of dicts (alternate FortiOS response shape)."""

    def test_list_shape_still_works(self):
        raw = _make_raw([
            {"name": "wan1", "link": True,  "speed": 1000, "rx_errors": 0, "tx_errors": 0},
            {"name": "lan3", "link": False, "speed": 0,    "rx_errors": 0, "tx_errors": 0},
        ])
        result = _call_assemble(raw)
        assert _iface(result, "wan1")["link"] is True
        assert _iface(result, "lan3")["link"] is False
