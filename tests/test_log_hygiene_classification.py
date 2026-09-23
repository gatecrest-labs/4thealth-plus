def test_addr_object_host_ip_single_host_ipmask_form():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "srv1", "subnet": "10.1.1.5 255.255.255.255"}
    assert _addr_object_host_ip(ao) == "10.1.1.5"


def test_addr_object_host_ip_single_host_cidr_form():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "srv1", "subnet": "10.1.1.5/32"}
    assert _addr_object_host_ip(ao) == "10.1.1.5"


def test_addr_object_host_ip_subnet_returns_none():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "net1", "subnet": "10.1.0.0 255.255.0.0"}
    assert _addr_object_host_ip(ao) is None


def test_addr_object_host_ip_range_returns_none():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "range1", "subnet": "10.1.1.1-10.1.1.10"}
    assert _addr_object_host_ip(ao) is None


def test_addr_object_host_ip_fqdn_returns_none():
    from app.log_hygiene import _addr_object_host_ip
    ao = {"name": "fqdn1"}
    assert _addr_object_host_ip(ao) is None


def test_service_single_port_plain_port():
    from app.log_hygiene import _service_single_port
    so = {"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}
    assert _service_single_port(so) == ("tcp", 443)


def test_service_single_port_colon_form():
    """FortiManager 'src:dst' portrange syntax: only the dst side matters."""
    from app.log_hygiene import _service_single_port
    so = {"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "0:443"}
    assert _service_single_port(so) == ("tcp", 443)


def test_service_single_port_range_returns_none():
    from app.log_hygiene import _service_single_port
    so = {"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8000-8100"}
    assert _service_single_port(so) is None


def test_service_single_port_udp():
    from app.log_hygiene import _service_single_port
    so = {"name": "svc1", "protocol": "TCP/UDP/SCTP", "udp-portrange": "53"}
    assert _service_single_port(so) == ("udp", 53)


def test_service_single_port_icmp_returns_none():
    from app.log_hygiene import _service_single_port
    so = {"name": "ping", "protocol": "ICMP"}
    assert _service_single_port(so) is None


def test_expand_addr_members_direct_host():
    from app.log_hygiene import _expand_addr_members
    addr_objects = [{"name": "srv1", "subnet": "10.1.1.5 255.255.255.255"}]
    evaluated, not_evaluated = _expand_addr_members(["srv1"], addr_objects, [])
    assert evaluated == [{"name": "srv1", "value": "10.1.1.5"}]
    assert not_evaluated == []


def test_expand_addr_members_via_group_and_direct_dedup():
    """A leaf reachable both directly on the rule and via a nested group
    must appear exactly once."""
    from app.log_hygiene import _expand_addr_members
    addr_objects = [
        {"name": "srv1", "subnet": "10.1.1.5 255.255.255.255"},
        {"name": "srv2", "subnet": "10.1.1.6 255.255.255.255"},
    ]
    addr_groups = [{"name": "grp1", "member": [{"name": "srv1"}, {"name": "srv2"}]}]
    evaluated, not_evaluated = _expand_addr_members(["grp1", "srv1"], addr_objects, addr_groups)
    names = sorted(e["name"] for e in evaluated)
    assert names == ["srv1", "srv2"]
    assert not_evaluated == []


def test_expand_addr_members_subnet_goes_to_not_evaluated():
    from app.log_hygiene import _expand_addr_members
    addr_objects = [{"name": "net1", "subnet": "10.1.0.0 255.255.0.0"}]
    evaluated, not_evaluated = _expand_addr_members(["net1"], addr_objects, [])
    assert evaluated == []
    assert not_evaluated == [{"name": "net1", "type": "ipmask"}]


def test_expand_addr_members_unresolved_name_goes_to_not_evaluated():
    from app.log_hygiene import _expand_addr_members
    evaluated, not_evaluated = _expand_addr_members(["all"], [], [])
    assert evaluated == []
    assert not_evaluated == [{"name": "all", "type": "unresolved"}]


def test_expand_service_members_single_port():
    from app.log_hygiene import _expand_service_members
    svc_objects = [{"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}]
    evaluated, not_evaluated = _expand_service_members(["svc1"], svc_objects, [])
    assert evaluated == [{"name": "svc1", "proto": "tcp", "port": 443}]
    assert not_evaluated == []


def test_expand_service_members_group_expansion():
    from app.log_hygiene import _expand_service_members
    svc_objects = [
        {"name": "svc1", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
        {"name": "svc2", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8443"},
    ]
    svc_groups = [{"name": "grp1", "member": [{"name": "svc1"}, {"name": "svc2"}]}]
    evaluated, not_evaluated = _expand_service_members(["grp1"], svc_objects, svc_groups)
    ports = sorted(e["port"] for e in evaluated)
    assert ports == [443, 8443]
