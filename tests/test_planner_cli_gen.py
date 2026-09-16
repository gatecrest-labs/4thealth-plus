"""
Exact-string tests for planner/cli_gen.py — FortiGate CLI generation.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.planner.cli_gen import (
    address_object_cli,
    addrgrp_create_cli,
    exception_comment,
    fqdn_address_object_cli,
    policy_cli,
    service_object_cli,
    wildcard_fqdn_address_object_cli,
)


def test_address_object_host():
    cli = address_object_cli("H_10.1.2.3", "10.1.2.3/32")
    assert cli == (
        "config firewall address\n"
        '    edit "H_10.1.2.3"\n'
        "        set type ipmask\n"
        "        set subnet 10.1.2.3 255.255.255.255\n"
        '        set comment "<TICKET_ID>"\n'
        "    next\n"
        "end"
    )


def test_address_object_network_mask_conversion():
    cli = address_object_cli("N_10.8.0.0_16", "10.8.0.0/16")
    assert "set subnet 10.8.0.0 255.255.0.0" in cli


def test_service_object():
    cli = service_object_cli("SVC_TCP_8443", "tcp", "8443")
    assert cli == (
        "config firewall service custom\n"
        '    edit "SVC_TCP_8443"\n'
        "        set tcp-portrange 8443\n"
        '        set comment "<TICKET_ID>"\n'
        "    next\n"
        "end"
    )


def test_address_object_substitutes_real_ticket_id():
    cli = address_object_cli("H_10.1.2.3", "10.1.2.3/32", ticket_id="CHG0012345")
    assert 'set comment "CHG0012345"' in cli
    assert "<TICKET_ID>" not in cli


def test_service_object_substitutes_real_ticket_id():
    cli = service_object_cli("SVC_TCP_8443", "tcp", "8443", ticket_id="CHG0012345")
    assert 'set comment "CHG0012345"' in cli
    assert "<TICKET_ID>" not in cli


def test_addrgrp_create_cli_substitutes_real_ticket_id():
    cli = addrgrp_create_cli("GRP-DST", ["A", "B"], ticket_id="CHG0012345")
    assert 'set comment "CHG0012345"' in cli
    assert "<TICKET_ID>" not in cli


def test_service_object_udp():
    assert "set udp-portrange 514" in service_object_cli("SVC_UDP_514", "udp", "514")


def test_policy_cli_full():
    cli = policy_cli(
        name="CHG1_OT_TO_IT_001",
        srcintf="port1",
        dstintf="port2",
        srcaddr=["H_10.1.2.3"],
        dstaddr=["H_10.9.8.7"],
        service=["SVC_TCP_8443"],
        logtraffic="all",
        logtraffic_start=True,
        comments="Ticket <TICKET_ID>",
        insert_before=42,
    )
    assert "edit 0" in cli
    assert 'set name "CHG1_OT_TO_IT_001"' in cli
    assert 'set srcintf "port1"' in cli
    assert 'set dstintf "port2"' in cli
    assert 'set srcaddr "H_10.1.2.3"' in cli
    assert 'set dstaddr "H_10.9.8.7"' in cli
    assert 'set service "SVC_TCP_8443"' in cli
    assert "set action accept" in cli
    assert 'set schedule "always"' in cli
    assert "set logtraffic all" in cli
    assert "set logtraffic-start enable" in cli
    assert 'set comments "Ticket <TICKET_ID>"' in cli
    # placement guidance appears as trailing comment
    assert "before policy ID 42" in cli
    assert "move" in cli


def test_policy_cli_no_log_start_no_insert():
    cli = policy_cli(
        name="P",
        srcintf="a",
        dstintf="b",
        srcaddr=["x"],
        dstaddr=["y"],
        service=["s"],
        logtraffic="utm",
        logtraffic_start=False,
        comments="",
        insert_before=None,
    )
    assert "logtraffic-start" not in cli
    assert "move" not in cli
    assert "set comments" not in cli


def test_policy_cli_multiple_addrs():
    cli = policy_cli(
        name="P",
        srcintf="a",
        dstintf="b",
        srcaddr=["x1", "x2"],
        dstaddr=["y"],
        service=["s"],
        logtraffic="all",
        logtraffic_start=False,
        comments="",
        insert_before=None,
    )
    assert 'set srcaddr "x1" "x2"' in cli


def test_exception_comment():
    text = exception_comment("CHG0099")
    assert "CHG0099" in text
    assert "exception" in text.lower()
    assert "<SecOps approver>" in text


def test_addrgrp_append_cli_exact():
    from app.planner.cli_gen import addrgrp_append_cli

    assert addrgrp_append_cli("WAN-to-Internet-Wifi", "H_10.1.1.7") == (
        "config firewall addrgrp\n"
        '    edit "WAN-to-Internet-Wifi"\n'
        '        append member "H_10.1.1.7"\n'
        "    next\n"
        "end"
    )


def test_addrgrp_append_cli_multiple_members():
    from app.planner.cli_gen import addrgrp_append_cli

    assert addrgrp_append_cli("GRP_X", ["H_A", "H_B"]) == (
        "config firewall addrgrp\n"
        '    edit "GRP_X"\n'
        '        append member "H_A"\n'
        '        append member "H_B"\n'
        "    next\n"
        "end"
    )


def test_addrgrp_create_cli_exact():
    from app.planner.cli_gen import addrgrp_create_cli

    assert addrgrp_create_cli("GRP_CHG1_SRC", ["H_10.0.0.1", "H_10.0.0.2"]) == (
        "config firewall addrgrp\n"
        '    edit "GRP_CHG1_SRC"\n'
        '        set member "H_10.0.0.1" "H_10.0.0.2"\n'
        '        set comment "<TICKET_ID>"\n'
        "    next\n"
        "end"
    )


def test_fqdn_address_object_cli():
    cli = fqdn_address_object_cli(
        "FQDN-api.vendor.com", "api.vendor.com", "Vendor API - CHG1"
    )
    assert cli == (
        "config firewall address\n"
        '    edit "FQDN-api.vendor.com"\n'
        "        set type fqdn\n"
        '        set fqdn "api.vendor.com"\n'
        '        set comment "Vendor API - CHG1"\n'
        "    next\n"
        "end"
    )


def test_wildcard_fqdn_address_object_cli():
    cli = wildcard_fqdn_address_object_cli("WFQDN-push.apple.com", "*.push.apple.com")
    assert "set type wildcard-fqdn" in cli
    assert 'set wildcard-fqdn "*.push.apple.com"' in cli
    assert "set comment" not in cli  # no comment passed


def test_fqdn_address_object_cli_escapes_quotes_and_strips_newlines():
    cli = fqdn_address_object_cli("FQDN-x", 'evil"fqdn\ninjected', "")
    assert '"' not in cli.split('set fqdn "')[1].split('"')[0].replace("''", "")
    assert "\n" not in cli.split('set fqdn "')[1].split('"')[0]


def test_addrgrp_create_cli_warn_replace_prepends_warning():
    cli = addrgrp_create_cli("GRP-DST", ["A", "B"], warn_replace=True)
    assert cli.startswith("# WARNING: 'set member' replaces all existing members.")
    assert 'set member "A" "B"' in cli


def test_addrgrp_create_cli_default_no_warning():
    cli = addrgrp_create_cli("GRP-DST", ["A"])
    assert not cli.startswith("#")


# ── Finding 1: CLI injection via the `name` argument ────────────────────────

_MALICIOUS_NAME = 'X"\n    next\nend\nconfig system admin\n    edit "evil'


def _edit_lines(cli: str) -> list[str]:
    return [ln for ln in cli.splitlines() if ln.strip().startswith("edit ")]


def test_fqdn_address_object_cli_escapes_injection_in_name():
    cli = fqdn_address_object_cli(_MALICIOUS_NAME, "api.vendor.com", "")
    edits = _edit_lines(cli)
    assert len(edits) == 1
    # The whole malicious payload collapsed onto the single edit line.
    assert edits[0].strip().startswith('edit "')
    assert edits[0].strip().endswith('"')
    # No injected structural keywords escaped onto their own lines.
    stripped = [ln.strip() for ln in cli.splitlines()]
    assert stripped.count("next") == 1
    assert stripped.count("end") == 1
    assert "config system admin" not in stripped
    assert "\n" not in edits[0]


def test_wildcard_fqdn_address_object_cli_escapes_injection_in_name():
    cli = wildcard_fqdn_address_object_cli(_MALICIOUS_NAME, "*.vendor.com")
    stripped = [ln.strip() for ln in cli.splitlines()]
    assert len(_edit_lines(cli)) == 1
    assert stripped.count("next") == 1
    assert stripped.count("end") == 1
    assert "config system admin" not in stripped


def test_addrgrp_create_cli_escapes_injection_in_name():
    cli = addrgrp_create_cli(_MALICIOUS_NAME, ["A"])
    stripped = [ln.strip() for ln in cli.splitlines()]
    assert len(_edit_lines(cli)) == 1
    assert stripped.count("next") == 1
    assert stripped.count("end") == 1
    assert "config system admin" not in stripped


def test_policy_cli_escapes_injection_in_name_and_comments():
    hostile = 'X"\r\n    next\nend\nconfig system admin\n    edit "evil\nnext\nend'
    cli = policy_cli(
        name=hostile,
        srcintf="port1",
        dstintf="port2",
        srcaddr=["SRC"],
        dstaddr=["DST"],
        service=["ALL"],
        logtraffic="all",
        logtraffic_start=True,
        comments=hostile,
        insert_before=None,
    )
    stripped = [ln.strip() for ln in cli.splitlines()]
    # Exactly the single-policy shape: one config/edit 0/next/end.
    assert stripped.count("config firewall policy") == 1
    assert len([ln for ln in stripped if ln.startswith("config ")]) == 1
    assert stripped.count("edit 0") == 1
    assert len(_edit_lines(cli)) == 1
    assert stripped.count("next") == 1
    assert stripped.count("end") == 1
    # No injected structural statements from the hostile payload.
    assert "config system admin" not in stripped
    assert 'edit "evil' not in stripped
    # Payload collapsed onto the single-line quoted fields, quotes escaped.
    name_line = next(ln for ln in stripped if ln.startswith("set name "))
    comment_line = next(ln for ln in stripped if ln.startswith("set comments "))
    for line in (name_line, comment_line):
        assert line.endswith('"')
        # Only the two delimiting quotes survive; inner quotes became ''.
        assert line.replace("''", "").count('"') == 2
        assert "''" in line
        assert "\n" not in line and "\r" not in line
