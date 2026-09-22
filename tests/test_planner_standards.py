"""
Tests for planner/standards.py — deterministic naming, risk, logging, and
approval lookups. Pure logic; YAML dicts injected where possible, real repo
YAML files exercised for the loaders.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.planner import standards
from app.planner.matching import parse_service_request
from app.planner.models import PlannerDataError
from app.planner.standards import (
    load_naming,
    log_settings,
    object_name,
    policy_name,
    review_requirements,
    risk_level,
    rule_type_for,
)

_REPO_ROOT = Path(__file__).parent.parent
_NAMING_EXAMPLE = _REPO_ROOT / "naming.example.yaml"
_REVIEW_EXAMPLE = _REPO_ROOT / "review_requirements.example.yaml"


@pytest.fixture(autouse=True)
def _use_example_standards_files(monkeypatch):
    """object_name()/policy_name()/load_naming() read naming.yaml via
    standards._NAMING_FILE with no path override, so they always hit the
    real (gitignored, team-maintained) file. Point default lookups at the
    committed naming.example.yaml instead, same pattern as
    test_planner_engine.py, so these tests are self-contained and don't
    depend on runtime config existing on disk."""
    monkeypatch.setattr(standards, "_NAMING_FILE", _NAMING_EXAMPLE)


@pytest.fixture
def naming_path(tmp_path):
    """A tmp_path copy of naming.example.yaml — never depends on the
    gitignored naming.yaml existing at the repo root."""
    dest = tmp_path / "naming.yaml"
    dest.write_text(_NAMING_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    return dest


@pytest.fixture
def review_requirements_path(tmp_path):
    """A tmp_path copy of review_requirements.example.yaml — never depends
    on the gitignored review_requirements.yaml existing at the repo root."""
    dest = tmp_path / "review_requirements.yaml"
    dest.write_text(_REVIEW_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    return dest

# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

def test_object_name_host():
    assert object_name("host", ip="10.1.2.3") == "H_10.1.2.3"


def test_object_name_network():
    assert object_name("network", ip="10.8.0.0/16") == "N_10.8.0.0_16"


def test_object_name_service():
    assert object_name("service", proto="tcp", port="8443") == "SVC_TCP_8443"


def test_policy_name_with_ticket():
    assert policy_name("CHG0012345", "OT_LAN", "IT", seq=1) == "CHG0012345_OT_LAN_TO_IT_001"


def test_policy_name_placeholder_without_ticket():
    assert policy_name("", "WAN", "DMZ") == "<TICKET_ID>_WAN_TO_DMZ_001"


def test_load_naming_reads_repo_yaml(naming_path):
    naming = load_naming(path=naming_path)
    assert "fortigate" in naming["platforms"]
    assert "log_settings" in naming


from app.planner.naming_template import NamingTemplateError


def test_object_name_host_uses_pattern_from_naming_dict():
    naming = {"platforms": {"fortigate": {"conventions": {
        "host": {"pattern": "CUSTOM_<IP_ADDRESS>"},
    }}}}
    assert object_name("host", ip="10.1.2.3", naming=naming) == "CUSTOM_10.1.2.3"


def test_object_name_network_uses_pattern_from_naming_dict():
    naming = {"platforms": {"fortigate": {"conventions": {
        "network": {"pattern": "NET-<NETWORK_ADDRESS>-<PREFIX_LEN>"},
    }}}}
    assert (
        object_name("network", ip="10.8.0.0/16", naming=naming)
        == "NET-10.8.0.0-16"
    )


def test_object_name_network_defaults_prefix_to_32_when_absent():
    naming = {"platforms": {"fortigate": {"conventions": {
        "network": {"pattern": "N_<NETWORK_ADDRESS>_<PREFIX_LEN>"},
    }}}}
    assert object_name("network", ip="10.8.0.0", naming=naming) == "N_10.8.0.0_32"


def test_object_name_service_uses_pattern_from_naming_dict():
    naming = {"platforms": {"fortigate": {"conventions": {
        "service": {"pattern": "SVC-<PROTO>-<PORT>"},
    }}}}
    assert (
        object_name("service", proto="tcp", port="8443", naming=naming)
        == "SVC-TCP-8443"
    )


def test_object_name_unknown_type_raises_naming_template_error():
    with pytest.raises(NamingTemplateError):
        object_name("nat_rule", ip="10.1.2.3")


def test_object_name_missing_pattern_raises_naming_template_error():
    naming = {"platforms": {"fortigate": {"conventions": {
        "host": {},  # no "pattern" key at all
    }}}}
    with pytest.raises(NamingTemplateError):
        object_name("host", ip="10.1.2.3", naming=naming)


def test_policy_name_uses_pattern_from_naming_dict():
    naming = {"platforms": {"fortigate": {"conventions": {
        "policy": {"pattern": "<TICKET_ID>-<SRC_INTF>-<DST_INTF>-<SEQ>"},
    }}}}
    assert (
        policy_name("CHG1", "wan1", "dmz", seq=2, naming=naming)
        == "CHG1-WAN1-DMZ-002"
    )


def test_load_naming_not_cached_across_calls(naming_path):
    # Regression guard: earlier versions used @lru_cache on the loader,
    # which meant an on-disk edit was invisible until process restart.
    naming = load_naming(path=naming_path)
    assert naming["platforms"]["fortigate"]["conventions"]["host"]["pattern"] == "H_<IP_ADDRESS>"
    naming_path.write_text(
        naming_path.read_text(encoding="utf-8").replace(
            'pattern: "H_<IP_ADDRESS>"', 'pattern: "CHANGED_<IP_ADDRESS>"'
        ),
        encoding="utf-8",
    )
    reloaded = load_naming(path=naming_path)
    assert (
        reloaded["platforms"]["fortigate"]["conventions"]["host"]["pattern"]
        == "CHANGED_<IP_ADDRESS>"
    )


# ---------------------------------------------------------------------------
# Risk level (SKILL.md Step 5 logic, deterministic)
# ---------------------------------------------------------------------------

_DOMAINS = {
    "NSS OT-All": "OT",
    "NSS CIP-H-All": "CIP-H",
    "NSS IT DMZ": "IT",
    "NSS Corp Internal": "IT",
    "Users Networks": "Users",
    "Internet": "Internet",
}


def test_risk_ot_zone_is_critical():
    assert risk_level(["NSS OT-All"], ["NSS Corp Internal"], _DOMAINS) == "critical"


def test_risk_internet_destination_is_critical():
    assert risk_level(["NSS Corp Internal"], ["Internet"], _DOMAINS) == "critical"


def test_risk_internet_source_is_critical():
    assert risk_level(["Internet"], ["NSS Corp Internal"], _DOMAINS) == "critical"


def test_risk_internet_zone_name_is_critical_regardless_of_domain():
    # A catalogue may label the Internet zone's domain "Default" — the zone
    # NAME is authoritative for the catch-all.
    domains = {"Internet": "Default", "Internal-Wifi": "Default"}
    assert risk_level(["Internet"], ["Internal-Wifi"], domains) == "critical"
    assert risk_level(["Internal-Wifi"], ["Internet"], domains) == "critical"


def test_risk_cross_domain_is_high():
    assert risk_level(["Users Networks"], ["NSS IT DMZ"], _DOMAINS) == "high"


def test_risk_same_domain_is_medium():
    assert risk_level(["NSS Corp Internal"], ["NSS IT DMZ"], _DOMAINS) == "medium"


def test_risk_unknown_zone_is_critical():
    assert risk_level([], ["NSS IT DMZ"], _DOMAINS) == "critical"
    assert risk_level(["Mystery Zone"], ["NSS IT DMZ"], _DOMAINS) == "critical"


# ---------------------------------------------------------------------------
# Rule type for logging
# ---------------------------------------------------------------------------

def test_rule_type_ot_to_it():
    assert rule_type_for("ALLOWED", {"OT"}, {"IT"},
                         parse_service_request("443")) == "allow_ot_to_it"


def test_rule_type_it_to_ot():
    assert rule_type_for("ALLOWED", {"IT"}, {"OT"},
                         parse_service_request("443")) == "allow_it_to_ot"


def test_rule_type_internet_outbound():
    assert rule_type_for("ALLOWED", {"IT"}, {"Internet"},
                         parse_service_request("443")) == "allow_internet_outbound"


def test_rule_type_internet_inbound():
    assert rule_type_for("ALLOWED", {"Internet"}, {"IT"},
                         parse_service_request("443")) == "allow_internet_inbound"


def test_rule_type_internet_inbound_wins_over_management_ports():
    assert rule_type_for("ALLOWED", {"Internet"}, {"IT"},
                         parse_service_request("ssh")) == "allow_internet_inbound"


def test_rule_type_management_ports():
    assert rule_type_for("ALLOWED", {"IT"}, {"IT"},
                         parse_service_request("ssh")) == "management_access"
    assert rule_type_for("ALLOWED", {"IT"}, {"IT"},
                         parse_service_request("3389")) == "management_access"


def test_rule_type_internal_default():
    assert rule_type_for("ALLOWED", {"IT"}, {"IT"},
                         parse_service_request("8443")) == "allow_internal"


def test_rule_type_blocked_exception_uses_dst_domain():
    # a blocked flow still gets the logging profile of its zone pair
    assert rule_type_for("BLOCKED", {"IT"}, {"OT"},
                         parse_service_request("443")) == "allow_it_to_ot"


# ---------------------------------------------------------------------------
# YAML-backed lookups
# ---------------------------------------------------------------------------

def test_log_settings_known_type(naming_path):
    naming = load_naming(path=naming_path)
    s = log_settings("allow_it_to_ot", naming=naming)
    assert s["log_start"] is True
    assert s["siem_forward"] is True
    assert s["retention_days"] == 365


def test_log_settings_unknown_type_raises(naming_path):
    naming = load_naming(path=naming_path)
    with pytest.raises(KeyError):
        log_settings("no_such_rule_type", naming=naming)


def test_review_requirements_critical(review_requirements_path):
    r = review_requirements("critical", path=review_requirements_path)
    assert r["peer_review"] is True
    assert any("CISO" in a for a in r["approvers"])
    assert r["sla_hours"] == 96


def test_load_naming_missing_file_raises_planner_data_error(tmp_path):
    missing = tmp_path / "does-not-exist.yaml"
    with pytest.raises(PlannerDataError) as exc_info:
        load_naming(path=missing)
    assert exc_info.value.source == "standards"
    assert "does-not-exist.yaml" in exc_info.value.detail


def test_review_requirements_missing_file_raises_planner_data_error(tmp_path):
    missing = tmp_path / "does-not-exist.yaml"
    with pytest.raises(PlannerDataError) as exc_info:
        review_requirements("critical", path=missing)
    assert exc_info.value.source == "standards"
    assert "does-not-exist.yaml" in exc_info.value.detail


# ---------------------------------------------------------------------------
# Least-privilege / permissiveness checks
# ---------------------------------------------------------------------------

from app.planner.standards import permissiveness_warnings


def _warns(srcs, dsts, service):
    return permissiveness_warnings(srcs, dsts, parse_service_request(service))


def test_specific_flow_has_no_permissiveness_warnings():
    assert _warns(["10.1.2.3"], ["10.9.8.7"], "tcp/443") == []


def test_slash24_networks_are_fine():
    assert _warns(["10.1.2.0/24"], ["10.9.8.0/24"], "tcp/443") == []


def test_any_source_flagged():
    warns = _warns(["0.0.0.0/0"], ["10.9.8.7"], "tcp/443")
    assert any("ANY source" in w for w in warns)


def test_any_destination_flagged():
    warns = _warns(["10.1.2.3"], ["0.0.0.0/0"], "tcp/443")
    assert any("ANY destination" in w for w in warns)


def test_broad_source_network_flagged():
    warns = _warns(["10.0.0.0/8"], ["10.9.8.7"], "tcp/443")
    assert any("10.0.0.0/8" in w and "broad" in w.lower() for w in warns)


def test_slash16_not_flagged_as_broad():
    assert _warns(["10.1.0.0/16"], ["10.9.8.7"], "tcp/443") == []


def test_any_service_flagged():
    warns = _warns(["10.1.2.3"], ["10.9.8.7"], "any")
    assert any("ANY service" in w for w in warns)


def test_wide_port_range_flagged():
    warns = _warns(["10.1.2.3"], ["10.9.8.7"], "tcp/1000-9000")
    assert any("1000-9000" in w and "port" in w.lower() for w in warns)


def test_moderate_port_range_not_flagged():
    assert _warns(["10.1.2.3"], ["10.9.8.7"], "tcp/8000-8100") == []


def test_any_any_any_escalated():
    warns = _warns(["0.0.0.0/0"], ["0.0.0.0/0"], "any")
    assert any("least-privilege" in w for w in warns)


def test_invalid_token_ignored_not_crash():
    # non-IP tokens (e.g. an FQDN) are skipped, never a crash
    assert _warns(["app.example.com"], ["10.9.8.7"], "tcp/443") == []
