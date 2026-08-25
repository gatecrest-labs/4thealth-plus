"""End-to-end tests for psirt.engine.assess() against a fake FMGClient."""
from unittest.mock import MagicMock

from app.psirt.engine import assess
from app.psirt.models import Advisory, AffectedRange


def _fake_http_client():
    client = MagicMock()
    resp = MagicMock()
    resp.status_code = 404  # advisory page not found — degrade gracefully
    resp.json.return_value = {"vulnerabilities": []}
    resp.text = ""
    client.get.return_value = resp
    return client


def _make_advisory(**overrides):
    defaults = dict(
        advisory_id="FG-IR-24-001",
        cve_ids=["CVE-2024-12345"],
        cvss_score=8.1,
        affected_ranges=[AffectedRange(product="FortiOS", min_version="", max_version="7.4.4",
                                        fixed_version="7.4.5")],
        workaround_text="",
        exploited_in_wild_text="",
    )
    defaults.update(overrides)
    return Advisory(**defaults)


def test_assess_single_adom_no_workaround_upgrade_required():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"},
    ]
    advisory = _make_advisory()
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.device == "FW01"
    assert f.current_version == "7.4.2"
    assert f.in_range is True
    assert f.verdict == "upgrade_required"
    assert result.priority == "high"  # CVSS 8.1 band


def test_assess_out_of_range_device_no_action():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW02", "os_ver": "7.0", "mr": "6", "patch": "1"},  # 7.6.1, out of range
    ]
    advisory = _make_advisory()
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert result.findings[0].verdict == "no_action"
    assert result.priority == "informational"


def test_assess_workaround_in_place_no_action():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"},
    ]
    fmg.get_device_interfaces_all_vdoms.return_value = [
        {"name": "port1", "allowaccess": "ping"},
    ]
    advisory = _make_advisory(workaround_text="Disable HTTP/HTTPS admin access")
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    f = result.findings[0]
    assert f.workaround_status == "in_place"
    assert f.verdict == "no_action"


def test_assess_unrecognized_workaround_text_is_manual_verification():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"},
    ]
    advisory = _make_advisory(workaround_text="Contact Fortinet support for a hotfix")
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    f = result.findings[0]
    assert f.workaround_status == "manual_verification_required"
    assert f.verdict == "config_change_required"


def test_assess_scans_all_adoms_when_scope_is_star():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}, {"name": "Branch"}]

    def _devices(adom):
        return [{"name": f"FW-{adom}", "os_ver": "7.0", "mr": "4", "patch": "2"}]
    fmg.get_devices.side_effect = _devices

    advisory = _make_advisory()
    result = assess(advisory, fmg, "*", _fake_http_client(), "", enrichment_enabled=True)
    devices_seen = {f.device for f in result.findings}
    assert devices_seen == {"FW-Corp", "FW-Branch"}


def test_assess_missing_firmware_is_unknown_needs_manual_check():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [{"name": "FW01"}]  # no os_ver/mr/patch
    advisory = _make_advisory()
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert result.findings[0].verdict == "unknown_needs_manual_check"


def test_assess_device_list_failure_is_degraded():
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.side_effect = Exception("FMG unreachable")
    advisory = _make_advisory()
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert result.degraded is True
    assert result.findings == []
    assert result.priority == "unknown"


def test_assess_fortimanager_product_evaluated():
    fmg = MagicMock()
    fmg.get_system_status.return_value = {"Version": "v7.4.5,build2360,240702 (GA)"}
    fmg.get_adoms.return_value = []
    advisory = _make_advisory(affected_ranges=[
        AffectedRange(product="FortiManager", max_version="7.4.4", fixed_version="7.4.5"),
    ])
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert len(result.findings) == 1
    assert result.findings[0].product == "FortiManager"
    assert result.findings[0].current_version == "7.4.5"
    assert result.findings[0].verdict == "no_action"  # 7.4.5 is the fixed version, out of range


def test_assess_out_of_scope_product_listed():
    fmg = MagicMock()
    fmg.get_adoms.return_value = []
    advisory = _make_advisory(affected_ranges=[
        AffectedRange(product="FortiSwitch", max_version="7.0.0"),
    ])
    result = assess(advisory, fmg, "Corp", _fake_http_client(), "", enrichment_enabled=True)
    assert result.out_of_scope_products == ["FortiSwitch"]
    assert result.findings == []
