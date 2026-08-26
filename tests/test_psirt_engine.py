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
    defaults = {
        "advisory_id": "FG-IR-24-001",
        "cve_ids": ["CVE-2024-12345"],
        "cvss_score": 8.1,
        "affected_ranges": [AffectedRange(product="FortiOS", min_version="", max_version="7.4.4",
                                          fixed_version="7.4.5")],
        "workaround_text": "",
        "exploited_in_wild_text": "",
    }
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
    # _fake_http_client() 404s the advisory-page fetch, so this scan is
    # enrichment-degraded — per finding #3, a degraded scan with no devices
    # confirmed in range must be reported as "unknown", not "informational"
    # (the two are indistinguishable to compute_priority(), but a degraded
    # scan cannot honestly claim "nothing to act on").
    assert result.degraded is True
    assert result.priority == "unknown"


def test_assess_out_of_range_device_no_action_when_not_degraded():
    """Same out-of-range scenario as above, but with a clean (non-degraded)
    enrichment fetch — this is the genuine 'nothing to act on' case and
    must still report 'informational', confirming fix #3 only changes
    behavior for degraded scans."""
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW02", "os_ver": "7.0", "mr": "6", "patch": "1"},  # 7.6.1, out of range
    ]
    client = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "CVSS Score: 8.1. Severity: High."
    resp.json.return_value = {"vulnerabilities": []}
    client.get.return_value = resp
    advisory = _make_advisory(advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    result = assess(advisory, fmg, "Corp", client, "https://kev.example/feed.json", enrichment_enabled=True)
    assert result.degraded is False
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


def test_assess_star_scope_filters_forti_prefixed_adoms():
    """Finding #7: '*' scope must apply the same forti-prefix ADOM filter
    every other ADOM-returning endpoint in this repo applies."""
    fmg = MagicMock()
    fmg.get_adoms.return_value = [
        {"name": "Corp"},
        {"name": "FortiManager_Managed_Devices"},
        {"name": "fortitest_system"},
    ]

    def _devices(adom):
        return [{"name": f"FW-{adom}", "os_ver": "7.0", "mr": "4", "patch": "2"}]
    fmg.get_devices.side_effect = _devices

    advisory = _make_advisory()
    result = assess(advisory, fmg, "*", _fake_http_client(), "", enrichment_enabled=True)
    adoms_scanned = {f.adom for f in result.findings}
    assert adoms_scanned == {"Corp"}
    fmg.get_devices.assert_called_once_with("Corp")


def test_assess_degraded_with_findings_but_none_in_range_is_unknown_not_informational():
    """Finding #3: a degraded scan (one ADOM's device list failed) whose
    checked devices are all out of range must not be reported as
    'informational / nothing to act on' — that's indistinguishable from a
    genuinely clean fleet, but here we know coverage was incomplete."""
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}, {"name": "Branch"}]

    _branch_error = RuntimeError("FMG unreachable for Branch")

    def _devices(adom):
        if adom == "Branch":
            raise _branch_error
        # Corp's device is out of the advisory's affected range.
        return [{"name": "FW-Corp", "os_ver": "7.0", "mr": "6", "patch": "1"}]
    fmg.get_devices.side_effect = _devices

    advisory = _make_advisory()  # affected range: FortiOS <= 7.4.4
    result = assess(advisory, fmg, "*", _fake_http_client(), "", enrichment_enabled=True)
    assert result.degraded is True
    assert len(result.findings) == 1  # Corp's device was checked
    assert result.findings[0].in_range is False
    assert result.priority == "unknown"
    assert "partial fleet coverage" in result.priority_rationale


def test_assess_surfaces_kev_fetch_failure_warning():
    """Finding #4: a KEV-feed failure (distinct from advisory-page failure)
    must degrade the assessment and surface a specific warning string."""
    fmg = MagicMock()
    fmg.get_adoms.return_value = [{"name": "Corp"}]
    fmg.get_devices.return_value = [
        {"name": "FW01", "os_ver": "7.0", "mr": "4", "patch": "2"},
    ]

    client = MagicMock()
    page_resp = MagicMock()
    page_resp.status_code = 200
    page_resp.text = "CVSS Score: 8.1. Severity: High."
    kev_resp = MagicMock()
    kev_resp.status_code = 500  # KEV feed unreachable
    client.get.side_effect = [page_resp, kev_resp]

    # advisory_url must be set — fetch_advisory_page() skips the HTTP call
    # entirely for an empty URL, which would shift the mocked call sequence
    # and make the KEV check consume the page-fetch mock response instead.
    advisory = _make_advisory(advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    result = assess(advisory, fmg, "Corp", client, "https://kev.example/feed.json", enrichment_enabled=True)
    assert result.degraded is True
    assert any("KEV" in w for w in result.warnings)
