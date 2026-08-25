"""Tests for PSIRT dataclass models — construction and to_dict() shape."""
from app.psirt.models import Advisory, AffectedRange, DeviceFinding, PsirtAssessment


def test_affected_range_to_dict():
    r = AffectedRange(product="FortiOS", min_version="7.4.0", max_version="7.4.4",
                       fixed_version="7.4.5", notes="")
    assert r.to_dict() == {
        "product": "FortiOS", "min_version": "7.4.0", "max_version": "7.4.4",
        "fixed_version": "7.4.5", "notes": "",
    }


def test_advisory_to_dict_round_trip():
    adv = Advisory(
        advisory_id="FG-IR-24-001",
        cve_ids=["CVE-2024-12345"],
        affected_ranges=[AffectedRange(product="FortiOS", max_version="7.4.4")],
    )
    d = adv.to_dict()
    assert d["advisory_id"] == "FG-IR-24-001"
    assert d["cve_ids"] == ["CVE-2024-12345"]
    assert d["affected_ranges"] == [
        {"product": "FortiOS", "min_version": "", "max_version": "7.4.4",
         "fixed_version": "", "notes": ""}
    ]
    assert d["enrichment_degraded"] is False


def test_device_finding_to_dict():
    f = DeviceFinding(device="FW01", adom="Corp", product="FortiOS",
                       current_version="7.4.2", in_range=True,
                       workaround_status="not_in_place",
                       verdict="config_change_required", reason="test reason")
    assert f.to_dict()["verdict"] == "config_change_required"
    assert f.to_dict()["in_range"] is True


def test_psirt_assessment_to_dict():
    adv = Advisory(advisory_id="FG-IR-24-001")
    finding = DeviceFinding(device="FW01", adom="Corp", product="FortiOS",
                             current_version="7.4.2", in_range=True,
                             workaround_status="not_in_place",
                             verdict="config_change_required", reason="r")
    assessment = PsirtAssessment(advisory=adv, findings=[finding], priority="high",
                                  priority_rationale="CVSS 8.1", kev_hit=True)
    d = assessment.to_dict()
    assert d["advisory"]["advisory_id"] == "FG-IR-24-001"
    assert d["findings"][0]["device"] == "FW01"
    assert d["priority"] == "high"
    assert d["kev_hit"] is True
