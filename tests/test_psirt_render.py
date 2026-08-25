"""Tests for PSIRT HTML report rendering."""
import os
import pytest

from app.psirt.models import Advisory, AffectedRange, DeviceFinding, PsirtAssessment


@pytest.fixture(autouse=True)
def _app_context():
    os.environ.setdefault("SECRET_KEY", "test-secret")
    os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")
    from app import create_app
    app = create_app()
    with app.test_request_context():
        yield


from app.psirt.render import render_psirt_html  # noqa: E402  (import after env vars set)


def _sample_assessment():
    advisory = Advisory(
        advisory_id="FG-IR-24-001",
        advisory_url="https://fortiguard.com/psirt/FG-IR-24-001",
        cve_ids=["CVE-2024-12345"],
        fortinet_severity="High",
        cvss_score=8.1,
        description="A vulnerability in FortiOS allows remote code execution.",
        affected_ranges=[AffectedRange(product="FortiOS", max_version="7.4.4", fixed_version="7.4.5")],
        exploited_in_wild_text="actively exploited in the wild",
    )
    findings = [
        DeviceFinding(device="FW01", adom="Corp", product="FortiOS", current_version="7.4.2",
                      in_range=True, workaround_status="not_applicable",
                      verdict="upgrade_required", reason="Firmware 7.4.2 is affected."),
        DeviceFinding(device="FW02", adom="Corp", product="FortiOS", current_version="7.6.1",
                      in_range=False, workaround_status="not_applicable",
                      verdict="no_action", reason="Out of affected range."),
    ]
    return PsirtAssessment(
        advisory=advisory, findings=findings, out_of_scope_products=["FortiSwitch"],
        priority="critical", priority_rationale="CVSS 8.1; forced to at least High because exploited",
        kev_hit=True, degraded=False, warnings=[],
    )


def test_render_includes_advisory_id_and_cve():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert "FG-IR-24-001" in html
    assert "CVE-2024-12345" in html


def test_render_includes_priority_and_kev_badge():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert "critical" in html.lower()
    assert "kev" in html.lower()


def test_render_includes_all_device_findings():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert "FW01" in html
    assert "FW02" in html
    assert "upgrade_required" in html.lower() or "upgrade required" in html.lower()


def test_render_includes_out_of_scope_products():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert "FortiSwitch" in html


def test_render_includes_warnings_when_present():
    data = _sample_assessment().to_dict()
    data["warnings"] = ["Could not reach FortiManager (primary): timeout"]
    html = render_psirt_html(data)
    assert "Could not reach FortiManager" in html


def test_render_escapes_html_in_reason_field():
    """User/advisory-derived text must be escaped — no injection into the report."""
    data = _sample_assessment().to_dict()
    data["findings"][0]["reason"] = "<script>alert(1)</script>"
    html = render_psirt_html(data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_is_self_contained_document():
    html = render_psirt_html(_sample_assessment().to_dict())
    assert html.strip().startswith("<!DOCTYPE html>")
    assert "<style>" in html
