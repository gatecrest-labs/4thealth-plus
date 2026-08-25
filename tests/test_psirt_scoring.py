"""Tests for deterministic PSIRT priority scoring."""
from app.psirt.scoring import compute_priority


def test_zero_exposure_is_informational_regardless_of_severity():
    priority, rationale = compute_priority(
        cvss_score=9.8, fortinet_severity="Critical",
        exploited_in_wild_text="actively exploited",
        kev_hit=True, any_device_in_range=False,
    )
    assert priority == "informational"
    assert "no devices" in rationale.lower() or "nothing to act on" in rationale.lower()


def test_cvss_band_critical():
    priority, _ = compute_priority(9.5, "", "", False, True)
    assert priority == "critical"


def test_cvss_band_high():
    priority, _ = compute_priority(7.5, "", "", False, True)
    assert priority == "high"


def test_cvss_band_medium():
    priority, _ = compute_priority(5.0, "", "", False, True)
    assert priority == "medium"


def test_cvss_band_low():
    priority, _ = compute_priority(2.0, "", "", False, True)
    assert priority == "low"


def test_no_cvss_falls_back_to_fortinet_severity():
    priority, rationale = compute_priority(None, "High", "", False, True)
    assert priority == "high"
    assert "fortinet" in rationale.lower()


def test_no_cvss_no_severity_defaults_medium():
    priority, _ = compute_priority(None, "", "", False, True)
    assert priority == "medium"


def test_kev_hit_forces_at_least_high():
    priority, rationale = compute_priority(4.0, "", "", kev_hit=True, any_device_in_range=True)
    assert priority == "high"
    assert "kev" in rationale.lower()


def test_exploited_text_forces_at_least_high():
    priority, rationale = compute_priority(
        3.0, "", "actively exploited in the wild", kev_hit=False, any_device_in_range=True,
    )
    assert priority == "high"
    assert "exploit" in rationale.lower()


def test_negative_exploitation_language_does_not_force_high():
    """'Fortinet is not aware of exploitation' must NOT trigger escalation."""
    priority, _ = compute_priority(
        3.0, "", "Fortinet is not aware of any instance where this vulnerability has been exploited",
        kev_hit=False, any_device_in_range=True,
    )
    assert priority == "low"


def test_kev_does_not_downgrade_an_already_critical_score():
    priority, _ = compute_priority(9.5, "", "", kev_hit=True, any_device_in_range=True)
    assert priority == "critical"
