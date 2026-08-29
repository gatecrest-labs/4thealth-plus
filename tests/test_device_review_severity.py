"""Tests for the static device-review check severity table."""

from app.device_review import CHECKS
from app.device_review_severity import SEVERITY


def test_every_check_key_has_a_severity():
    check_keys = {c["key"] for c in CHECKS}
    assert set(SEVERITY) == check_keys


def test_severity_values_are_valid():
    valid = {"critical", "high", "medium", "low"}
    assert all(v in valid for v in SEVERITY.values())


def test_default_admin_is_critical():
    assert SEVERITY["default_admin"] == "critical"


def test_ha_sync_is_critical():
    assert SEVERITY["ha_sync"] == "critical"
