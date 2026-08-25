"""Tests for FortiOS/FortiManager version comparison."""
import pytest
from app.psirt.models import AffectedRange
from app.psirt.version_match import VersionMatchError, compare_versions, parse_version, version_in_range


def test_parse_version_three_part():
    assert parse_version("7.4.4") == (7, 4, 4)


def test_parse_version_two_part_padded():
    assert parse_version("7.4") == (7, 4, 0)


def test_parse_version_invalid_raises():
    with pytest.raises(VersionMatchError):
        parse_version("not-a-version")


def test_parse_version_empty_raises():
    with pytest.raises(VersionMatchError):
        parse_version("")


def test_compare_versions():
    assert compare_versions("7.4.4", "7.4.5") == -1
    assert compare_versions("7.4.5", "7.4.4") == 1
    assert compare_versions("7.4.4", "7.4.4") == 0


def test_version_in_range_bounded():
    rng = AffectedRange(product="FortiOS", min_version="7.4.0", max_version="7.4.4")
    assert version_in_range("7.4.2", rng) is True
    assert version_in_range("7.4.5", rng) is False
    assert version_in_range("7.3.9", rng) is False


def test_version_in_range_open_ended_below():
    """'X and below' — no min_version, everything <= max matches."""
    rng = AffectedRange(product="FortiOS", max_version="7.4.0")
    assert version_in_range("7.0.0", rng) is True
    assert version_in_range("7.4.0", rng) is True
    assert version_in_range("7.4.1", rng) is False


def test_version_in_range_open_ended_above():
    """No max_version — everything >= min matches."""
    rng = AffectedRange(product="FortiOS", min_version="7.4.0")
    assert version_in_range("7.4.0", rng) is True
    assert version_in_range("9.9.9", rng) is True
    assert version_in_range("7.3.9", rng) is False


def test_version_in_range_unparseable_device_version_raises():
    rng = AffectedRange(product="FortiOS", max_version="7.4.0")
    with pytest.raises(VersionMatchError):
        version_in_range("garbage", rng)
