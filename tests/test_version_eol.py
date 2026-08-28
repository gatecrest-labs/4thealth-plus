"""Tests for the static FortiOS version end-of-support table."""

from app.version_eol import is_eol


def test_known_eol_version_returns_true():
    assert is_eol("v6.4.2") is True


def test_current_version_returns_false():
    assert is_eol("v7.4.5") is False


def test_unknown_version_defaults_to_not_eol():
    assert is_eol("v99.9.9") is False


def test_handles_version_without_v_prefix():
    assert is_eol("6.4.2") is True
