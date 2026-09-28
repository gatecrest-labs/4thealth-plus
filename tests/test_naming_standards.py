"""Tests for app/naming_standards.py — validation and persistence for
naming.yaml, used by the Admin → Naming Standards UI."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.naming_standards import (
    NamingValidationError,
    get_naming,
    reset_to_default,
    save_naming,
    validate_naming,
)

_REPO_ROOT = Path(__file__).parent.parent
_NAMING_EXAMPLE = _REPO_ROOT / "naming.example.yaml"


def _valid_naming_dict():
    import yaml
    return yaml.safe_load(_NAMING_EXAMPLE.read_text(encoding="utf-8"))


def test_validate_naming_accepts_shipped_default():
    assert validate_naming(_valid_naming_dict()) == []


def test_validate_naming_rejects_missing_pattern():
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["host"]["pattern"] = ""
    errors = validate_naming(data)
    assert any("host" in e for e in errors)


def test_validate_naming_rejects_unknown_token():
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["service"]["pattern"] = (
        "SVC_<NOT_A_REAL_TOKEN>"
    )
    errors = validate_naming(data)
    assert any("NOT_A_REAL_TOKEN" in e for e in errors)


def test_validate_naming_rejects_missing_convention_entirely():
    data = _valid_naming_dict()
    del data["platforms"]["fortigate"]["conventions"]["policy"]
    errors = validate_naming(data)
    assert any("policy" in e for e in errors)


def test_validate_naming_rejects_cross_type_token():
    """A host pattern using <PORT> (a service-only token) must be rejected
    even though PORT exists somewhere in the app's overall token universe —
    validate_naming() must check each type against only its own real
    vocabulary, not a pooled dict of every type's tokens."""
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["host"]["pattern"] = (
        "H_<PORT>_<TICKET_ID>"
    )
    errors = validate_naming(data)
    assert any("host" in e and "PORT" in e for e in errors)


def test_validate_naming_rejects_missing_log_settings():
    data = _valid_naming_dict()
    del data["log_settings"]
    errors = validate_naming(data)
    assert any("log_settings" in e for e in errors)


def test_validate_naming_rejects_empty_log_settings():
    data = _valid_naming_dict()
    data["log_settings"] = {}
    errors = validate_naming(data)
    assert any("log_settings" in e for e in errors)


def test_validate_naming_reports_all_errors_not_just_first():
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["host"]["pattern"] = ""
    data["platforms"]["fortigate"]["conventions"]["network"]["pattern"] = ""
    errors = validate_naming(data)
    assert len(errors) >= 2


def test_save_naming_writes_valid_data(tmp_path, monkeypatch):
    dest = tmp_path / "naming.yaml"
    monkeypatch.setattr("app.naming_standards._NAMING_PATH", dest)
    save_naming(_valid_naming_dict())
    assert dest.exists()
    assert "H_<IP_ADDRESS>" in dest.read_text(encoding="utf-8")


def test_save_naming_rejects_invalid_data_without_writing(tmp_path, monkeypatch):
    dest = tmp_path / "naming.yaml"
    monkeypatch.setattr("app.naming_standards._NAMING_PATH", dest)
    data = _valid_naming_dict()
    data["platforms"]["fortigate"]["conventions"]["host"]["pattern"] = ""
    with pytest.raises(NamingValidationError) as exc_info:
        save_naming(data)
    assert not dest.exists()
    assert any("host" in e for e in exc_info.value.errors)


def test_reset_to_default_copies_example_file(tmp_path, monkeypatch):
    dest = tmp_path / "naming.yaml"
    dest.write_text("stale: true", encoding="utf-8")
    monkeypatch.setattr("app.naming_standards._NAMING_PATH", dest)
    monkeypatch.setattr("app.naming_standards._NAMING_EXAMPLE_PATH", _NAMING_EXAMPLE)
    reset_to_default()
    assert "H_<IP_ADDRESS>" in dest.read_text(encoding="utf-8")


def test_get_naming_reads_current_file(tmp_path, monkeypatch):
    dest = tmp_path / "naming.yaml"
    dest.write_text(_NAMING_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    # get_naming() passes path=_NAMING_PATH explicitly to load_naming(), so
    # the module attribute to patch is this file's own _NAMING_PATH, not
    # app.planner.standards._NAMING_FILE (that default is only used when
    # load_naming() is called with no path argument at all).
    monkeypatch.setattr("app.naming_standards._NAMING_PATH", dest)
    naming = get_naming()
    assert "fortigate" in naming["platforms"]
