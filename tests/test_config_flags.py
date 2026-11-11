"""Layer flags for the 1,000-device scale work (all default off).

Parsing is tested through ``_env_flag`` rather than by reloading
``app.config``: a reload replaces the ``Config`` class and breaks every other
test that patches ``app.config.Config``.
"""

import pytest

FLAGS = ("INVENTORY_CACHE", "POLICY_STORE", "AUDIT_SNAPSHOTS", "JOB_QUEUE")


def test_flags_exist_as_bool_on_config():
    from app.config import Config

    for name in FLAGS:
        assert isinstance(getattr(Config, name), bool)


def test_flag_unset_is_off(monkeypatch):
    from app.config import _env_flag

    monkeypatch.delenv("INVENTORY_CACHE", raising=False)
    assert _env_flag("INVENTORY_CACHE") is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", True),
        ("true", True),
        ("YES", True),
        ("on", True),
        ("0", False),
        ("", False),
        ("no", False),
    ],
)
def test_flags_parse_truthy_values(monkeypatch, raw, expected):
    from app.config import _env_flag

    monkeypatch.setenv("INVENTORY_CACHE", raw)
    assert _env_flag("INVENTORY_CACHE") is expected
