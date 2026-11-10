"""Layer flags for the 1,000-device scale work (all default off)."""

import importlib

import pytest

FLAGS = ("INVENTORY_CACHE", "POLICY_STORE", "AUDIT_SNAPSHOTS", "JOB_QUEUE")


def _reload_config(monkeypatch, **env):
    for name in FLAGS:
        monkeypatch.delenv(name, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import app.config as cfg

    return importlib.reload(cfg).Config


@pytest.fixture(autouse=True)
def _restore_config():
    yield
    import app.config as cfg

    importlib.reload(cfg)


def test_flags_default_off(monkeypatch):
    config = _reload_config(monkeypatch)
    for name in FLAGS:
        assert getattr(config, name) is False


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
    config = _reload_config(monkeypatch, INVENTORY_CACHE=raw)
    assert config.INVENTORY_CACHE is expected
