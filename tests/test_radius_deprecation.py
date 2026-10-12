import logging

from app import create_app


def test_enabling_standalone_radius_logs_a_deprecation_warning(caplog):
    with caplog.at_level(logging.WARNING):
        create_app(test_config={"TESTING": True, "RADIUS_ENABLED": True})
    messages = [r.getMessage() for r in caplog.records]
    assert any("RADIUS_ENABLED is deprecated" in m and "4tSuite" in m for m in messages)


def test_no_warning_when_standalone_radius_is_off(caplog):
    with caplog.at_level(logging.WARNING):
        create_app(test_config={"TESTING": True, "RADIUS_ENABLED": False})
    assert not any("RADIUS_ENABLED is deprecated" in r.getMessage() for r in caplog.records)
