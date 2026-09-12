def test_schedulers_enabled_requires_inline_and_not_testing(monkeypatch):
    from app import _schedulers_enabled
    from app.config import Config

    monkeypatch.setattr(Config, "RUN_SCHEDULERS", "inline")
    assert _schedulers_enabled({"TESTING": False}) is True
    assert _schedulers_enabled({"TESTING": True}) is False

    monkeypatch.setattr(Config, "RUN_SCHEDULERS", "off")
    assert _schedulers_enabled({"TESTING": False}) is False
    assert _schedulers_enabled({"TESTING": True}) is False


def test_create_app_does_not_start_schedulers_by_default(monkeypatch):
    """RUN_SCHEDULERS defaults to "off" — create_app() must not call
    start_all_schedulers() unless a test/deployment explicitly opts in."""
    import app as app_module
    from app.config import Config

    monkeypatch.setattr(Config, "RUN_SCHEDULERS", "off")
    called = []
    monkeypatch.setattr(app_module, "start_all_schedulers", lambda a: called.append(a))

    app_module.create_app(test_config={"TESTING": False})

    assert called == []


def test_create_app_starts_schedulers_when_inline_and_not_testing(monkeypatch):
    import app as app_module
    from app.config import Config

    monkeypatch.setattr(Config, "RUN_SCHEDULERS", "inline")
    called = []
    monkeypatch.setattr(app_module, "start_all_schedulers", lambda a: called.append(a))

    created = app_module.create_app(test_config={"TESTING": False})

    assert called == [created]


def test_collector_module_forces_run_schedulers_inline(monkeypatch):
    import os

    monkeypatch.delenv("RUN_SCHEDULERS", raising=False)
    import importlib

    import app.collector as collector_module

    importlib.reload(collector_module)

    assert os.environ["RUN_SCHEDULERS"] == "inline"
