import importlib
import os


def test_session_cookie_name_is_app_specific(monkeypatch):
    """Must not be Flask's default "session" -- browser cookies are scoped
    by domain+path, not port, so a default name collides with any other
    local Flask app (e.g. 4tlog, 4tExecutive) served from localhost at a
    different port, silently clobbering each other's session cookie."""
    monkeypatch.setenv("SECRET_KEY", "a-real-secret")
    import app.config as config_mod

    importlib.reload(config_mod)
    assert config_mod.Config.SESSION_COOKIE_NAME == "4thealth_plus_session"
    # restore for subsequent tests in the same process
    os.environ["SECRET_KEY"] = "test-secret-key-for-ci"
    importlib.reload(config_mod)
