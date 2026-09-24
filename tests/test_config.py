def test_session_cookie_name_is_app_specific():
    """Must not be Flask's default "session" -- browser cookies are scoped
    by domain+path, not port, so a default name collides with any other
    local Flask app (e.g. 4tlog, 4tExecutive) served from localhost at a
    different port, silently clobbering each other's session cookie.

    SESSION_COOKIE_NAME is a fixed string literal, not derived from any
    env var -- unlike SECRET_KEY, it needs no importlib.reload() to test.
    (An earlier version of this test did reload app.config, which swaps
    app.config.Config for a new class object; any module that had already
    done `from app.config import Config` -- e.g. app/llm/claude_provider.py
    -- keeps pointing at the stale one, so later
    monkeypatch.setattr("app.config.Config...") calls in unrelated test
    files silently miss. That caused real, hard-to-trace failures in
    tests/test_llm_providers.py. Reproducible directly:
    `pytest tests/test_config.py tests/test_llm_providers.py` failed
    before this fix, passes after.)"""
    from app.config import Config

    assert Config.SESSION_COOKIE_NAME == "4thealth_plus_session"
