import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")


def test_proxy_fix_applied_when_env_set(monkeypatch):
    """When TRUSTED_PROXY_COUNT is set, the wsgi app should be wrapped with ProxyFix."""
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    # Re-import wsgi to pick up the env var change
    import importlib

    import wsgi as wsgi_mod
    importlib.reload(wsgi_mod)
    from werkzeug.middleware.proxy_fix import ProxyFix
    assert isinstance(wsgi_mod.app, ProxyFix)


def test_proxy_fix_not_applied_by_default(monkeypatch):
    """Without TRUSTED_PROXY_COUNT, wsgi app should NOT be wrapped with ProxyFix."""
    monkeypatch.delenv("TRUSTED_PROXY_COUNT", raising=False)
    import importlib

    import wsgi as wsgi_mod
    importlib.reload(wsgi_mod)
    from werkzeug.middleware.proxy_fix import ProxyFix
    assert not isinstance(wsgi_mod.app, ProxyFix)
