"""Regression test for manage_users.py's cmd_secret.

cmd_secret used to call app.auth.generate_secret_key(), which transitively
imports app.config -- and app.config raises RuntimeError at import time if
SECRET_KEY isn't already set in the environment. That made it impossible to
run the documented first-run "generate a SECRET_KEY" step, since the whole
point of the command is to produce that value before it exists anywhere.

The fix replaced the app.auth import with a direct secrets.token_hex(32)
call. This test locks in that behavior by asserting cmd_secret still works
when SECRET_KEY is absent from the environment.
"""
import re

import pytest


@pytest.fixture
def manage_users(monkeypatch):
    # Simulate the true first-run scenario: no SECRET_KEY in the environment
    # at all. conftest.py sets SECRET_KEY via os.environ.setdefault() for
    # the rest of the suite, so explicitly delete it for this test.
    monkeypatch.delenv("SECRET_KEY", raising=False)

    import importlib

    import manage_users as mu

    importlib.reload(mu)
    return mu


def test_cmd_secret_succeeds_without_secret_key_in_env(manage_users, monkeypatch, capsys):
    import os

    assert "SECRET_KEY" not in os.environ

    manage_users.cmd_secret(None)

    captured = capsys.readouterr()
    assert "Generated SECRET_KEY:" in captured.out

    match = re.search(r"Generated SECRET_KEY:\n([0-9a-f]+)", captured.out)
    assert match is not None, captured.out
    key = match.group(1)

    # secrets.token_hex(32) -> 32 bytes -> 64 hex characters.
    assert len(key) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", key)

    assert f"SECRET_KEY={key}" in captured.out
