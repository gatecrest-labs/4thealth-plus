"""F1 access layer: shared session pool, config knobs (in-flight cap added in Task 2)."""

import threading

import pytest

from app import fmg_access


@pytest.fixture(autouse=True)
def _fresh():
    fmg_access.reset()
    yield
    fmg_access.reset()


def test_same_session_returned_for_same_verify():
    assert fmg_access.get_session(True) is fmg_access.get_session(True)


def test_different_verify_gives_different_session():
    assert fmg_access.get_session(True) is not fmg_access.get_session(False)


def test_session_creation_is_thread_safe():
    seen = []
    barrier = threading.Barrier(32)

    def worker():
        barrier.wait()
        seen.append(fmg_access.get_session(False))

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({id(s) for s in seen}) == 1


def test_adapter_pool_maxsize_is_32():
    adapter = fmg_access.get_session(True).get_adapter("https://fmg.example/jsonrpc")
    assert adapter._pool_maxsize == 32


def test_config_defaults():
    from app.config import Config

    assert Config.FMG_RETRIES == 2
    assert Config.FMG_MAX_INFLIGHT is None


def test_env_int_parsing(monkeypatch):
    from app.config import _env_int

    monkeypatch.delenv("X_KNOB", raising=False)
    assert _env_int("X_KNOB", 5) == 5
    assert _env_int("X_KNOB", None) is None
    monkeypatch.setenv("X_KNOB", "7")
    assert _env_int("X_KNOB", 5) == 7
    monkeypatch.setenv("X_KNOB", "bogus")
    assert _env_int("X_KNOB", 5) == 5
    monkeypatch.setenv("X_KNOB", "")
    assert _env_int("X_KNOB", 5) == 5
