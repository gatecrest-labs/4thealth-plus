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


# ---- Task 2: in-flight cap ----
import time

from app.config import Config


def test_cap_defaults_by_role(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", None)
    monkeypatch.setattr(fmg_access.fmg_metrics, "role", lambda: "collector")
    assert fmg_access.inflight_cap() == 8
    monkeypatch.setattr(fmg_access.fmg_metrics, "role", lambda: "web")
    assert fmg_access.inflight_cap() == 4


def test_explicit_cap_overrides_role(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 3)
    monkeypatch.setattr(fmg_access.fmg_metrics, "role", lambda: "collector")
    assert fmg_access.inflight_cap() == 3


def test_zero_means_unlimited_and_slot_does_not_block(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 0)
    assert fmg_access.inflight_cap() == 0
    with fmg_access.slot(), fmg_access.slot(), fmg_access.slot():
        pass


def test_peak_never_exceeds_cap_under_100_threads(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 3)

    def worker():
        with fmg_access.slot():
            time.sleep(0.005)

    threads = [threading.Thread(target=worker) for _ in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert fmg_access.peak_inflight() == 3


def test_slot_released_after_exception(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 1)
    for _ in range(10):
        with pytest.raises(RuntimeError), fmg_access.slot():
            raise RuntimeError("boom")
    done = threading.Event()

    def worker():
        with fmg_access.slot():
            done.set()

    threading.Thread(target=worker, daemon=True).start()
    assert done.wait(1.0)


def test_slot_yields_wait_seconds(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 1)
    waits = []
    holding = threading.Event()

    def first():
        with fmg_access.slot():
            holding.set()
            time.sleep(0.1)

    def second():
        holding.wait()
        with fmg_access.slot() as waited:
            waits.append(waited)

    a, b = threading.Thread(target=first), threading.Thread(target=second)
    a.start()
    b.start()
    a.join()
    b.join()
    assert waits[0] > 0.02


def test_slot_wait_is_bounded_and_does_not_leak(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 1)
    monkeypatch.setattr(Config, "FMG_SLOT_WAIT_SECS", 0.05)
    holding, release = threading.Event(), threading.Event()

    def holder():
        with fmg_access.slot():
            holding.set()
            release.wait(2)

    t = threading.Thread(target=holder)
    t.start()
    holding.wait()
    with pytest.raises(fmg_access.SlotTimeout), fmg_access.slot():
        pass
    release.set()
    t.join()
    with fmg_access.slot():  # the timed-out waiter must not have leaked a slot
        pass
    assert fmg_access.peak_inflight() == 1


def test_slot_wait_zero_means_unbounded(monkeypatch):
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 1)
    monkeypatch.setattr(Config, "FMG_SLOT_WAIT_SECS", 0)
    with fmg_access.slot():
        pass
