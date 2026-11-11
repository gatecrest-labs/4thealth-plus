"""Ordered, jittered boot warm-up (Phase 2, Task 8)."""

import threading
import time

import pytest

from app import boot_warmup, inventory_cache
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    boot_warmup.reset()
    monkeypatch.setattr(boot_warmup, "_STEP_SECONDS", 0.05)
    monkeypatch.setattr(boot_warmup, "_JITTER_SECONDS", 0.0)
    monkeypatch.setattr(boot_warmup, "_GATE_TIMEOUT_SECONDS", 2.0)
    yield
    boot_warmup.reset()


def test_flag_off_runs_immediately_without_gate_or_delay(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    done = threading.Event()
    boot_warmup.defer("x", done.set, priority=3)
    assert done.wait(0.5)  # no gate, no stagger


def test_priority_order_and_stagger(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    order, stamps = [], {}
    t0 = time.monotonic()
    for pr in (3, 1, 2, 0):
        boot_warmup.defer(
            f"p{pr}",
            lambda pr=pr: (
                order.append(pr),
                stamps.__setitem__(pr, time.monotonic() - t0),
            ),
            priority=pr,
        )
    boot_warmup.mark_inventory_ready()
    assert boot_warmup.join(3)
    assert order == [0, 1, 2, 3]
    assert (
        stamps[1] >= 0.04
        and stamps[2] - stamps[1] >= 0.03
        and stamps[3] - stamps[2] >= 0.03
    )


def test_priority_zero_does_not_wait_for_the_gate(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    ran = threading.Event()
    boot_warmup.defer("inventory", ran.set, priority=0)
    assert ran.wait(0.5)  # gate never opened


def test_waits_for_inventory_first_refresh_then_runs(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    ran = threading.Event()
    boot_warmup.defer("later", ran.set, priority=1)
    assert not ran.wait(0.3)  # held by the gate
    boot_warmup.mark_inventory_ready()
    assert ran.wait(1.0)


def test_gate_timeout_releases_jobs_if_inventory_never_finishes(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    monkeypatch.setattr(boot_warmup, "_GATE_TIMEOUT_SECONDS", 0.2)
    ran = threading.Event()
    boot_warmup.defer("later", ran.set, priority=1)
    assert ran.wait(1.5)


def test_exception_in_one_job_does_not_stop_the_rest(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    ran = []
    boot_warmup.defer("bad", lambda: 1 / 0, priority=1)
    boot_warmup.defer("good", lambda: ran.append("good"), priority=2)
    boot_warmup.mark_inventory_ready()
    assert boot_warmup.join(3)
    assert ran == ["good"]


def test_job_deferred_after_gate_open_still_staggers(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    boot_warmup.mark_inventory_ready()
    t0 = time.monotonic()
    seen = []
    boot_warmup.defer("late", lambda: seen.append(time.monotonic() - t0), priority=2)
    assert boot_warmup.join(2)
    assert seen[0] >= 0.09


def test_jitter_is_bounded(monkeypatch):
    monkeypatch.setattr(boot_warmup, "_STEP_SECONDS", 15.0)
    monkeypatch.setattr(boot_warmup, "_JITTER_SECONDS", 10.0)
    for _ in range(200):
        d = boot_warmup.delay_for(2)
        assert 30.0 <= d <= 40.0
    assert boot_warmup.delay_for(0) == 0.0


def test_inventory_first_refresh_runs_before_other_warmups(monkeypatch):
    """Collector boot: the first FMG call is the ADOM list, and later jobs wait for it."""
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    synth = SyntheticFMG(adoms=2, devices=10)
    client = FMGClient(host="fmg.example", token="t")
    client._post = synth.post
    monkeypatch.setattr(inventory_cache, "_make_client", lambda: client)

    class FakeSched:
        def add_job(self, **kw):
            pass

        def start(self):
            pass

    monkeypatch.setattr(inventory_cache, "_make_scheduler", lambda: FakeSched())
    calls_when_other_started = []
    boot_warmup.defer(
        "other",
        lambda: calls_when_other_started.append(sum(synth.calls.values())),
        priority=1,
    )
    assert inventory_cache.init_scheduler(object()) is True
    assert boot_warmup.join(5)
    assert next(iter(synth.calls)).startswith("get /dvmdb/adom")  # first FMG call
    assert (
        calls_when_other_started and calls_when_other_started[0] > 0
    )  # inventory done first


def test_web_boot_makes_zero_fmg_calls(monkeypatch):
    """A web worker (no schedulers) never talks to FortiManager at import/boot or when
    serving the cached dashboard summary."""
    import time as _t
    from unittest.mock import patch

    calls = []

    def boom(self, body, timeout=None):
        calls.append(body)
        raise AssertionError("web boot must not call FMG")

    monkeypatch.setattr(FMGClient, "_post", boom)
    from app import create_app

    app = create_app()
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["_csrf_token"] = "t"
        sess["login_at"] = int(_t.time())
    with patch(
        "app.auth._load_users",
        return_value={"admin": {"password_hash": "x", "role": "admin"}},
    ):
        assert c.get("/api/summary").status_code == 200
    assert calls == []
