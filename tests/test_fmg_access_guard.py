"""F1 guards: password-auth warning, no HTTP bypass of _post, burst respects the cap."""

import logging
import re
import threading
from pathlib import Path

from app import fmg_access
from app.config import Config

APP_DIR = Path(__file__).resolve().parent.parent / "app"
FLAGS = ("INVENTORY_CACHE", "POLICY_STORE", "AUDIT_SNAPSHOTS", "JOB_QUEUE")


def _auth(monkeypatch, token, user, flags_on):
    monkeypatch.setattr(Config, "FMG_API_TOKEN", token)
    monkeypatch.setattr(Config, "FMG_USERNAME", user)
    for f in FLAGS:
        monkeypatch.setattr(Config, f, f in flags_on)


def test_warns_for_password_auth_with_layer_on(monkeypatch, caplog):
    _auth(monkeypatch, "", "api", {"INVENTORY_CACHE"})
    with caplog.at_level(logging.WARNING):
        assert fmg_access.warn_if_password_auth(logging.getLogger("t")) is True
    assert "password" in caplog.text.lower()


def test_silent_for_token_auth(monkeypatch, caplog):
    _auth(monkeypatch, "tok", "api", {"INVENTORY_CACHE"})
    with caplog.at_level(logging.WARNING):
        assert fmg_access.warn_if_password_auth(logging.getLogger("t")) is False
    assert caplog.text == ""


def test_silent_when_no_layer_flag_on(monkeypatch, caplog):
    _auth(monkeypatch, "", "api", set())
    with caplog.at_level(logging.WARNING):
        assert fmg_access.warn_if_password_auth(logging.getLogger("t")) is False
    assert caplog.text == ""


def test_no_direct_http_post_outside_post():
    """Every FMG call must go through FMGClient._post (metrics, cap, retries)."""
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        text = path.read_text()
        if re.search(r"\._http\.post\(|\.session\.post\(", text):
            offenders.append(path.name)
    # fmg_client.py holds the one legitimate call, inside _post.
    assert offenders == ["fmg_client.py"]
    text = (APP_DIR / "fmg_client.py").read_text()
    assert len(re.findall(r"\._http\.post\(", text)) == 1


def test_burst_against_synthetic_fmg_respects_cap(monkeypatch):
    from app.fmg_client import FMGClient
    from app.synthetic_fmg import SyntheticFMG

    fmg_access.reset()
    monkeypatch.setattr(Config, "FMG_MAX_INFLIGHT", 4)
    synth = SyntheticFMG(adoms=2, devices=50, latency_ms=(2, 4))

    class Session:
        def post(self, url, json=None, **kw):
            data = synth.post(json)

            class R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self_inner):
                    return data

            return R()

    clients = []
    for _ in range(200):
        c = FMGClient(host="h", token="t")
        c._http = Session()
        clients.append(c)

    def worker(c):
        c._post({"id": 1, "method": "get", "params": [{"url": "/dvmdb/adom"}]})

    threads = [threading.Thread(target=worker, args=(c,)) for c in clients]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert synth.total_calls == 200
    assert 1 <= fmg_access.peak_inflight() <= 4
