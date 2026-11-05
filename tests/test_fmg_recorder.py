import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import json

import pytest

from app.fmg_recorder import Recorder, ReplayMiss, ReplayTransport, Scrubber


def _roundtrip(obj, **kw):
    return json.loads(json.dumps(Scrubber(**kw).scrub(obj)))


# ---- Scrubber -------------------------------------------------------------


def test_secret_keys_are_redacted_whatever_their_depth():
    out = _roundtrip(
        {
            "session": "abc",
            "data": {"passwd": "hunter2", "cloud-authentication-access-key": "xyz"},
            "list": [{"token": "t0k", "name": "keepme"}],
        }
    )
    assert out["session"] == "<redacted>"
    assert out["data"]["passwd"] == "<redacted>"
    assert out["data"]["cloud-authentication-access-key"] == "<redacted>"
    assert out["list"][0]["token"] == "<redacted>"
    assert out["list"][0]["name"] == "keepme"


def test_ipv4_is_replaced_consistently_but_netmasks_survive():
    out = _roundtrip(
        {
            "a": "10.1.2.3",
            "b": "10.1.2.3",
            "c": "10.9.9.9",
            "mask": "255.255.255.0",
            "any": "0.0.0.0",
            "embedded": "set server 10.1.2.3 via 10.9.9.9",
        }
    )
    assert out["a"] == out["b"] != "10.1.2.3"
    assert out["c"] != out["a"]
    assert out["mask"] == "255.255.255.0"
    assert out["any"] == "0.0.0.0"
    assert out["embedded"] == f"set server {out['a']} via {out['c']}"


def test_serial_numbers_are_replaced_consistently():
    out = _roundtrip(
        {
            "sn": "FGT60FTK21091234",
            "also": "x FGT60FTK21091234 y",
            "o": "FMG-VM0A17001234",
        }
    )
    assert "FGT60FTK21091234" not in json.dumps(out)
    assert out["also"] == f"x {out['sn']} y"
    assert "FMG-VM0A17001234" not in json.dumps(out)


def test_emails_are_replaced():
    assert "@corp.com" not in json.dumps(_roundtrip({"email": "alan@corp.com"}))


def test_literals_replace_in_values_keys_and_urls_longest_first():
    out = _roundtrip(
        {
            "url": "/pm/config/adom/Corp West/pkg/Corp West HQ",
            "Corp West": 1,
        },
        literals={"Corp West": "ADOM1", "Corp West HQ": "PKG1"},
    )
    assert out["url"] == "/pm/config/adom/ADOM1/pkg/PKG1"
    assert "ADOM1" in out  # dict keys too


def test_versions_and_plain_numbers_are_untouched():
    src = {"Version": "v8.0.2-build0198 261006 (GA.F)", "os_ver": 8, "mr": 0}
    assert _roundtrip(src) == src


def test_scrub_does_not_mutate_its_input():
    src = {"session": "abc", "ip": "10.1.1.1"}
    Scrubber().scrub(src)
    assert src == {"session": "abc", "ip": "10.1.1.1"}


# ---- Recorder -> ReplayTransport ----------------------------------------


def _body(method, url, rid=1, **extra):
    return {"id": rid, "method": method, "params": [{"url": url, **extra}]}


def _resp(data, rid=1, code=0):
    return {
        "id": rid,
        "result": [{"status": {"code": code, "message": "OK"}, "data": data}],
    }


def test_recorder_writes_scrubbed_exchanges_and_replay_serves_them(tmp_path):
    path = tmp_path / "ex.json"
    rec = Recorder(path, scrubber=Scrubber())
    rec.record(_body("get", "/sys/status", 5), _resp({"Version": "v8.0.2"}, 5))
    rec.record(
        {**_body("exec", "/sys/login/user", 6), "session": "SECRET"},
        {**_resp({}, 6), "session": "SECRET2"},
    )

    text = path.read_text()
    assert "SECRET" not in text

    replay = ReplayTransport(path)
    out = replay.post(_body("get", "/sys/status", 99))
    assert out["result"][0]["data"] == {"Version": "v8.0.2"}
    assert out["id"] == 99  # request id echoed, not the recorded one


def test_replay_ignores_session_and_id_but_not_url_or_params(tmp_path):
    path = tmp_path / "ex.json"
    rec = Recorder(path, scrubber=Scrubber())
    rec.record(
        _body("get", "/dvmdb/adom/a/device", filter=["name", "==", "x"]), _resp([1])
    )
    replay = ReplayTransport(path)

    body = _body("get", "/dvmdb/adom/a/device", 7, filter=["name", "==", "x"])
    body["session"] = "whatever"
    assert replay.post(body)["result"][0]["data"] == [1]

    with pytest.raises(ReplayMiss):
        replay.post(_body("get", "/dvmdb/adom/a/device", filter=["name", "==", "y"]))
    with pytest.raises(ReplayMiss):
        replay.post(_body("get", "/dvmdb/adom/b/device"))


def test_repeated_requests_replay_in_order_and_last_one_repeats(tmp_path):
    # Task polling: same request, different answers over time.
    path = tmp_path / "ex.json"
    rec = Recorder(path, scrubber=Scrubber())
    for pct in (0, 50, 100):
        rec.record(_body("get", "/task/task/9"), _resp({"percent": pct}))
    replay = ReplayTransport(path)
    seen = [
        replay.post(_body("get", "/task/task/9"))["result"][0]["data"]["percent"]
        for _ in range(5)
    ]
    assert seen == [0, 50, 100, 100, 100]


def test_replay_miss_message_names_the_request(tmp_path):
    path = tmp_path / "ex.json"
    Recorder(path, scrubber=Scrubber())  # empty
    with pytest.raises(ReplayMiss, match="/nope"):
        ReplayTransport(path).post(_body("get", "/nope"))


def test_recorder_loads_existing_file_and_appends(tmp_path):
    path = tmp_path / "ex.json"
    Recorder(path, scrubber=Scrubber()).record(_body("get", "/a"), _resp(1))
    Recorder(path, scrubber=Scrubber()).record(_body("get", "/b"), _resp(2))
    assert len(json.loads(path.read_text())["exchanges"]) == 2


# ---- FMGClient integration --------------------------------------------


def test_client_records_every_exchange_when_fmg_record_file_is_set(
    tmp_path, monkeypatch
):
    from unittest.mock import MagicMock

    from app.fmg_client import FMGClient

    path = tmp_path / "rec.json"
    monkeypatch.setenv("FMG_RECORD_FILE", str(path))
    c = FMGClient(host="fmg.example.com", token="tok")
    fake = MagicMock()
    fake.json.return_value = _resp({"Version": "v8.0.2-build0198 261006 (GA.F)"})
    c._http.post = MagicMock(return_value=fake)

    assert c.get_system_status()["Version"].startswith("v8.0.2")
    ex = json.loads(path.read_text())["exchanges"]
    assert ex[0]["request"]["method"] == "get"
    assert "tok" not in path.read_text()


def test_client_does_not_record_by_default(tmp_path, monkeypatch):
    from app.fmg_client import FMGClient

    monkeypatch.delenv("FMG_RECORD_FILE", raising=False)
    assert FMGClient(host="h", token="t")._recorder is None


def test_replayed_client_runs_real_methods_offline(tmp_path):
    from app.fmg_client import FMGClient

    path = tmp_path / "ex.json"
    Recorder(path, scrubber=Scrubber()).record(
        _body("get", "/sys/status"),
        _resp({"Version": "v8.0.2-build0198 261006 (GA.F)"}),
    )
    c = FMGClient(host="h", token="t")
    c._post = ReplayTransport(path).post
    assert c.version.train == "8.0"


def test_replay_falls_back_to_url_when_params_hold_a_volatile_value(tmp_path):
    # e.g. the audit-log query carries a time window computed from "now".
    path = tmp_path / "ex.json"
    rec = Recorder(path, scrubber=Scrubber())
    rec.record(
        _body("get", "/sys/audit-log", filter=["ts", ">", "2026-11-01"]), _resp([7])
    )
    replay = ReplayTransport(path, loose_urls=("/sys/audit-log",))
    later = _body("get", "/sys/audit-log", filter=["ts", ">", "2026-11-05"])
    assert replay.post(later)["result"][0]["data"] == [7]


def test_url_fallback_applies_only_to_listed_urls(tmp_path):
    path = tmp_path / "ex.json"
    Recorder(path, scrubber=Scrubber()).record(_body("get", "/x", n=1), _resp("one"))
    with pytest.raises(ReplayMiss):
        ReplayTransport(path, loose_urls=("/other",)).post(_body("get", "/x", n=2))


def test_exact_params_win_over_the_url_fallback(tmp_path):
    path = tmp_path / "ex.json"
    rec = Recorder(path, scrubber=Scrubber())
    rec.record(_body("get", "/x", n=1), _resp("one"))
    rec.record(_body("get", "/x", n=2), _resp("two"))
    replay = ReplayTransport(path, loose_urls=("/x",))
    assert replay.post(_body("get", "/x", n=2))["result"][0]["data"] == "two"


def test_admin_account_names_inside_cli_text_are_replaced_consistently():
    cli = (
        '=== Preview result ===\nconfig system admin\n    edit "jsmith"\n'
        '        set gui-x 1\n    next\n    edit "admin"\n    next\nend\n'
        'config firewall policy\n    edit "keepme"\n    next\nend\n'
    )
    s = Scrubber()
    out = s.scrub({"a": cli, "b": 'login by "jsmith"'})
    assert "jsmith" not in json.dumps(out)
    assert 'edit "admin"' in out["a"]  # the stock account is not identifying
    assert 'edit "keepme"' in out["a"]  # only the admin block is touched
    assert out["b"].count("admin-user-1") == 1  # same mapping everywhere
