"""scripts/fmg_spike.py: read-only measurements against a (lab) FortiManager."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "fmg_spike.py"


@pytest.fixture(scope="module")
def spike():
    spec = importlib.util.spec_from_file_location("fmg_spike", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fmg_spike"] = mod
    spec.loader.exec_module(mod)
    return mod


def _rig():
    fmg = SyntheticFMG(devices=12, adoms=1, packages_per_adom=2, rules_per_package=5)
    c = FMGClient(host="fmg.invalid", token="t")
    c._post = fmg.post
    adom = next(
        a["name"] for a in c.get_adoms() if not a["name"].lower().startswith("forti")
    )
    devices = [d["name"] for d in c.get_devices(adom)]
    return fmg, c, adom, devices


def test_summarize_sizes_relative(spike):
    out = spike.summarize_sizes({"full": b"x" * 1000, "trim": b"x" * 250})
    assert out["full"] == {"bytes": 1000, "relative": 1.0}
    assert out["trim"] == {"bytes": 250, "relative": 0.25}


def test_percentiles_known_samples(spike):
    out = spike.percentiles([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0])
    assert out["p50"] == pytest.approx(5.5)
    assert out["p95"] == 10.0
    assert out["max"] == 10.0
    assert spike.percentiles([]) == {"p50": 0.0, "p95": 0.0, "max": 0.0}


def test_diff_keys(spike):
    assert spike.diff_keys({"a": 1, "b": 2}, {"b": 3, "c": 4}) == {
        "only_a": ["a"],
        "only_b": ["c"],
    }


def _assert_read_only(fmg):
    for key in fmg.calls:
        assert key.startswith("get ") or key == "exec /sys/proxy/json", key


def test_devices_fields_reports_size_variants(spike):
    fmg, c, adom, _ = _rig()
    out = spike.run_devices_fields(c, adom)
    assert set(out["sizes"]) == {"full", "fields", "loadsub0", "fields+loadsub0"}
    assert all("vdom_present" in v for v in out["variants"].values())
    _assert_read_only(fmg)


def test_proxy_multi_reports_shape_and_unreachable_target(spike):
    fmg, c, adom, devices = _rig()
    out = spike.run_proxy_multi(c, adom, devices, max_targets=5)
    assert out["single"]["targets_returned"] == 1
    assert "multi" in out and "with_unreachable" in out
    # No real device names may leak into the (committable) report.
    assert not any(d in json.dumps(out) for d in devices)
    _assert_read_only(fmg)


def test_pkg_marker_lists_candidate_fields(spike):
    fmg, c, adom, _ = _rig()
    out = spike.run_pkg_marker(c, adom)
    assert "package_entry_keys" in out and "package_object_keys" in out
    assert "revision_entry_keys" in out
    assert isinstance(out["candidate_marker_fields"], list)
    _assert_read_only(fmg)


def test_latency_reports_sequential_and_concurrent(spike):
    fmg, c, adom, devices = _rig()
    out = spike.run_latency(c, adom, devices, n=6, workers=3)
    assert out["sequential"]["count"] == 6
    assert out["concurrent"]["count"] == 6
    assert set(out["sequential"]["seconds"]) == {"p50", "p95", "max"}
    _assert_read_only(fmg)
