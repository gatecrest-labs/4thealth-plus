"""scripts/measure_fmg_baseline.py: today's FMG call volume on a synthetic fleet."""

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "measure_fmg_baseline.py"
_ROOT = _SCRIPT.parent.parent

SWEEPS = {
    "summary_job",
    "versions_cache",
    "map_cache",
    "adom_cache",
    "pending_status_cache",
    "exec_device_sweep",
    "exec_hygiene_sweep",
    "license_status_cache",
    "device_backup_cache",
}

SMALL = {
    "adoms": 2,
    "packages_per_adom": 2,
    "rules_per_package": 10,
    "address_objects": 40,
}


@pytest.fixture(scope="module")
def baseline():
    spec = importlib.util.spec_from_file_location("measure_fmg_baseline", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["measure_fmg_baseline"] = mod
    spec.loader.exec_module(mod)
    return mod.measure(devices=20, **SMALL)


def test_measure_small_rig_reports_each_sweep(baseline):
    assert baseline["devices"] == 20
    assert set(baseline["sweeps"]) == SWEEPS
    for name, sweep in baseline["sweeps"].items():
        assert sweep["calls"] > 0, name
        assert sweep["interval_min"] > 0, name
    assert baseline["calls_per_hour"] > 0


def test_inventory_is_downloaded_repeatedly(baseline):
    """Finding C2: several sweeps each re-download the same device list."""
    assert baseline["inventory_downloads_per_cycle"] >= 5


def test_measure_does_not_write_to_fmg(baseline):
    for sweep in baseline["sweeps"].values():
        for key in sweep["by_url"]:
            assert key.startswith("get ") or key == "exec /sys/proxy/json", key


def test_measure_does_not_touch_project_root_state():
    """Sweeps persist to project-root JSON files; the script must redirect them."""
    spec = importlib.util.spec_from_file_location("measure_fmg_baseline2", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    files = [
        _ROOT / n
        for n in ("license_status.json", "device_backup.json", "summary_history.json")
    ]
    before = {f: (f.exists(), f.stat().st_mtime if f.exists() else None) for f in files}
    mod.measure(devices=6, **SMALL)
    after = {f: (f.exists(), f.stat().st_mtime if f.exists() else None) for f in files}
    assert before == after
