"""scripts/verify_job_queue.py small run (Phase 6)."""

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_job_queue.py"


def test_job_queue_script_small_run_passes():
    spec = importlib.util.spec_from_file_location("verify_job_queue", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verify_job_queue"] = mod
    spec.loader.exec_module(mod)
    r = mod.run(devices=12, adoms=2, cap=2, jobs_per_adom=2)
    assert r["errors"] == [] and r["jobs"] == 4 and 1 <= r["peak_running"] <= 2
