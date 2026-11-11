"""scripts/verify_snapshot_load.py: small synthetic run completes with no errors."""

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_snapshot_load.py"


def test_snapshot_load_script_small_run_passes():
    spec = importlib.util.spec_from_file_location("verify_snapshot_load", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verify_snapshot_load"] = mod
    spec.loader.exec_module(mod)
    result = mod.run(devices=12, adoms=2, readers=1, read_seconds=0.5)
    assert result["errors"] == []
    assert result["reads"] > 0 and result["db_bytes"] > 0
    assert result["review"]["devices"] > 0 and result["review"]["proxy_reads"] == 0
