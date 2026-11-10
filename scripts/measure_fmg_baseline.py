"""Measure how many FortiManager calls the app's background sweeps make today.

Runs each existing sweep once against a ``SyntheticFMG`` fleet and extrapolates
calls/hour from each sweep's real schedule interval. The number it prints is
the baseline later scale phases must beat by 10x (design doc, section 7a).

Nothing here talks to a real FortiManager and nothing persistent is touched:
``FMGClient._post`` is replaced by the synthetic transport, the shared store
and the project-root JSON files the sweeps write are redirected to a temp dir.

    uv run python scripts/measure_fmg_baseline.py --devices 1000 \\
        --out docs/superpowers/measurements/2026-11-baseline-1000.json
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

INVENTORY_KEY = "get /dvmdb/adom/{adom}/device"


def _sweeps():
    """(name, module, function, interval_minutes) for every sweep measured.

    Intervals mirror each scheduler's own default/env so the extrapolation
    matches what a deployment actually runs.
    """
    from app import (
        adom_cache,
        device_backup_cache,
        executive_summary_cache,
        license_status_cache,
        map_cache,
        pending_status_cache,
        summary_job,
        versions_cache,
    )

    env = os.environ.get
    return [
        ("summary_job", summary_job, "_run_job", 24 * 60),
        (
            "versions_cache",
            versions_cache,
            "_run_job",
            int(env("VERSIONS_CACHE_INTERVAL_MIN", "30")),
        ),
        (
            "map_cache",
            map_cache,
            "_run_job",
            int(env("MAP_CACHE_INTERVAL_HOURS", "24")) * 60,
        ),
        ("adom_cache", adom_cache, "_run_refresh", 30),
        (
            "pending_status_cache",
            pending_status_cache,
            "_run_refresh",
            pending_status_cache._REFRESH_MINUTES,
        ),
        (
            "exec_device_sweep",
            executive_summary_cache,
            "_run_device_sweep",
            int(env("EXEC_SUMMARY_REFRESH_MINUTES", "15")),
        ),
        (
            "exec_hygiene_sweep",
            executive_summary_cache,
            "_run_hygiene_sweep",
            int(env("EXEC_SUMMARY_HYGIENE_REFRESH_MINUTES", "60")),
        ),
        ("license_status_cache", license_status_cache, "_run_sweep", 24 * 60),
        ("device_backup_cache", device_backup_cache, "_run_sweep", 24 * 60),
    ]


def measure(
    devices: int = 1000, latency_ms: tuple[float, float] = (0.0, 0.0), **synth_kwargs
) -> dict:
    """Run each sweep once on a synthetic fleet and report FMG call volume.

    Returns ``{"devices", "adoms", "sweeps": {name: {"calls", "by_url",
    "interval_min", "calls_per_hour", "seconds", "error"?}}, "calls_per_hour",
    "inventory_downloads_per_cycle"}``. ``synth_kwargs`` are passed to
    ``SyntheticFMG`` (adoms, packages_per_adom, rules_per_package, ...).
    """
    from app import (
        create_app,
        device_backup_cache,
        license_status_cache,
        summary_history,
    )
    from app.config import Config
    from app.fmg_client import FMGClient
    from app.synthetic_fmg import SyntheticFMG

    synth = SyntheticFMG(devices=devices, latency_ms=latency_ms, **synth_kwargs)

    def fake_post(self, body, timeout=None):
        return synth.post(body, timeout)

    results: dict[str, dict] = {}
    with (
        tempfile.TemporaryDirectory(prefix="fmg-baseline-") as tmp,
        contextlib.ExitStack() as stack,
    ):
        tmp_path = Path(tmp)
        stack.enter_context(
            patch.dict(os.environ, {"COLLECTOR_DB_PATH": str(tmp_path / "state.db")})
        )
        stack.enter_context(patch.object(FMGClient, "_post", fake_post))
        stack.enter_context(patch.object(Config, "FMG_PRIMARY_HOST", "synthetic-fmg"))
        stack.enter_context(patch.object(Config, "FMG_API_TOKEN", "synthetic"))
        stack.enter_context(
            patch.object(license_status_cache, "_STORE_PATH", tmp_path / "license.json")
        )
        stack.enter_context(
            patch.object(device_backup_cache, "_STORE_PATH", tmp_path / "backup.json")
        )
        stack.enter_context(
            patch.object(summary_history, "_HISTORY_PATH", tmp_path / "history.json")
        )

        app = create_app(test_config={"TESTING": True})
        with app.app_context():
            for name, module, func, interval_min in _sweeps():
                before = Counter(synth.calls)
                started = time.monotonic()
                error = None
                try:
                    getattr(module, func)(app)
                except Exception as exc:  # a failing sweep still made calls
                    error = repr(exc)
                by_url = dict(Counter(synth.calls) - before)
                calls = sum(by_url.values())
                entry = {
                    "calls": calls,
                    "by_url": by_url,
                    "interval_min": interval_min,
                    "calls_per_hour": calls * 60.0 / interval_min,
                    "seconds": round(time.monotonic() - started, 2),
                }
                if error:
                    entry["error"] = error
                results[name] = entry

    inventory = sum(s["by_url"].get(INVENTORY_KEY, 0) for s in results.values())
    adoms = max(synth.adom_count, 1)
    return {
        "devices": devices,
        "adoms": synth.adom_count,
        "sweeps": results,
        "calls_per_hour": sum(s["calls_per_hour"] for s in results.values()),
        "inventory_downloads_per_cycle": inventory // adoms,
        "unsupported": dict(synth.unsupported),
        "proxy_calls": dict(synth.proxy_calls),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--devices", type=int, default=1000)
    ap.add_argument("--latency-ms", type=float, nargs=2, default=(0.0, 0.0))
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    result = measure(args.devices, tuple(args.latency_ms))
    for name, s in result["sweeps"].items():
        flag = f"  ERROR {s['error']}" if "error" in s else ""
        print(
            f"{name:24s} {s['calls']:>7d} calls  every {s['interval_min']:>5d} min"
            f"  = {s['calls_per_hour']:>9.1f}/h  ({s['seconds']}s){flag}"
        )
    print(f"TOTAL calls/hour: {result['calls_per_hour']:.1f}")
    print(f"inventory downloads per cycle: {result['inventory_downloads_per_cycle']}")
    if result["unsupported"]:
        print(f"UNSUPPORTED by synthetic FMG: {result['unsupported']}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True))
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
