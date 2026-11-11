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
    devices: int = 1000,
    latency_ms: tuple[float, float] = (0.0, 0.0),
    inventory_cache: bool = False,
    policy_store: bool = False,
    audit_snapshots: bool = False,
    **synth_kwargs,
) -> dict:
    """Run each sweep once on a synthetic fleet and report FMG call volume.

    Returns ``{"devices", "adoms", "sweeps": {name: {"calls", "by_url",
    "interval_min", "calls_per_hour", "seconds", "error"?}}, "calls_per_hour",
    "inventory_downloads_per_cycle"}``. ``synth_kwargs`` are passed to
    ``SyntheticFMG`` (adoms, packages_per_adom, rules_per_package, ...).

    With ``inventory_cache`` the ``INVENTORY_CACHE`` layer is switched on: the
    collector's inventory refresh runs first (measured as the ``inventory_cache``
    source, at its own refresh interval) and every other sweep then reads the
    store instead of FortiManager.

    With ``policy_store`` the ``POLICY_STORE`` layer is on too: the collector's
    policy refresh runs first (sources ``policy_cache_objects`` and
    ``policy_cache_packages``) and the hygiene sweep and summary then read the
    store. The packages refresh runs cold, then warm, and its calls/hour is the
    steady state ``warm x (60 / interval) + (cold - warm) / ttl_hours`` (every
    package is refetched once per TTL, the rest of the time only the package
    lists are read).
    Also reports how many devices a scheduled Config-Delta run would preview.

    With ``audit_snapshots`` (Phase 5) the whole fleet is captured once (reported
    as ``prime_calls``), then one steady-state capture batch and one revision check
    are measured (sources ``snapshot_cache`` / ``snapshot_revisions``), and a bulk
    Device Review of one ADOM is run live and from snapshots on the same fleet
    (``audit_snapshots.device_review_run_calls``).
    """
    from app import (
        create_app,
        device_backup_cache,
        inventory,
        license_status_cache,
        summary_history,
    )
    from app import (
        inventory_cache as inventory_job,
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
        # The exec-summary sweep also does live infra-target fetches; keep a
        # measurement run off the network (they are not FortiManager calls).
        stack.enter_context(patch.object(Config, "INFRA_TARGETS", []))
        stack.enter_context(patch.object(Config, "INVENTORY_CACHE", inventory_cache))
        stack.enter_context(patch.object(Config, "POLICY_STORE", policy_store))
        inventory.reset_counters()
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
            sweeps = _sweeps()
            if inventory_cache:
                sweeps = [
                    (
                        "inventory_cache",
                        inventory_job,
                        "_run_refresh",
                        Config.INVENTORY_REFRESH_SECS / 60.0,
                    ),
                    *sweeps,
                ]
            if policy_store:
                from app import policy_cache as policy_job

                sweeps = [
                    (
                        "policy_cache_objects",
                        policy_job,
                        "_run_objects",
                        float(Config.POLICY_OBJECTS_REFRESH_MINUTES),
                    ),
                    (
                        "policy_cache_packages",
                        policy_job,
                        "_run_refresh",
                        policy_job._CYCLE_SECONDS / 60.0,
                    ),
                    *sweeps,
                ]
            for name, module, func, interval_min in sweeps:
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
                if policy_store and name == "policy_cache_packages" and not error:
                    warm_before = Counter(synth.calls)
                    getattr(module, func)(app)
                    warm = sum((Counter(synth.calls) - warm_before).values())
                    ttl_h = float(Config.POLICY_PACKAGE_TTL_HOURS)
                    entry["warm_calls"] = warm
                    entry["steady_state"] = True
                    entry["calls_per_hour"] = (
                        warm * 60.0 / interval_min + max(calls - warm, 0) / ttl_h
                    )
                if error:
                    entry["error"] = error
                results[name] = entry

            config_delta = None
            if inventory_cache:
                config_delta = _config_delta_gating(synth, devices)

            audit = None
            if audit_snapshots:
                audit = _audit_snapshots(synth, results)

    downloads = sum(s["by_url"].get(INVENTORY_KEY, 0) for s in results.values())
    adoms = max(synth.adom_count, 1)
    return {
        "devices": devices,
        "adoms": synth.adom_count,
        "sweeps": results,
        "calls_per_hour": sum(s["calls_per_hour"] for s in results.values()),
        "inventory_downloads_per_cycle": downloads // adoms,
        "inventory_cache": inventory_cache,
        "policy_store": policy_store,
        "config_delta": config_delta,
        "audit_snapshots": audit,
        "inventory_counters": inventory.counters(),
        "unsupported": dict(synth.unsupported),
        "proxy_calls": dict(synth.proxy_calls),
    }


def _audit_snapshots(synth, results: dict) -> dict:
    """Prime the snapshot store, measure steady state, compare Device Review live vs snapshot."""
    from app import audit_data, snapshot_cache, snapshot_store
    from app.config import Config
    from app.fmg_client import FMGClient
    from app.routes import audit_review_routes

    client = FMGClient(host="synthetic-fmg", token="synthetic")
    fleet = snapshot_cache._fleet(client)
    total_devices = sum(len(v) for v in fleet.values())

    before = Counter(synth.calls)
    started = time.monotonic()
    for adom, names in fleet.items():
        for name in names:
            snapshot_cache.capture_device(client, adom, name)
    prime_calls = sum((Counter(synth.calls) - before).values())
    prime_seconds = round(time.monotonic() - started, 2)
    captured = sum(
        1
        for adom in fleet
        for row in snapshot_store.device_meta_rows(adom)
        if row["keys"] > 0
    )

    batch_min = float(Config.AUDIT_SNAPSHOT_BATCH_MINUTES)
    rev_min = float(Config.AUDIT_SNAPSHOT_REVISION_CHECK_MINUTES)
    for name, func, interval in (
        ("snapshot_cache", snapshot_cache.refresh_batch, batch_min),
        ("snapshot_revisions", snapshot_cache.refresh_revisions, rev_min),
    ):
        b = Counter(synth.calls)
        t = time.monotonic()
        func(client)
        by_url = dict(Counter(synth.calls) - b)
        calls = sum(by_url.values())
        results[name] = {
            "calls": calls,
            "by_url": by_url,
            "interval_min": interval,
            "calls_per_hour": calls * 60.0 / interval,
            "seconds": round(time.monotonic() - t, 2),
            "steady_state": True,
        }

    adom = next(iter(fleet), "")
    review = {}
    for label, on in (("live", False), ("snapshot", True)):
        with patch.object(Config, "AUDIT_SNAPSHOTS", on):
            b = sum(synth.proxy_calls.values())
            t = time.monotonic()
            audit_review_routes.bulk_device_review_adom(adom, [], {})
            review[label] = sum(synth.proxy_calls.values()) - b
            review[f"{label}_seconds"] = round(time.monotonic() - t, 2)
    return {
        "devices": total_devices,
        "captured_devices": captured,
        "prime_calls": prime_calls,
        "prime_seconds": prime_seconds,
        "window_days": Config.AUDIT_SNAPSHOT_WINDOW_DAYS,
        "batch_size": snapshot_cache.batch_size(total_devices),
        "review_adom": adom,
        "device_review_run_calls": review,
        "audit_counters": audit_data.counters(),
    }


def _config_delta_gating(synth, devices: int) -> dict:
    """Devices a scheduled Config-Delta run previews vs gates, from the inventory store."""
    from app import config_delta_gate, inventory_store
    from app.fmg_helpers import make_client

    previewed = gated = 0
    with make_client() as client:
        for meta in inventory_store.read_meta() or []:
            adom = meta["adom"]
            config_delta_gate.mark_full_sweep_done(
                adom
            )  # a normal (non-full-sweep) run
            rows = inventory_store.read_devices(adom) or []
            sel = config_delta_gate.select_devices(
                client, adom, [{"name": d["name"], "ip": d.get("ip", "")} for d in rows]
            )
            previewed += len(sel.preview)
            gated += len(sel.gated)
    return {"devices": devices, "previewed_per_run": previewed, "gated_per_run": gated}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--devices", type=int, default=1000)
    ap.add_argument("--latency-ms", type=float, nargs=2, default=(0.0, 0.0))
    ap.add_argument(
        "--inventory-cache",
        action="store_true",
        help="measure with the INVENTORY_CACHE layer on (Phase 2)",
    )
    ap.add_argument(
        "--policy-store",
        action="store_true",
        help="measure with POLICY_STORE on (Phase 3): hygiene steady state",
    )
    ap.add_argument(
        "--audit-snapshots",
        action="store_true",
        help="measure with AUDIT_SNAPSHOTS on (Phase 5): capture steady state + Device Review",
    )
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    result = measure(
        args.devices,
        tuple(args.latency_ms),
        inventory_cache=args.inventory_cache,
        policy_store=args.policy_store,
        audit_snapshots=args.audit_snapshots,
    )
    for name, s in result["sweeps"].items():
        flag = f"  ERROR {s['error']}" if "error" in s else ""
        print(
            f"{name:24s} {s['calls']:>7d} calls  every {s['interval_min']:>6g} min"
            f"  = {s['calls_per_hour']:>9.1f}/h  ({s['seconds']}s){flag}"
        )
    print(f"TOTAL calls/hour: {result['calls_per_hour']:.1f}")
    print(f"inventory downloads per cycle: {result['inventory_downloads_per_cycle']}")
    if result.get("config_delta"):
        cd = result["config_delta"]
        print(
            f"Config-Delta per scheduled run: {cd['previewed_per_run']} previewed, "
            f"{cd['gated_per_run']} gated of {cd['devices']}"
        )
    if result.get("audit_snapshots"):
        a = result["audit_snapshots"]
        rv = a["device_review_run_calls"]
        print(
            f"Snapshots: primed {a['captured_devices']}/{a['devices']} devices with "
            f"{a['prime_calls']} calls in {a['prime_seconds']}s; batch size {a['batch_size']}; "
            f"Device Review of {a['review_adom']}: live {rv['live']} proxy calls "
            f"({rv['live_seconds']}s), snapshot {rv['snapshot']} ({rv['snapshot_seconds']}s)"
        )
    if result["unsupported"]:
        print(f"UNSUPPORTED by synthetic FMG: {result['unsupported']}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True))
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
