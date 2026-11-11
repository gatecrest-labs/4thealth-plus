"""Size and concurrency check for the device snapshot store, no FortiManager needed.

Captures a synthetic fleet (default 1,000 devices) through the real collector
code path (``app.snapshot_cache.capture_device``) into a SQLite database while
separate reader processes keep reading device snapshots the way web workers do,
then reports DB size, write time, per-device read latency percentiles, any error,
and how long a bulk Device Review of one ADOM takes from the store (with no
FortiManager call at all).

It runs on any machine. Run it once on the production RHEL VM as the app user,
next to ``scripts/verify_shared_store.py`` and ``scripts/verify_policy_store_load.py``,
to prove the disk and the WAL sharing hold up at 1,000-device scale::

    sudo -u 4thealth /opt/4thealth/.venv/bin/python scripts/verify_snapshot_load.py \\
        --db /opt/4thealth/snapshot-load-proof.db --readers 2

Exit status 0 only if no reader or writer reported an error.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SECRET_KEY", "verify-snapshot-load")

_KEYS = {"interfaces", "ntp", "admins", "system_global", "ipsec_phase1"}


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def _reader(stop_file: str, adoms: list[str]) -> int:
    """Child process: read device snapshots like a web worker until *stop_file* appears."""
    from app import snapshot_store

    latencies: list[float] = []
    errors: list[str] = []
    reads = 0
    rng = random.Random()
    deadline = time.time() + 600
    devices: dict[str, list[str]] = {}
    while not os.path.exists(stop_file) and time.time() < deadline:
        try:
            if not devices:
                devices = {
                    a: [r["device"] for r in snapshot_store.device_meta_rows(a)]
                    for a in adoms
                }
                devices = {a: d for a, d in devices.items() if d}
                if not devices:
                    time.sleep(0.02)
                    continue
            adom = rng.choice(sorted(devices))
            device = rng.choice(devices[adom])
            started = time.perf_counter()
            got = snapshot_store.get_keys(adom, device, _KEYS)
            latencies.append((time.perf_counter() - started) * 1000.0)
            reads += 1
            for key, row in got.items():
                if row["value"] is None:
                    errors.append(f"{adom}/{device}/{key}: empty value")
        except Exception as exc:  # any reader failure is a finding
            errors.append(repr(exc)[:200])
            time.sleep(0.05)
    sample = latencies if len(latencies) <= 5000 else rng.sample(latencies, 5000)
    print(json.dumps({"reads": reads, "latencies_ms": sample, "errors": errors[:20]}))
    return 0


def run(
    devices: int = 1000,
    adoms: int = 5,
    readers: int = 2,
    db_path: Path | None = None,
    read_seconds: float = 3.0,
) -> dict:
    """Run the check and return its measurements (see module docstring)."""
    from app import audit_data, snapshot_cache
    from app.config import Config
    from app.fmg_client import FMGClient
    from app.routes import audit_review_routes
    from app.synthetic_fmg import SyntheticFMG

    tmp = (
        tempfile.TemporaryDirectory(prefix="snapshot-load-")
        if db_path is None
        else None
    )
    db = Path(db_path) if db_path else Path(tmp.name) / "snapshot_load.db"
    stop_file = str(db.with_suffix(".stop"))
    Path(stop_file).unlink(missing_ok=True)
    previous_db = os.environ.get("COLLECTOR_DB_PATH")
    os.environ["COLLECTOR_DB_PATH"] = str(db)
    errors: list[str] = []
    procs: list[subprocess.Popen] = []
    write_seconds = 0.0
    review: dict = {}
    saved = (Config.AUDIT_SNAPSHOTS, Config.INVENTORY_CACHE)
    saved_make_client = None
    try:
        synth = SyntheticFMG(adoms=adoms, devices=devices, seed=1)
        client = FMGClient(host="synthetic-fmg", token="x")
        client._post = synth.post
        Config.AUDIT_SNAPSHOTS, Config.INVENTORY_CACHE = True, False
        fleet = snapshot_cache._fleet(client)
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        for _ in range(readers):
            procs.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "--reader",
                        "--stop-file",
                        stop_file,
                        "--adom-list",
                        json.dumps(sorted(fleet)),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )
            )
        t0 = time.perf_counter()
        failed = 0
        for adom, names in fleet.items():
            for name in names:
                out = snapshot_cache.capture_device(client, adom, name)
                failed += len(out.get("failed_keys", []))
        write_seconds = time.perf_counter() - t0
        if failed:
            errors.append(f"writer: {failed} data keys failed to capture")
        time.sleep(read_seconds)  # readers keep reading the finished store

        first = min(fleet)

        class _NoFMG(FMGClient):
            def __init__(self):
                super().__init__(host="synthetic-fmg", token="x")
                self.proxy_reads = 0

                def post(body, timeout=None):
                    if body["params"][0].get("url") == "/sys/proxy/json":
                        self.proxy_reads += 1
                        raise AssertionError("live device read during snapshot review")
                    return synth.post(body, timeout)

                self._post = post

        guard = _NoFMG()
        saved_make_client = audit_review_routes.make_client
        audit_review_routes.make_client = lambda: guard
        audit_data.reset_counters()
        b0 = time.perf_counter()
        results = audit_review_routes.bulk_device_review_adom(first, [], {})
        review = {
            "adom": first,
            "devices": len(results),
            "rows": sum(len(r["rows"]) for r in results),
            "seconds": round(time.perf_counter() - b0, 2),
            "proxy_reads": guard.proxy_reads,
            "errors": sum(1 for r in results if r.get("error")),
            "audit_counters": audit_data.counters(),
        }
        if guard.proxy_reads or review["errors"]:
            errors.append(
                f"review: {review['proxy_reads']} live reads, {review['errors']} errors"
            )
    except Exception as exc:
        errors.append(f"writer: {exc!r}")
    finally:
        Config.AUDIT_SNAPSHOTS, Config.INVENTORY_CACHE = saved
        if saved_make_client is not None:
            audit_review_routes.make_client = saved_make_client
        Path(stop_file).write_text("stop")
        reads = 0
        latencies: list[float] = []
        for proc in procs:
            try:
                out, err = proc.communicate(timeout=60)
                data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
                reads += data.get("reads", 0)
                latencies += data.get("latencies_ms", [])
                errors += [f"reader: {e}" for e in data.get("errors", [])]
                if proc.returncode not in (0, None):
                    errors.append(f"reader exited {proc.returncode}: {err[-200:]}")
            except Exception as exc:
                proc.kill()
                errors.append(f"reader: {exc!r}")
        Path(stop_file).unlink(missing_ok=True)
        if previous_db is None:
            os.environ.pop("COLLECTOR_DB_PATH", None)
        else:
            os.environ["COLLECTOR_DB_PATH"] = previous_db

    db_bytes = sum(
        p.stat().st_size for p in db.parent.glob(db.name + "*") if p.is_file()
    )
    result = {
        "devices": devices,
        "adoms": adoms,
        "readers": readers,
        "write_seconds": round(write_seconds, 2),
        "db_bytes": db_bytes,
        "reads": reads,
        "read_p50_ms": round(_percentile(latencies, 0.50), 3),
        "read_p95_ms": round(_percentile(latencies, 0.95), 3),
        "review": review,
        "errors": errors,
    }
    if tmp is not None:
        tmp.cleanup()
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--reader", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--stop-file", default="", help=argparse.SUPPRESS)
    ap.add_argument("--adom-list", default="[]", help=argparse.SUPPRESS)
    ap.add_argument(
        "--db", type=Path, default=None, help="database file (default: a temp file)"
    )
    ap.add_argument("--devices", type=int, default=1000)
    ap.add_argument("--adoms", type=int, default=5)
    ap.add_argument("--readers", type=int, default=2)
    ap.add_argument("--read-seconds", type=float, default=3.0)
    ap.add_argument(
        "--json", type=Path, default=None, help="also write the result here"
    )
    args = ap.parse_args(argv)
    if args.reader:
        return _reader(args.stop_file, json.loads(args.adom_list))
    result = run(args.devices, args.adoms, args.readers, args.db, args.read_seconds)
    print(
        f"{result['devices']} devices: capture {result['write_seconds']}s, "
        f"db {result['db_bytes'] / 1e6:.1f} MB"
    )
    print(
        f"{result['readers']} readers: {result['reads']} reads, "
        f"p50 {result['read_p50_ms']} ms, p95 {result['read_p95_ms']} ms"
    )
    rv = result["review"]
    if rv:
        print(
            f"Device Review of {rv['adom']} ({rv['devices']} devices, {rv['rows']} rows): "
            f"{rv['seconds']}s, {rv['proxy_reads']} live reads"
        )
    if result["errors"]:
        print(f"ERRORS ({len(result['errors'])}):")
        for e in result["errors"][:10]:
            print(f"  {e}")
    else:
        print("OK: no errors")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
