"""Size and concurrency check for the policy store, no FortiManager needed.

Writes a synthetic fleet (default 5 ADOMs x 80 packages x 300 rules) through the
real collector code path (``app.policy_cache``) into a SQLite database while
separate reader processes keep reading packages the way web workers do, then
reports DB size, write time, read latency percentiles, any error, and how long
the Rule Lookup index takes to build from the store (and its Python memory peak).

It runs on any machine. Run it once on the production RHEL VM as the app user,
next to ``scripts/verify_shared_store.py``, to prove the disk and the WAL
sharing hold up at 1,000-device scale::

    sudo -u 4thealth /opt/4thealth/.venv/bin/python scripts/verify_policy_store_load.py \\
        --db /opt/4thealth/policy-load-proof.db --readers 2

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
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SECRET_KEY", "verify-policy-store-load")


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def _reader(stop_file: str) -> int:
    """Child process: read packages the way a web worker does until *stop_file* appears."""
    from app import policy_store

    latencies: list[float] = []
    errors: list[str] = []
    reads = 0
    rng = random.Random()
    deadline = time.time() + 600
    while not os.path.exists(stop_file) and time.time() < deadline:
        try:
            adoms = sorted(policy_store.known_adoms())
            if not adoms:
                time.sleep(0.02)
                continue
            adom = rng.choice(adoms)
            meta = policy_store.package_meta(adom)
            if not meta:
                time.sleep(0.02)
                continue
            pkg = rng.choice(meta)["pkg"]
            started = time.perf_counter()
            row = policy_store.get_policies(adom, pkg)
            if row is not None:
                latencies.append((time.perf_counter() - started) * 1000.0)
                reads += 1
                if len(row["policies"]) != row["policy_count"]:
                    errors.append(
                        f"{adom}/{pkg}: policy_count {row['policy_count']} != {len(row['policies'])}"
                    )
        except Exception as exc:  # any reader failure is a finding
            errors.append(repr(exc)[:200])
            time.sleep(0.05)
    sample = latencies if len(latencies) <= 5000 else rng.sample(latencies, 5000)
    print(json.dumps({"reads": reads, "latencies_ms": sample, "errors": errors[:20]}))
    return 0


def run(
    adoms: int = 5,
    packages: int = 80,
    rules: int = 300,
    readers: int = 2,
    db_path: Path | None = None,
    read_seconds: float = 3.0,
) -> dict:
    """Run the check and return its measurements (see module docstring)."""
    from app import policy_cache, policy_store, rule_lookup_cache
    from app.config import Config
    from app.fmg_client import FMGClient
    from app.synthetic_fmg import SyntheticFMG

    tmp = (
        tempfile.TemporaryDirectory(prefix="policy-load-") if db_path is None else None
    )
    db = Path(db_path) if db_path else Path(tmp.name) / "policy_load.db"
    stop_file = str(db.with_suffix(".stop"))
    Path(stop_file).unlink(missing_ok=True)
    previous_db = os.environ.get("COLLECTOR_DB_PATH")
    os.environ["COLLECTOR_DB_PATH"] = str(db)
    errors: list[str] = []
    procs: list[subprocess.Popen] = []
    try:
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
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )
            )
        synth = SyntheticFMG(
            adoms=adoms,
            devices=max(adoms, 10),
            packages_per_adom=packages,
            rules_per_package=rules,
            seed=1,
        )
        client = FMGClient(host="synthetic-fmg", token="x")
        client._post = synth.post
        saved = (Config.POLICY_STORE, Config.INVENTORY_CACHE)
        Config.POLICY_STORE, Config.INVENTORY_CACHE = True, False
        try:
            t0 = time.perf_counter()
            objects = policy_cache.refresh_objects(client)
            objects_seconds = time.perf_counter() - t0
            t1 = time.perf_counter()
            refresh = policy_cache.refresh_once(client)
            write_seconds = time.perf_counter() - t1
            errors += [f"objects: {f}" for f in objects.get("failed", [])]
            errors += [f"packages: {f}" for f in refresh.get("failed", [])]
            time.sleep(read_seconds)  # readers keep reading the finished store

            first_adom = min(policy_store.known_adoms())

            rule_lookup_cache._store.clear()
            rule_lookup_cache._building.clear()
            rule_lookup_cache.make_client = lambda: client
            calls_before = sum(synth.calls.values())
            tracemalloc.start()
            b0 = time.perf_counter()
            rule_lookup_cache.refresh_adom(first_adom)
            build_seconds = time.perf_counter() - b0
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            entry = rule_lookup_cache.get_adom(first_adom) or {}
            rule_lookup = {
                "adom": first_adom,
                "rules": len(entry.get("rules", [])),
                "build_seconds": round(build_seconds, 3),
                "peak_mb": round(peak / 1e6, 1),
                "fmg_calls": sum(synth.calls.values()) - calls_before,
                "status": entry.get("status"),
            }
        finally:
            Config.POLICY_STORE, Config.INVENTORY_CACHE = saved
    except Exception as exc:
        errors.append(f"writer: {exc!r}")
        objects_seconds = write_seconds = 0.0
        rule_lookup = {"rules": 0, "build_seconds": 0.0, "peak_mb": 0.0, "fmg_calls": 0}
    finally:
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
        "adoms": adoms,
        "packages": adoms * packages,
        "rules_per_package": rules,
        "readers": readers,
        "objects_seconds": round(objects_seconds, 2),
        "write_seconds": round(write_seconds, 2),
        "db_bytes": db_bytes,
        "reads": reads,
        "read_p50_ms": round(_percentile(latencies, 0.50), 2),
        "read_p95_ms": round(_percentile(latencies, 0.95), 2),
        "rule_lookup": rule_lookup,
        "errors": errors,
    }
    if tmp is not None:
        tmp.cleanup()
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--reader", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--stop-file", default="", help=argparse.SUPPRESS)
    ap.add_argument(
        "--db", type=Path, default=None, help="database file (default: a temp file)"
    )
    ap.add_argument("--adoms", type=int, default=5)
    ap.add_argument("--packages", type=int, default=80, help="packages per ADOM")
    ap.add_argument("--rules", type=int, default=300, help="rules per package")
    ap.add_argument("--readers", type=int, default=2)
    ap.add_argument("--read-seconds", type=float, default=3.0)
    ap.add_argument(
        "--json", type=Path, default=None, help="also write the result here"
    )
    args = ap.parse_args(argv)
    if args.reader:
        return _reader(args.stop_file)
    result = run(
        args.adoms, args.packages, args.rules, args.readers, args.db, args.read_seconds
    )
    print(
        f"{result['packages']} packages x {result['rules_per_package']} rules: "
        f"objects {result['objects_seconds']}s, packages {result['write_seconds']}s, "
        f"db {result['db_bytes'] / 1e6:.1f} MB"
    )
    print(
        f"{result['readers']} readers: {result['reads']} reads, "
        f"p50 {result['read_p50_ms']} ms, p95 {result['read_p95_ms']} ms"
    )
    rl = result["rule_lookup"]
    print(
        f"Rule Lookup index ({rl.get('rules', 0)} rules): build {rl.get('build_seconds')}s, "
        f"peak {rl.get('peak_mb')} MB Python memory, {rl.get('fmg_calls')} FMG calls"
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
