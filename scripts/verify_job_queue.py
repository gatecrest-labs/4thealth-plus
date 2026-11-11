"""Smoke check for the job queue on a synthetic fleet, no FortiManager needed.

Enqueues Device Review jobs for every ADOM of a synthetic fleet (live reads, so each
does real work), runs them through the real runner with the configured cap, and
reports latency, the peak number of jobs running at once, result sizes and any
error. Exit status 0 only if every job ended ``done`` and the cap was never exceeded.

    uv run python scripts/verify_job_queue.py --devices 1000 --adoms 5
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "verify-job-queue")


def run(
    devices: int = 1000, adoms: int = 5, cap: int = 2, jobs_per_adom: int = 2
) -> dict:
    from app import job_handlers, job_runner, job_store
    from app.config import Config
    from app.fmg_client import FMGClient
    from app.routes import audit_review_routes
    from app.synthetic_fmg import SyntheticFMG

    with tempfile.TemporaryDirectory(prefix="job-queue-") as tmp:
        previous = os.environ.get("COLLECTOR_DB_PATH")
        os.environ["COLLECTOR_DB_PATH"] = str(Path(tmp) / "jobs.db")
        saved = (
            Config.JOB_MAX_RUNNING,
            Config.AUDIT_SNAPSHOTS,
            Config.INVENTORY_CACHE,
            Config.JOB_MAX_QUEUED_PER_USER,
        )
        saved_mc = audit_review_routes.make_client
        real_run = job_handlers.run
        errors: list[str] = []
        try:
            synth = SyntheticFMG(adoms=adoms, devices=devices, seed=1)
            client = FMGClient(host="synthetic-fmg", token="x")
            client._post = synth.post
            Config.JOB_MAX_RUNNING = cap
            Config.AUDIT_SNAPSHOTS = Config.INVENTORY_CACHE = False
            Config.JOB_MAX_QUEUED_PER_USER = 1000
            job_runner._active = 0
            audit_review_routes.make_client = lambda: client
            names = [
                a["name"]
                for a in client.get_adoms()
                if not a["name"].lower().startswith("forti")
            ]
            ids = [
                job_store.enqueue(
                    "device_review",
                    "verify",
                    a,
                    job_handlers.prepare("device_review", {"adom": a})[1],
                )
                for a in names
                for _ in range(jobs_per_adom)
            ]

            peak, running, lock = 0, 0, threading.Lock()

            def tracked(*args, **kw):
                nonlocal peak, running
                with lock:
                    running += 1
                    peak = max(peak, running)
                try:
                    return real_run(*args, **kw)
                finally:
                    with lock:
                        running -= 1

            job_handlers.run = tracked
            started = time.perf_counter()
            deadline = time.time() + 600
            while time.time() < deadline:
                job_runner.tick()
                if all(
                    (job_store.get(i) or {}).get("status")
                    in ("done", "failed", "cancelled")
                    for i in ids
                ):
                    break
                time.sleep(0.02)
            seconds = time.perf_counter() - started
            sizes = []
            for i in ids:
                j = job_store.get(i)
                if j["status"] != "done":
                    errors.append(f"{i}: {j['status']} {j.get('error')}")
                else:
                    sizes.append(len(json.dumps(j["result"])))
            if peak > cap:
                errors.append(f"cap exceeded: peak {peak} > {cap}")
            return {
                "jobs": len(ids),
                "cap": cap,
                "peak_running": peak,
                "seconds": round(seconds, 2),
                "result_kb_max": round(max(sizes, default=0) / 1024, 1),
                "result_kb_total": round(sum(sizes) / 1024, 1),
                "errors": errors,
            }
        finally:
            job_handlers.run = real_run
            (
                Config.JOB_MAX_RUNNING,
                Config.AUDIT_SNAPSHOTS,
                Config.INVENTORY_CACHE,
                Config.JOB_MAX_QUEUED_PER_USER,
            ) = saved
            audit_review_routes.make_client = saved_mc
            if previous is None:
                os.environ.pop("COLLECTOR_DB_PATH", None)
            else:
                os.environ["COLLECTOR_DB_PATH"] = previous


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--devices", type=int, default=1000)
    ap.add_argument("--adoms", type=int, default=5)
    ap.add_argument("--cap", type=int, default=2)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args(argv)
    r = run(args.devices, args.adoms, args.cap)
    print(
        f"{r['jobs']} jobs, cap {r['cap']}: peak running {r['peak_running']}, "
        f"{r['seconds']}s, result max {r['result_kb_max']} KB (total {r['result_kb_total']} KB)"
    )
    print("OK: no errors" if not r["errors"] else f"ERRORS: {r['errors'][:5]}")
    if args.json:
        args.json.write_text(json.dumps(r, indent=2, sort_keys=True))
    return 1 if r["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
