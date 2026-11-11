"""Read-only measurements against a (lab) FortiManager for the scale design.

Answers the Phase 0 questions in docs/superpowers/specs/2026-11-10-scale-1000-
fortigates-design.md. Every subcommand issues only read calls (JSON-RPC
``get`` and ``exec /sys/proxy/json`` with ``action: get``); nothing stages,
installs or writes. Reports never contain real ADOM/device names, only
counts, sizes, timings and field names -- but read a report before
committing it (the repo is public).

    uv run python scripts/fmg_spike.py devices-fields   # payload size: fields / loadsub
    uv run python scripts/fmg_spike.py proxy-multi      # can one proxy call carry many targets?
    uv run python scripts/fmg_spike.py pkg-marker       # is there a policy change marker?
    uv run python scripts/fmg_spike.py latency          # proxy latency, sequential vs concurrent

Uses the same FMG settings as the app (.env: FMG_PRIMARY_HOST, FMG_API_TOKEN).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESOURCE = "/api/v2/monitor/system/status"
DEVICE_FIELDS = [
    "name",
    "ip",
    "sn",
    "platform_str",
    "os_ver",
    "mr",
    "patch",
    "conn_status",
    "conf_status",
    "db_status",
    "ha_mode",
    "mgt_vdom",
    "vdom",
]
_MARKER_RE = re.compile(
    r"(time|modif|rev|chk|hash|oid|version|date|updated|created)", re.IGNORECASE
)


# ---- pure helpers ----------------------------------------------------------


def summarize_sizes(variants: dict[str, bytes]) -> dict[str, dict]:
    """Bytes per variant and size relative to the largest variant."""
    largest = max((len(v) for v in variants.values()), default=0) or 1
    return {
        name: {"bytes": len(blob), "relative": round(len(blob) / largest, 4)}
        for name, blob in variants.items()
    }


def percentiles(samples: list[float]) -> dict[str, float]:
    """p50 (median), p95 (nearest rank) and max of *samples*."""
    if not samples:
        return {"p50": 0.0, "p95": 0.0, "max": 0.0}
    s = sorted(samples)
    n = len(s)
    mid = n // 2
    p50 = s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2
    p95 = s[max(0, -(-95 * n // 100) - 1)]
    return {"p50": p50, "p95": p95, "max": s[-1]}


def diff_keys(a: dict, b: dict) -> dict[str, list[str]]:
    """Keys only in *a* and only in *b*."""
    return {"only_a": sorted(set(a) - set(b)), "only_b": sorted(set(b) - set(a))}


# ---- spikes ---------------------------------------------------------------


def _get(client, params: dict) -> tuple[dict, bytes]:
    resp = client._post({"id": client._next_id(), "method": "get", "params": [params]})
    return resp, json.dumps(resp, sort_keys=True).encode()


def run_devices_fields(client, adom: str) -> dict:
    """Compare the ADOM device-list payload with/without ``fields`` and ``loadsub``."""
    url = f"/dvmdb/adom/{adom}/device"
    variants = {
        "full": {"url": url},
        "fields": {"url": url, "fields": DEVICE_FIELDS},
        "loadsub0": {"url": url, "loadsub": 0},
        "fields+loadsub0": {"url": url, "fields": DEVICE_FIELDS, "loadsub": 0},
    }
    blobs: dict[str, bytes] = {}
    info: dict[str, dict] = {}
    first: dict[str, dict] = {}
    for name, params in variants.items():
        resp, blob = _get(client, params)
        blobs[name] = blob
        result = (resp.get("result") or [{}])[0]
        data = result.get("data") or []
        devices = [d for d in data if isinstance(d, dict)]
        first[name] = devices[0] if devices else {}
        info[name] = {
            "status_code": result.get("status", {}).get("code"),
            "device_count": len(devices),
            "vdom_present": any(d.get("vdom") for d in devices),
            "avg_keys_per_device": round(sum(len(d) for d in devices) / len(devices), 1)
            if devices
            else 0,
        }
    return {
        "sizes": summarize_sizes(blobs),
        "variants": info,
        "keys_lost_vs_full": {
            name: diff_keys(first["full"], first[name])["only_a"]
            for name in variants
            if name != "full"
        },
    }


def _proxy_body(client, targets: list[str]) -> dict:
    return {
        "id": client._next_id(),
        "method": "exec",
        "params": [
            {
                "url": "/sys/proxy/json",
                "data": {"action": "get", "resource": RESOURCE, "target": targets},
            }
        ],
    }


def _proxy_shape(client, targets: list[str]) -> dict:
    started = time.monotonic()
    resp = client._post(_proxy_body(client, targets))
    seconds = time.monotonic() - started
    result = (resp.get("result") or [{}])[0]
    data = result.get("data")
    entries = data if isinstance(data, list) else []
    return {
        "targets_requested": len(targets),
        "targets_returned": len(entries),
        "rpc_code": result.get("status", {}).get("code"),
        "per_target": [
            {
                "status_code": (e.get("status") or {}).get("code"),
                "http_status": (e.get("response") or {}).get("http_status"),
            }
            for e in entries
            if isinstance(e, dict)
        ],
        "response_bytes": len(json.dumps(resp).encode()),
        "seconds": round(seconds, 4),
    }


def run_proxy_multi(
    client, adom: str, devices: list[str], max_targets: int = 20
) -> dict:
    """Can one ``/sys/proxy/json`` call carry several targets, and what does an
    unreachable/unknown target do to the rest?"""
    targets = [f"adom/{adom}/device/{d}" for d in devices[:max_targets]]
    bogus = f"adom/{adom}/device/__spike_nonexistent__"
    return {
        "resource": RESOURCE,
        "single": _proxy_shape(client, targets[:1]),
        "multi": _proxy_shape(client, targets),
        "with_unreachable": _proxy_shape(client, [*targets[:3], bogus]),
        "max_targets_tested": len(targets),
    }


def _keys(obj) -> list[str]:
    if isinstance(obj, list):
        obj = next((o for o in obj if isinstance(o, dict)), {})
    return sorted(obj) if isinstance(obj, dict) else []


def run_pkg_marker(client, adom: str) -> dict:
    """Which fields could signal 'this policy package changed'? Lists key names only."""
    packages = client.get_policy_packages(adom)
    entry_keys = _keys(packages)
    object_keys: list[str] = []
    if packages:
        try:
            object_keys = _keys(
                client._get(f"/pm/pkg/adom/{adom}/{packages[0]['path']}")
            )
        except Exception:
            object_keys = []
    try:
        revision_keys = _keys(client.get_adom_revisions(adom))
    except Exception:
        revision_keys = []
    try:
        audit_keys = _keys(client.get_audit_log(hours=1))
    except Exception:
        audit_keys = []
    sources = {
        "package_entry": entry_keys,
        "package_object": object_keys,
        "revision_entry": revision_keys,
        "audit_log_entry": audit_keys,
    }
    return {
        "package_count": len(packages),
        "package_entry_keys": entry_keys,
        "package_object_keys": object_keys,
        "revision_entry_keys": revision_keys,
        "audit_log_entry_keys": audit_keys,
        "candidate_marker_fields": sorted(
            f"{src}.{k}"
            for src, ks in sources.items()
            for k in ks
            if _MARKER_RE.search(k)
        ),
    }


def run_latency(
    client, adom: str, devices: list[str], n: int = 20, workers: int = 5
) -> dict:
    """Proxy GET latency: *n* sequential calls, then *n* across *workers* threads."""
    if not devices:
        return {"error": "no devices"}
    picks = [devices[i % len(devices)] for i in range(n)]

    def one(dev: str) -> float:
        started = time.monotonic()
        client._proxy(adom, dev, RESOURCE)
        return time.monotonic() - started

    seq = [one(d) for d in picks]
    wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        conc = list(pool.map(one, picks))
    wall = time.monotonic() - wall_start
    return {
        "resource": RESOURCE,
        "sequential": {"count": len(seq), "seconds": percentiles(seq)},
        "concurrent": {
            "count": len(conc),
            "workers": workers,
            "seconds": percentiles(conc),
            "wall_seconds": round(wall, 4),
        },
    }


# ---- CLI -----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "command", choices=["devices-fields", "proxy-multi", "pkg-marker", "latency"]
    )
    ap.add_argument("--adom", help="ADOM to use (default: first non-system ADOM)")
    ap.add_argument(
        "--targets", type=int, default=20, help="devices to use (proxy-multi/latency)"
    )
    ap.add_argument("--n", type=int, default=20, help="calls for latency")
    ap.add_argument("--workers", type=int, default=5, help="threads for latency")
    ap.add_argument(
        "--out-dir", type=Path, default=ROOT / "docs" / "superpowers" / "measurements"
    )
    args = ap.parse_args(argv)

    from app.fmg_helpers import make_client

    with make_client() as client:
        adom = args.adom or next(
            a["name"]
            for a in client.get_adoms()
            if not a["name"].lower().startswith("forti")
        )
        devices = [d["name"] for d in client.get_devices(adom)][: args.targets]
        if args.command == "devices-fields":
            report = run_devices_fields(client, adom)
        elif args.command == "proxy-multi":
            report = run_proxy_multi(client, adom, devices, max_targets=args.targets)
        elif args.command == "pkg-marker":
            report = run_pkg_marker(client, adom)
        else:
            report = run_latency(client, adom, devices, n=args.n, workers=args.workers)
        try:
            report["fmg_version"] = str(client.version)
        except Exception:
            report["fmg_version"] = None

    report["device_sample"] = len(devices)
    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{datetime.now(UTC):%Y-%m-%d}-spike-{args.command}.json"
    out.write_text(text)
    print(
        f"wrote {out}  (review for sensitive data before committing)", file=sys.stderr
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
