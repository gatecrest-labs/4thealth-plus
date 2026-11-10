"""Per-process FortiManager call metrics (count, errors, latency per URL).

Every ``FMGClient._post`` is timed and recorded under a normalized key
``"<method> <url with names replaced>"`` so a sweep over 1,000 devices shows
up as one row, not 1,000. Each process (web, collector) keeps its own
counters and periodically publishes them to the shared collector store under
``fmg_metrics:<role>`` so the Admin page can show both.

Recording must never affect an FMG call: every public function swallows its
own failures.
"""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from collections import deque
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

_FLUSH_INTERVAL_S = 30.0
_SAMPLE_SIZE = 500
_MAX_KEYS = 500  # distinct URL keys per process; the rest fold into "<other>"
_STALE_ROW_SECONDS = 24 * 3600
# Flush on a background thread so a slow/locked store never delays an FMG call.
# tests/conftest.py turns this off for deterministic synchronous flushes.
_flush_async = True

_lock = threading.Lock()
_flush_state = threading.Lock()  # guards the rate-limit check-and-set
_flush_inflight = threading.Lock()  # single-flight: at most one write at a time
_stats: dict[str, dict] = {}
_since = datetime.now(UTC).isoformat()
_last_flush = 0.0

# Path segments whose *next* segment is a name worth collapsing.
_NAME_AFTER = {
    "adom": "{adom}",
    "pkg": "{pkg}",
    "pblock": "{pblock}",
    "vdom": "{vdom}",
    "device": "{device}",
    "group": "{group}",
}
# Object kinds under .../obj/... whose next segment is an object name.
_OBJ_KINDS = {"address", "addrgrp", "vip", "ippool", "custom", "group"}
# A package path (which may contain folders) ends where one of these begins.
_PKG_PATH_END = {"firewall", "_package"}


def normalize_url(url: str) -> str:
    """Replace ADOM / package / device / VDOM / object names and task ids with placeholders.

    Keeps the number of distinct keys bounded no matter how many ADOMs,
    packages or devices exist (1,000 devices must still be one row).
    """
    parts = url.split("/")
    # /pm/pkg/adom/<adom>[/<folder>.../<package>] -- here "pkg" is a namespace,
    # not a name prefix, and everything after the ADOM is a package path.
    if parts[:4] == ["", "pm", "pkg", "adom"]:
        out = parts[:4]
        if len(parts) > 4:
            out.append("{adom}")
        if len(parts) > 5:
            out.append("{pkg}")
        return "/".join(out)

    in_obj = "obj" in parts
    out: list[str] = []
    pending: list[str] = []  # placeholders for the next segments
    swallow_pkg_path = False
    for i, seg in enumerate(parts):
        if swallow_pkg_path:
            if seg in _PKG_PATH_END:
                swallow_pkg_path = False  # fall through and emit it
            else:
                continue  # folder / package-name segment already collapsed
        elif pending and seg:
            out.append(pending.pop(0))
            continue
        if seg.isdigit():
            out.append("{id}")
            continue
        out.append(seg)
        if seg == "status" and i > 0 and parts[i - 1] == "_package":
            pending = ["{device}", "{vdom}"]
        elif in_obj and seg in _OBJ_KINDS:
            pending = ["{name}"]
        elif seg == "pkg" and parts[i - 1] != "pm":
            out.append("{pkg}")
            swallow_pkg_path = True
        elif seg in _NAME_AFTER and not (seg == "pkg" and parts[i - 1] == "pm"):
            pending = [_NAME_AFTER[seg]]
    return "/".join(out)


def _enabled() -> bool:
    return os.environ.get("FMG_METRICS", "on").strip().lower() not in (
        "off",
        "0",
        "false",
        "no",
    )


def role() -> str:
    """``collector`` when this process runs the schedulers, else ``web``."""
    from app.config import Config

    return "collector" if Config.RUN_SCHEDULERS == "inline" else "web"


def snapshot_key() -> str:
    """Store key for this process: one per web worker (pid), one for the collector."""
    r = role()
    return (
        "fmg_metrics:collector"
        if r == "collector"
        else f"fmg_metrics:{r}:{os.getpid()}"
    )


def reset() -> None:
    """Clear all counters (used by tests)."""
    global _since, _last_flush
    with _lock:
        _stats.clear()
        _since = datetime.now(UTC).isoformat()
        _last_flush = 0.0


def record(method: str, url: str, seconds: float, ok: bool) -> None:
    """Record one FMG call. Never raises."""
    if not _enabled():
        return
    try:
        key = f"{method} {normalize_url(url)}"
        with _lock:
            if key not in _stats and len(_stats) >= _MAX_KEYS:
                key = f"{method} <other>"
            entry = _stats.setdefault(
                key,
                {
                    "count": 0,
                    "errors": 0,
                    "total_s": 0.0,
                    "samples": deque(maxlen=_SAMPLE_SIZE),
                },
            )
            entry["count"] += 1
            entry["total_s"] += seconds
            entry["samples"].append(seconds)
            if not ok:
                entry["errors"] += 1
    except Exception:
        logger.debug("fmg_metrics.record failed", exc_info=True)


def _percentile(sorted_samples: list[float], q: float) -> float:
    if not sorted_samples:
        return 0.0
    if q == 0.5:
        n = len(sorted_samples)
        mid = n // 2
        return (
            sorted_samples[mid]
            if n % 2
            else (sorted_samples[mid - 1] + sorted_samples[mid]) / 2
        )
    return sorted_samples[max(0, math.ceil(q * len(sorted_samples)) - 1)]


def snapshot() -> dict:
    """Current counters as a JSON-serializable dict."""
    with _lock:
        by_url = {}
        total = errors = 0
        for key, e in _stats.items():
            s = sorted(e["samples"])
            by_url[key] = {
                "count": e["count"],
                "errors": e["errors"],
                "total_s": e["total_s"],
                "p50_s": _percentile(s, 0.5),
                "p95_s": _percentile(s, 0.95),
            }
            total += e["count"]
            errors += e["errors"]
        return {
            "role": role(),
            "since": _since,
            "total": total,
            "errors": errors,
            "by_url": by_url,
        }


def merge(snapshots: list[dict]) -> dict:
    """Combine per-process snapshots (e.g. several gunicorn workers) into one.

    Counts, errors and total time add up; p95 is the worst worker's p95 and p50
    is the call-weighted mean of the workers' medians (an approximation).
    """
    merged: dict[str, dict] = {}
    total = errors = 0
    since = min((s.get("since", "") for s in snapshots), default="")
    for snap in snapshots:
        total += snap.get("total", 0)
        errors += snap.get("errors", 0)
        for key, e in snap.get("by_url", {}).items():
            m = merged.setdefault(
                key,
                {"count": 0, "errors": 0, "total_s": 0.0, "_p50w": 0.0, "p95_s": 0.0},
            )
            m["count"] += e["count"]
            m["errors"] += e["errors"]
            m["total_s"] += e["total_s"]
            m["_p50w"] += e["p50_s"] * e["count"]
            m["p95_s"] = max(m["p95_s"], e["p95_s"])
    by_url = {}
    for key, m in merged.items():
        by_url[key] = {
            "count": m["count"],
            "errors": m["errors"],
            "total_s": m["total_s"],
            "p50_s": m["_p50w"] / m["count"] if m["count"] else 0.0,
            "p95_s": m["p95_s"],
        }
    return {
        "role": snapshots[0].get("role", "web") if snapshots else "web",
        "since": since,
        "workers": len(snapshots),
        "total": total,
        "errors": errors,
        "by_url": by_url,
    }


def _write_snapshot() -> None:
    """Publish this process's counters to the shared store. Never raises."""
    try:
        from app import collector_store

        snap = snapshot()
        collector_store.write_snapshot(
            snapshot_key(), snap, collected_at=datetime.now(UTC).isoformat()
        )
        if snap["role"] != "collector":
            # Worker pids change on every restart; drop rows nobody updates any more.
            collector_store.delete_stale_snapshots(
                "fmg_metrics:web:", _STALE_ROW_SECONDS
            )
    except Exception:
        logger.debug("fmg_metrics flush failed", exc_info=True)


def _flush_worker() -> None:
    try:
        _write_snapshot()
    finally:
        _flush_inflight.release()


def flush(force: bool = False) -> None:
    """Publish ``snapshot()`` to the shared store, at most every 30 s. Never raises.

    The write runs on a short-lived daemon thread (single-flight) so a slow or
    locked store cannot delay the FMG call that triggered it. ``force=True``
    writes synchronously (tests, shutdown).
    """
    global _last_flush
    if not _enabled():
        return
    try:
        if force:
            with _flush_state:
                _last_flush = time.monotonic()
            _write_snapshot()
            return
        with _flush_state:
            now = time.monotonic()
            if _last_flush and now - _last_flush < _FLUSH_INTERVAL_S:
                return
            if not _flush_inflight.acquire(blocking=False):
                return
            _last_flush = now
        if _flush_async:
            threading.Thread(
                target=_flush_worker, name="fmg-metrics-flush", daemon=True
            ).start()
        else:
            _flush_worker()
    except Exception:
        logger.debug("fmg_metrics.flush failed", exc_info=True)
