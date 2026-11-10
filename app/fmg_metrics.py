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
import threading
import time
from collections import deque
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

_FLUSH_INTERVAL_S = 30.0
_SAMPLE_SIZE = 500

_lock = threading.Lock()
_stats: dict[str, dict] = {}
_since = datetime.now(UTC).isoformat()
_last_flush = 0.0

# Path segments whose *next* segment is a name worth collapsing.
_NAME_AFTER = {"adom": "{adom}", "pkg": "{pkg}", "vdom": "{vdom}", "device": "{device}"}


def normalize_url(url: str) -> str:
    """Replace ADOM / package / device / VDOM names and task ids with placeholders.

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

    out: list[str] = []
    pending: list[str] = []  # placeholders for the next segments
    for i, seg in enumerate(parts):
        if pending and seg:
            out.append(pending.pop(0))
            continue
        if seg.isdigit():
            out.append("{id}")
            continue
        out.append(seg)
        if seg == "status" and i > 0 and parts[i - 1] == "_package":
            pending = ["{device}", "{vdom}"]
        elif seg in _NAME_AFTER and not (seg == "pkg" and parts[i - 1] == "pm"):
            pending = [_NAME_AFTER[seg]]
    return "/".join(out)


def role() -> str:
    """``collector`` when this process runs the schedulers, else ``web``."""
    from app.config import Config

    return "collector" if Config.RUN_SCHEDULERS == "inline" else "web"


def reset() -> None:
    """Clear all counters (used by tests)."""
    global _since, _last_flush
    with _lock:
        _stats.clear()
        _since = datetime.now(UTC).isoformat()
        _last_flush = 0.0


def record(method: str, url: str, seconds: float, ok: bool) -> None:
    """Record one FMG call. Never raises."""
    try:
        key = f"{method} {normalize_url(url)}"
        with _lock:
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


def flush(force: bool = False) -> None:
    """Publish ``snapshot()`` to the shared store, at most every 30 s. Never raises."""
    global _last_flush
    try:
        now = time.monotonic()
        if not force and _last_flush and now - _last_flush < _FLUSH_INTERVAL_S:
            return
        _last_flush = now
        from app import collector_store

        snap = snapshot()
        collector_store.write_snapshot(
            f"fmg_metrics:{snap['role']}",
            snap,
            collected_at=datetime.now(UTC).isoformat(),
        )
    except Exception:
        logger.debug("fmg_metrics.flush failed", exc_info=True)
