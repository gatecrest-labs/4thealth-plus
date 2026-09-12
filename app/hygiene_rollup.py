"""Fleet-wide rule-hygiene rollup history — persisted so trends survive restarts.

Follows the same JSON-file-at-project-root pattern as device_review_jobs.json
(app/device_review_scheduler.py) and api_tokens.json (app/api_tokens.py).
"""

from __future__ import annotations

_MAX_RUNS = 30
_MAX_DETAILS = 50
_CACHE_KEY = "hygiene_history"


def build_details(package_findings: list[dict]) -> list[dict]:
    """Per-package drill-down for the fleet rollup's "details" field.

    package_findings: [{"package": str, "adom": str, "findings": list[dict]}],
    one entry per policy package swept this cycle. Packages with no
    findings are excluded. Capped at _MAX_DETAILS, most relevant first:
    sorted by number of findings (descending), then adom (ascending), then
    package (ascending) for a stable order among equally-sized packages.
    """
    entries = [p for p in package_findings if p.get("findings")]
    entries.sort(key=lambda p: (-len(p["findings"]), p["adom"], p["package"]))
    return entries[:_MAX_DETAILS]


def get_history() -> list[dict]:
    """Return the rollup history, newest first, or [] if none exists yet."""
    from app import collector_store

    snapshot = collector_store.read_snapshot(_CACHE_KEY)
    history = snapshot.get("history") if snapshot else None
    return history if isinstance(history, list) else []


def get_latest() -> dict | None:
    """Return the most recent rollup record, or None if no history exists."""
    history = get_history()
    return history[0] if history else None


def append_run(record: dict) -> None:
    """Prepend a new rollup record, keeping at most _MAX_RUNS entries."""
    from app import collector_store

    history = get_history()
    history.insert(0, record)
    history = history[:_MAX_RUNS]
    collector_store.write_snapshot(_CACHE_KEY, {"history": history})
