"""Fleet-wide rule-hygiene rollup history — persisted so trends survive restarts.

Follows the same JSON-file-at-project-root pattern as device_review_jobs.json
(app/device_review_scheduler.py) and api_tokens.json (app/api_tokens.py).
"""

from __future__ import annotations

import json
from pathlib import Path

from app.atomic_io import atomic_write_json

_ROLLUP_PATH = Path(__file__).parent.parent / "hygiene_rollup.json"
_MAX_RUNS = 30


def get_history() -> list[dict]:
    """Return the rollup history, newest first, or [] if none exists yet."""
    if not _ROLLUP_PATH.exists():
        return []
    try:
        data = json.loads(_ROLLUP_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def get_latest() -> dict | None:
    """Return the most recent rollup record, or None if no history exists."""
    history = get_history()
    return history[0] if history else None


def append_run(record: dict) -> None:
    """Prepend a new rollup record, keeping at most _MAX_RUNS entries."""
    history = get_history()
    history.insert(0, record)
    atomic_write_json(_ROLLUP_PATH, history[:_MAX_RUNS])
