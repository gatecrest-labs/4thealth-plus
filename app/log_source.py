"""4tlog connection config — Admin -> Log Hygiene. Mirrors app/smtp_client.py's
atomic-JSON config pattern. The token is stored reversibly (this app sends
it on every call to 4tlog; it does not verify inbound tokens), unlike
app/api_tokens.py's hashed inbound tokens."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from app.atomic_io import atomic_write_json

_CONFIG_PATH = Path(__file__).parent.parent / "log_source_config.json"
_lock = threading.Lock()

_DEFAULTS: dict = {
    "enabled": False,
    "base_url": "",
    "token": "",
    "verify_ssl": True,
}


def load_log_source_config() -> dict:
    with _lock:
        if not _CONFIG_PATH.exists():
            return dict(_DEFAULTS)
        try:
            with open(_CONFIG_PATH) as f:
                data = json.load(f)
            return {**_DEFAULTS, **data}
        except Exception:
            return dict(_DEFAULTS)


def save_log_source_config(cfg: dict) -> None:
    with _lock:
        atomic_write_json(_CONFIG_PATH, {**_DEFAULTS, **cfg})
