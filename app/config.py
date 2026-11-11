"""Application configuration loaded from environment / .env file."""

import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE_DIR = Path(__file__).parent.parent


def _load_infra_targets() -> list:
    path = _BASE_DIR / "infra_targets.json"
    if path.exists():
        with path.open() as f:
            return json.load(f)
    return []


def _require_secret_key() -> str:
    val = os.environ.get("SECRET_KEY", "")
    if not val or val == "change-me-in-production":
        raise RuntimeError(
            "SECRET_KEY is not set or is the insecure default. "
            "Generate one with: python manage_users.py secret"
        )
    return val


_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _env_flag(name: str) -> bool:
    """True when env var *name* is one of 1/true/yes/on (case-insensitive)."""
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def _env_bool(name: str, default: bool) -> bool:
    """Boolean env var *name*; unset or blank gives *default*."""
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in _TRUTHY


def _policy_ttl_hours() -> int:
    """Policy package TTL in hours: POLICY_PACKAGE_TTL_HOURS, else the older
    HYGIENE_PACKAGE_TTL_HOURS, else 6."""
    fallback = _env_int("HYGIENE_PACKAGE_TTL_HOURS", 6)
    return _env_int("POLICY_PACKAGE_TTL_HOURS", fallback)


def _env_int(name: str, default: int | None) -> int | None:
    """Integer env var *name*; unset, blank or non-numeric gives *default*."""
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw)
    except ValueError:
        return default


class Config:
    SECRET_KEY = _require_secret_key()
    # Browser cookies are scoped by domain+path, not by port (RFC 6265).
    # Without a unique name here, this collides with any other Flask app's
    # default "session" cookie served from localhost at a different port
    # (e.g. 4tlog, 4tExecutive) -- whichever app's response the browser
    # processes last silently overwrites the others' session cookie,
    # causing intermittent 401s and CSRF failures that have nothing to do
    # with this app's own auth logic.
    SESSION_COOKIE_NAME = "4thealth_plus_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Auto-enable when SSL cert/key are present; can also be forced via .env
    _ssl_active = os.path.exists(
        os.environ.get("SSL_CERT", "certs/cert.pem")
    ) and os.path.exists(os.environ.get("SSL_KEY", "certs/key.pem"))
    SESSION_COOKIE_SECURE = os.environ.get(
        "COOKIE_SECURE", "auto"
    ).lower() == "true" or (
        os.environ.get("COOKIE_SECURE", "auto").lower() == "auto" and _ssl_active
    )
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    # Absolute session cap — no matter how active, sessions expire after this many seconds.
    SESSION_ABSOLUTE_LIFETIME = int(
        os.environ.get("SESSION_ABSOLUTE_LIFETIME", str(10 * 3600))
    )  # 10 h
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(4 * 1024 * 1024)))

    # Infrastructure dashboard targets — loaded from infra_targets.json
    INFRA_TARGETS: list = _load_infra_targets()

    # Primary FortiManager host — used for ADOM/device queries (fmg_helpers.py)
    FMG_PRIMARY_HOST = os.environ.get("FMG_PRIMARY_HOST", "")

    FMG_USERNAME = os.environ.get("FMG_USERNAME", "")
    FMG_PASSWORD = os.environ.get("FMG_PASSWORD", "")
    FMG_API_TOKEN = os.environ.get("FMG_API_TOKEN", "")

    FMG_VERIFY_SSL = os.environ.get("FMG_VERIFY_SSL", "true").lower() == "true"
    FMG_TIMEOUT = int(os.environ.get("FMG_TIMEOUT", "30"))
    # F1 access layer. FMG_MAX_INFLIGHT: unset = role default (collector 8,
    # web worker 4), 0 = unlimited. FMG_RETRIES: extra attempts, 0 = off.
    FMG_MAX_INFLIGHT = _env_int("FMG_MAX_INFLIGHT", None)
    FMG_RETRIES = _env_int("FMG_RETRIES", 2)
    # Seconds a call may wait for an in-flight slot before failing (0 = no bound).
    FMG_SLOT_WAIT_SECS = _env_int("FMG_SLOT_WAIT_SECS", 60)

    # Health thresholds (yellow / red)
    CPU_WARN = int(os.environ.get("CPU_WARN", "70"))
    CPU_CRIT = int(os.environ.get("CPU_CRIT", "90"))
    MEM_WARN = int(os.environ.get("MEM_WARN", "75"))
    MEM_CRIT = int(os.environ.get("MEM_CRIT", "90"))

    # RADIUS / FortiAuthenticator (optional)
    RADIUS_ENABLED = os.environ.get("RADIUS_ENABLED", "false").lower() == "true"
    RADIUS_HOST = os.environ.get("RADIUS_HOST", "")
    RADIUS_PORT = int(os.environ.get("RADIUS_PORT", "1812"))
    # Secondary FAC for HA / maintenance failover — leave blank if not used
    RADIUS_HOST_2 = os.environ.get("RADIUS_HOST_2", "")
    RADIUS_PORT_2 = int(os.environ.get("RADIUS_PORT_2", "1812"))
    RADIUS_SECRET = os.environ.get("RADIUS_SECRET", "")
    RADIUS_TIMEOUT = int(os.environ.get("RADIUS_TIMEOUT", "10"))
    RADIUS_GROUP_ADMIN = os.environ.get("RADIUS_GROUP_ADMIN", "")
    RADIUS_GROUP_VIEWER = os.environ.get("RADIUS_GROUP_VIEWER", "")

    # SSO sessions are admins when the user is a member of this group (membership is
    # pushed from 4tSuite). Empty disables SSO admin; a missing group makes nobody admin.
    SSO_ADMIN_GROUP = os.environ.get("SSO_ADMIN_GROUP", "administrators").strip()

    # "inline" = start every BackgroundScheduler job in this same process
    # (the old, single-process behaviour — convenient for local dev and
    # for anyone not running the separate collector process). Anything
    # else (default "off") means this process starts NO schedulers and
    # expects `python -m app.collector` to be running separately. See
    # app/collector.py and docker-compose.yml's `collector` service.
    RUN_SCHEDULERS = os.environ.get("RUN_SCHEDULERS", "off").lower()

    # Scale layers (1,000+ FortiGate work, see
    # docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md).
    # Each flag switches one layer from the legacy direct-FMG path to the
    # cached path; all default off so behaviour is unchanged until enabled.
    INVENTORY_CACHE = _env_flag("INVENTORY_CACHE")
    # Inventory cache (F2): collector refresh period, the age beyond which a
    # reader falls back to a live FMG call (0/unset = 3 x refresh), and how many
    # ADOMs the collector fetches in parallel.
    INVENTORY_REFRESH_SECS = _env_int("INVENTORY_REFRESH_SECS", 300)
    INVENTORY_MAX_AGE_SECS = _env_int("INVENTORY_MAX_AGE_SECS", 0)
    INVENTORY_PARALLEL_ADOMS = _env_int("INVENTORY_PARALLEL_ADOMS", 4)
    POLICY_STORE = _env_flag("POLICY_STORE")
    # F5 Config-Delta gating (needs INVENTORY_CACHE): preview only devices whose
    # cached sync status shows pending changes. Default on; "off" disables.
    CONFIG_DELTA_GATING = _env_bool("CONFIG_DELTA_GATING", True)
    CONFIG_DELTA_FULL_SWEEP_HOURS = _env_int("CONFIG_DELTA_FULL_SWEEP_HOURS", 24)
    CONFIG_DELTA_JOB_BUDGET_SECS = _env_int("CONFIG_DELTA_JOB_BUDGET_SECS", 3600)
    # POLICY_STORE: a package's cached hygiene result is reused until it is this
    # old (each package jittered x0.75..x1.25 so refetches spread out).
    HYGIENE_PACKAGE_TTL_HOURS = _env_int("HYGIENE_PACKAGE_TTL_HOURS", 6)
    # Policy/object store (Phase 4). Package TTL (jittered x0.75..x1.25), object
    # refresh period, the age beyond which a reader goes live (0 = 2 x 1.25 x TTL),
    # collector fetch parallelism, per-package Refresh throttle.
    POLICY_PACKAGE_TTL_HOURS = _policy_ttl_hours()
    POLICY_OBJECTS_REFRESH_MINUTES = _env_int("POLICY_OBJECTS_REFRESH_MINUTES", 60)
    POLICY_MAX_AGE_SECS = _env_int("POLICY_MAX_AGE_SECS", 0)
    POLICY_PARALLEL_FETCH = _env_int("POLICY_PARALLEL_FETCH", 4)
    POLICY_REFRESH_MIN_INTERVAL_SECS = _env_int("POLICY_REFRESH_MIN_INTERVAL_SECS", 30)
    # Device audit snapshots (Phase 5). The rolling window over which every device
    # is re-captured, the age beyond which a reader goes live (0 = window + 1 day),
    # collector workers, batch period and how often ADOM config revisions are
    # checked for devices that changed.
    AUDIT_SNAPSHOT_WINDOW_DAYS = _env_int("AUDIT_SNAPSHOT_WINDOW_DAYS", 7)
    AUDIT_SNAPSHOT_MAX_AGE_HOURS = _env_int("AUDIT_SNAPSHOT_MAX_AGE_HOURS", 0)
    AUDIT_SNAPSHOT_WORKERS = _env_int("AUDIT_SNAPSHOT_WORKERS", 2)
    AUDIT_SNAPSHOT_BATCH_MINUTES = _env_int("AUDIT_SNAPSHOT_BATCH_MINUTES", 10)
    AUDIT_SNAPSHOT_REVISION_CHECK_MINUTES = _env_int(
        "AUDIT_SNAPSHOT_REVISION_CHECK_MINUTES", 60
    )
    AUDIT_SNAPSHOTS = _env_flag("AUDIT_SNAPSHOTS")
    JOB_QUEUE = _env_flag("JOB_QUEUE")

    # SNMP (FortiManager / FortiAnalyzer / FortiAuthenticator CPU & memory polling)
    SNMP_ENABLED = os.environ.get("SNMP_ENABLED", "false").lower() == "true"
    SNMP_PORT = int(os.environ.get("SNMP_PORT", "161"))
    SNMP_TIMEOUT = int(os.environ.get("SNMP_TIMEOUT", "5"))
    SNMP_RETRIES = int(os.environ.get("SNMP_RETRIES", "1"))
    SNMP_POLL_INTERVAL = int(os.environ.get("SNMP_POLL_INTERVAL", "60"))
    SNMP_USER = os.environ.get("SNMP_USER", "")
    SNMP_AUTH_PROTOCOL = os.environ.get("SNMP_AUTH_PROTOCOL", "SHA")
    SNMP_AUTH_KEY = os.environ.get("SNMP_AUTH_KEY", "")
    SNMP_PRIV_PROTOCOL = os.environ.get("SNMP_PRIV_PROTOCOL", "AES")
    SNMP_PRIV_KEY = os.environ.get("SNMP_PRIV_KEY", "")

    # AI Assist (Rule Validation) — LLM provider selection and credentials
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "claude")
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5")
    OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "")
    OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")
    OLLAMA_API_KEY = os.environ.get("OLLAMA_API_KEY", "")

    # PSIRT Advisory Assessment enrichment (fortiguard.com + CISA KEV feed)
    PSIRT_ENRICHMENT_ENABLED = (
        os.environ.get("PSIRT_ENRICHMENT_ENABLED", "true").lower() == "true"
    )
    PSIRT_KEV_URL = os.environ.get(
        "PSIRT_KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    PSIRT_FETCH_TIMEOUT = int(os.environ.get("PSIRT_FETCH_TIMEOUT", "5"))
