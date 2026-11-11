"""Per-package hygiene results in the shared store (first slice of the policy store).

One row per (ADOM, package): the findings the hygiene checks produced, the
number counted for the executive score, the sets of object names the package's
rules reference (enough to detect unused objects ADOM-wide), a fingerprint of the
policy list and when it was fetched. The collector's hygiene sweep reuses a row
younger than its jittered TTL instead of re-downloading the package's policies.
Raw policy lists are never stored.
"""

from __future__ import annotations

import hashlib
import json
import zlib
from datetime import UTC, datetime

from app.config import Config
from app.inventory_store import InventoryStoreError, _age, _Conn

HygienePkgStoreError = InventoryStoreError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hygiene_pkg (
    adom TEXT NOT NULL, pkg TEXT NOT NULL, fetched_at TEXT NOT NULL,
    fingerprint TEXT NOT NULL, policy_count INTEGER NOT NULL,
    score_findings INTEGER NOT NULL, findings_json TEXT NOT NULL,
    addr_refs_json TEXT NOT NULL, svc_refs_json TEXT NOT NULL,
    PRIMARY KEY (adom, pkg));
"""
_SCHEMA_ID = "hygiene_pkg"


def _conn(write: bool = False) -> _Conn:
    return _Conn(write=write, schema=_SCHEMA, schema_id=_SCHEMA_ID)


def fingerprint(policies: list[dict]) -> str:
    """Stable hash of a policy list (independent of dict key order)."""
    blob = json.dumps(policies, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def effective_ttl_for(adom: str, pkg: str, base_seconds: float) -> float:
    """*base_seconds* x a stable 0.75..1.25 factor derived from ``adom/pkg``."""
    frac = (zlib.crc32(f"{adom}/{pkg}".encode()) % 10000) / 10000.0
    return base_seconds * (0.75 + 0.5 * frac)


def effective_ttl_seconds(adom: str, pkg: str) -> float:
    """The package's TTL: configured hours x a stable 0.75..1.25 factor (spreads refetches)."""
    return effective_ttl_for(
        adom, pkg, float(Config.HYGIENE_PACKAGE_TTL_HOURS) * 3600.0
    )


def get(adom: str, pkg: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT fetched_at, fingerprint, policy_count, score_findings, findings_json, "
            "addr_refs_json, svc_refs_json FROM hygiene_pkg WHERE adom=? AND pkg=?",
            (adom, pkg),
        ).fetchone()
    if row is None:
        return None
    return {
        "fetched_at": row[0],
        "age_seconds": _age(row[0]),
        "fingerprint": row[1],
        "policy_count": row[2],
        "score_findings": row[3],
        "findings": json.loads(row[4]),
        "addr_refs": set(json.loads(row[5])),
        "svc_refs": set(json.loads(row[6])),
    }


def put(
    adom: str,
    pkg: str,
    *,
    fingerprint: str,
    policy_count: int,
    score_findings: int,
    findings: list[dict],
    addr_refs,
    svc_refs,
) -> None:
    with _conn(write=True) as conn:
        conn.execute(
            "INSERT INTO hygiene_pkg (adom, pkg, fetched_at, fingerprint, policy_count, "
            "score_findings, findings_json, addr_refs_json, svc_refs_json) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(adom, pkg) DO UPDATE SET "
            "fetched_at=excluded.fetched_at, fingerprint=excluded.fingerprint, "
            "policy_count=excluded.policy_count, score_findings=excluded.score_findings, "
            "findings_json=excluded.findings_json, addr_refs_json=excluded.addr_refs_json, "
            "svc_refs_json=excluded.svc_refs_json",
            (
                adom,
                pkg,
                datetime.now(UTC).isoformat(),
                fingerprint,
                policy_count,
                score_findings,
                json.dumps(findings),
                json.dumps(sorted(addr_refs)),
                json.dumps(sorted(svc_refs)),
            ),
        )
        conn.commit()


def touch(adom: str, pkg: str) -> None:
    """Mark the cached entry as just verified (its policies were refetched unchanged)."""
    with _conn(write=True) as conn:
        conn.execute(
            "UPDATE hygiene_pkg SET fetched_at=? WHERE adom=? AND pkg=?",
            (datetime.now(UTC).isoformat(), adom, pkg),
        )
        conn.commit()


def delete_missing(adom: str, keep: set[str]) -> int:
    """Drop cached packages of *adom* that FortiManager no longer lists."""
    with _conn(write=True) as conn:
        have = [
            r[0]
            for r in conn.execute("SELECT pkg FROM hygiene_pkg WHERE adom=?", (adom,))
        ]
        gone = [p for p in have if p not in keep]
        for p in gone:
            conn.execute("DELETE FROM hygiene_pkg WHERE adom=? AND pkg=?", (adom, p))
        conn.commit()
    return len(gone)


def _set_fetched_at_for_test(adom: str, pkg: str, fetched_at: str) -> None:
    with _conn(write=True) as conn:
        conn.execute(
            "UPDATE hygiene_pkg SET fetched_at=? WHERE adom=? AND pkg=?",
            (fetched_at, adom, pkg),
        )
        conn.commit()
