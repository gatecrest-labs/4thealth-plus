"""Rule Lookup cache — every policy rule of every non-system ADOM.

Backs the Rule Lookup section of the Rule Review tab. Runs at startup and every
RULE_LOOKUP_CACHE_INTERVAL_MIN minutes (default 60), mirroring license_cache.

Per-ADOM entry in _store:
  rules          list[dict]  one record per rule (policy-block rules expanded)
  ctx            Context     resolved address networks + service catalog
  last_updated   str         ISO-8601 UTC
  status         str         "ok" | "running" | "error"
  error          str | None  last whole-ADOM failure (old data is kept)
  package_errors list[str]   packages that failed to fetch on the last build

Rule record keys: adom, package, firewalls, policyid, name, status, action,
srcintf, dstintf, srcaddr, dstaddr, service, srcaddr_negate, dstaddr_negate,
comment, policy_block ("" when the rule is not inside a policy block).
"""

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from app.fmg_helpers import make_client
from app.hygiene import _action, _status
from app.planner.matching import ServiceCatalog
from app.rule_lookup import Context, resolve_groups

logger = logging.getLogger(__name__)

_store: dict = {}
_lock = threading.Lock()
_building: set = set()


def get_adom(adom: str) -> dict | None:
    """Return a shallow copy of an ADOM's cache entry, or None if never built."""
    with _lock:
        entry = _store.get(adom)
        return dict(entry) if entry else None


def is_stale(entry: dict) -> bool:
    """True when an entry is older than the refresh interval and not being rebuilt.

    The cache is per-process memory. In the split web/collector deployment the
    collector's scheduler cannot warm the web workers' copy, so the search route
    uses this to rebuild lazily (serving the stale data meanwhile).
    """
    if entry.get("status") == "running" or not entry.get("last_updated"):
        return False
    interval_min = int(os.environ.get("RULE_LOOKUP_CACHE_INTERVAL_MIN", "60"))
    age = datetime.now(UTC) - datetime.fromisoformat(entry["last_updated"])
    return age.total_seconds() > interval_min * 60


def _names(val) -> list[str]:
    if not val:
        return []
    if isinstance(val, str):
        return [val]
    return [(i.get("name", str(i)) if isinstance(i, dict) else str(i)) for i in val]


def _flag(val) -> bool:
    return val in (1, "enable", True)


def _record(
    adom: str, pkg_path: str, firewalls: list[str], p: dict, block: str
) -> dict:
    return {
        "adom": adom,
        "package": pkg_path,
        "firewalls": firewalls,
        "policyid": p.get("policyid", ""),
        "name": p.get("name") or "",
        "status": _status(p),
        "action": _action(p),
        "srcintf": _names(p.get("srcintf")),
        "dstintf": _names(p.get("dstintf")),
        "srcaddr": _names(p.get("srcaddr")),
        "dstaddr": _names(p.get("dstaddr")),
        "service": _names(p.get("service")),
        "srcaddr_negate": _flag(p.get("srcaddr-negate")),
        "dstaddr_negate": _flag(p.get("dstaddr-negate")),
        "comment": p.get("comments") or p.get("comment") or "",
        "policy_block": block,
    }


def _firewalls(pkg: dict) -> list[str]:
    out = []
    for m in pkg.get("scope member") or []:
        if isinstance(m, dict) and m.get("name"):
            out.append(f"{m['name']} / {m.get('vdom') or 'root'}")
    return out


def _fetch_package(adom: str, pkg: dict) -> tuple[list[dict], list[str]]:
    """Return (rules, errors); a failed policy block is an error, not silence."""
    pkg_path = pkg.get("path") or pkg.get("name", "")
    firewalls = _firewalls(pkg)
    rules: list[dict] = []
    errors: list[str] = []
    with make_client() as client:
        for p in client.get_policies(adom, pkg_path):
            if not isinstance(p, dict):
                continue
            block = str(p.get("_policy_block") or "").strip()
            if block:
                try:
                    block_rules = client.get_pblock_policies(adom, block, strict=True)
                except Exception as exc:
                    errors.append(
                        f"{pkg.get('name')}: policy block {block} failed: {exc}"
                    )
                    continue
                for bp in block_rules:
                    if isinstance(bp, dict):
                        rules.append(_record(adom, pkg_path, firewalls, bp, block))
                continue
            rules.append(_record(adom, pkg_path, firewalls, p, ""))
    return rules, errors


def _build_adom(adom: str) -> dict:
    from app.routes.hygiene_routes import build_addr_resolver

    with make_client() as client:
        all_pkgs = client.get_policy_packages(adom)
        addr_objects = client.get_address_objects(adom, scope="all") or []
        addr_groups = client.get_address_groups(adom, scope="all") or []
        vip_objects = client.get_vip_objects(adom) or []
        svc_objects = client.get_service_objects(adom, scope="all") or []
        svc_groups = client.get_service_groups(adom, scope="all") or []

    pkgs = [
        p
        for p in all_pkgs
        if isinstance(p, dict)
        and (p.get("type") or "").lower() != "folder"
        and p.get("name")
    ]

    rules: list[dict] = []
    package_errors: list[str] = []

    def _work(pkg):
        try:
            pkg_rules, errs = _fetch_package(adom, pkg)
            return pkg_rules, errs
        except Exception as exc:
            return [], [f"{pkg.get('name')}: {exc}"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        for pkg_rules, errs in pool.map(_work, pkgs):
            package_errors.extend(errs)
            rules.extend(pkg_rules)

    return {
        "rules": rules,
        "ctx": Context(
            addr=resolve_groups(
                build_addr_resolver(addr_objects, [], vip_objects), addr_groups
            ),
            svc=ServiceCatalog(svc_objects, svc_groups),
            svc_names={
                o["name"].lower(): o["name"]
                for o in svc_objects + svc_groups
                if isinstance(o, dict) and o.get("name")
            },
        ),
        "package_errors": package_errors,
    }


def refresh_adom(adom: str) -> None:
    """Rebuild one ADOM's entry (blocking). A failure keeps any previous data."""
    with _lock:
        if adom in _building:
            return
        _building.add(adom)
        if adom in _store:
            _store[adom] = {**_store[adom], "status": "running"}
    try:
        built = _build_adom(adom)
        with _lock:
            _store[adom] = {
                **built,
                "last_updated": datetime.now(UTC).isoformat(),
                "status": "ok",
                "error": None,
            }
    except Exception as exc:
        logger.exception("rule_lookup_cache: %s refresh failed", adom)
        with _lock:
            old = _store.get(adom) or {
                "rules": [],
                "ctx": Context(addr={}, svc=ServiceCatalog([], [])),
                "package_errors": [],
                "last_updated": None,
            }
            _store[adom] = {**old, "status": "error", "error": str(exc)}
    finally:
        with _lock:
            _building.discard(adom)


def refresh_adom_async(adom: str) -> None:
    threading.Thread(
        target=refresh_adom, args=[adom], name=f"rule_lookup_{adom}", daemon=True
    ).start()


def _run_job(app) -> None:
    try:
        with make_client() as client:
            adoms = [
                a.get("name", "")
                for a in client.get_adoms()
                if isinstance(a, dict) and a.get("name")
            ]
    except Exception:
        logger.exception("rule_lookup_cache: could not list ADOMs")
        return
    for name in adoms:
        if not name.lower().startswith("forti"):
            refresh_adom(name)


def init_scheduler(app):
    """Start the interval scheduler and fire an immediate warm-up."""
    from apscheduler.schedulers.background import BackgroundScheduler

    interval_min = int(os.environ.get("RULE_LOOKUP_CACHE_INTERVAL_MIN", "60"))
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_job,
        args=[app],
        trigger="interval",
        minutes=interval_min,
        id="rule_lookup_cache_refresh",
        name="Rule lookup cache refresh",
    )
    scheduler.start()
    logger.info("rule_lookup_cache: scheduler started — every %d minutes", interval_min)
    threading.Thread(
        target=_run_job, args=[app], name="rule_lookup_cache_startup", daemon=True
    ).start()
    return scheduler
