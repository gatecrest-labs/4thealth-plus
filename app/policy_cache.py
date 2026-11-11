"""Collector-owned policy and object refresh (F3).

Per cycle (``POLICY_STORE`` on): list each ADOM's packages, then fetch the
policies of every package whose stored row is missing, failed or older than its
jittered TTL (fingerprint unchanged -> only the age is refreshed), plus the
policy blocks those packages reference. Firewall objects are refreshed on their
own, slower job: the shared global objects once, each ADOM's local ones once.

Every read is strict, so a swallowed FMG error is never stored as "empty". A
failed fetch keeps the previous row and flags it. An answer that would empty a
previously non-empty list (packages of an ADOM, a package's policies, an object
table) is held back once and only accepted if the very next answer agrees, so a
transient empty reply cannot wipe good data.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from app import boot_warmup, inventory, policy_store
from app.config import Config
from app.policy_store import KINDS, fingerprint_of

logger = logging.getLogger(__name__)

_CYCLE_SECONDS = 900
_REQUESTS_PER_TICK = 20
_EMPTY_PENDING = "empty answer pending confirmation"
_GLOBAL_KINDS = ("address", "addrgrp", "vip", "ippool")

_running = threading.Lock()
_req_lock = threading.Lock()
_empty_list_seen: set[str] = set()  # ADOMs whose package list came back empty once


def _make_client():
    from app.fmg_helpers import make_client

    return make_client()


def _make_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler

    return BackgroundScheduler()


def _non_forti(adoms) -> list[str]:
    return [
        a["name"]
        for a in adoms
        if isinstance(a, dict)
        and a.get("name")
        and not a["name"].lower().startswith("forti")
    ]


def _pending_confirmation(prev: dict | None) -> bool:
    return bool(
        prev
        and prev.get("status") == "error"
        and (prev.get("error") or "").startswith(_EMPTY_PENDING)
    )


# ── packages ─────────────────────────────────────────────────────────────────


def _fetch_package(client, adom: str, path: str, prev: dict | None):
    """Fetch and store one package. Returns ``("ok"|"kept", policies|None)``; raises on FMG failure."""
    policies = client.get_policies(adom, path)
    if (
        not policies
        and prev
        and (prev.get("policy_count") or 0) > 0
        and not _pending_confirmation(prev)
    ):
        policy_store.mark_policies_error(adom, path, _EMPTY_PENDING)
        return "kept", None
    fp = fingerprint_of(policies)
    if prev and prev.get("fingerprint") == fp:
        policy_store.touch_policies(adom, path)
    else:
        policy_store.put_policies(adom, path, policies, fp)
    return "ok", policies


def _referenced_blocks(policies) -> set[str]:
    return {
        str(p.get("_policy_block")).strip()
        for p in policies or []
        if isinstance(p, dict) and str(p.get("_policy_block") or "").strip()
    }


def _refresh_blocks(client, adom: str, new_refs: set[str], failed: list[str]) -> None:
    meta = {m["block"]: m for m in policy_store.block_meta(adom)}
    for block in sorted(new_refs | set(meta)):
        m = meta.get(block)
        due = (
            m is None
            or m["status"] != "ok"
            or m["age_seconds"] is None
            or m["age_seconds"]
            >= policy_store.effective_ttl_seconds(adom, f"block:{block}")
        )
        if not due:
            continue
        try:
            rules = client.get_pblock_policies(adom, block, strict=True)
            fp = fingerprint_of(rules)
            if m and m.get("fingerprint") == fp:
                policy_store.touch_block(adom, block)
            else:
                policy_store.put_block(adom, block, rules, fp)
        except Exception as exc:
            logger.warning(
                "policy_cache: policy block %s/%s failed: %s", adom, block, exc
            )
            policy_store.mark_block_error(adom, block, str(exc))
            failed.append(f"{adom}/block:{block}")


def _refresh_adom(client, adom: str, stats: dict, failed: list[str]) -> None:
    try:
        entries = client.get_policy_packages(adom, strict=True)
    except Exception as exc:
        logger.warning("policy_cache: package list for %s failed: %s", adom, exc)
        failed.append(f"{adom} (package list: {exc})")
        return
    previous = policy_store.get_packages(adom)
    if (
        not entries
        and previous
        and previous["entries"]
        and adom not in _empty_list_seen
    ):
        _empty_list_seen.add(adom)
        failed.append(f"{adom} (package list: {_EMPTY_PENDING})")
        return
    _empty_list_seen.discard(adom)
    policy_store.put_packages(adom, entries)
    paths = [e["path"] for e in entries if isinstance(e, dict) and e.get("path")]
    meta = {m["pkg"]: m for m in policy_store.package_meta(adom)}
    due: list[str] = []
    for path in paths:
        m = meta.get(path)
        fresh = (
            m is not None
            and m["status"] == "ok"
            and m["age_seconds"] is not None
            and m["age_seconds"] < policy_store.effective_ttl_seconds(adom, path)
        )
        if fresh:
            stats["reused"] += 1
        else:
            due.append(path)

    def _work(path: str):
        try:
            return _fetch_package(client, adom, path, meta.get(path))
        except Exception as exc:
            return exc

    workers = max(1, int(Config.POLICY_PARALLEL_FETCH or 1))
    new_refs: set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(_work, due))
    for path, outcome in zip(due, outcomes, strict=True):
        if isinstance(outcome, Exception):
            logger.warning("policy_cache: %s/%s failed: %s", adom, path, outcome)
            policy_store.mark_policies_error(adom, path, str(outcome))
            failed.append(f"{adom}/{path}")
            continue
        status, policies = outcome
        stats["fetched"] += 1
        if status == "kept":
            failed.append(f"{adom}/{path} ({_EMPTY_PENDING})")
        else:
            new_refs |= _referenced_blocks(policies)
    policy_store.delete_missing_packages(adom, set(paths))
    _refresh_blocks(client, adom, new_refs, failed)
    stats["packages"] += len(paths)


def _refresh(client) -> dict:
    started = time.monotonic()
    adoms = inventory.adoms(client) or []
    names = _non_forti(adoms)
    if not adoms and policy_store.known_adoms():
        raise RuntimeError(
            "FortiManager returned an empty ADOM list; keeping the previous policy store"
        )
    stats = {"packages": 0, "fetched": 0, "reused": 0}
    failed: list[str] = []
    for adom in names:
        _refresh_adom(client, adom, stats, failed)
    policy_store.delete_missing_adoms(set(names))
    return {
        "adoms": len(names),
        **stats,
        "failed": failed,
        "seconds": round(time.monotonic() - started, 2),
    }


def refresh_once(client=None) -> dict:
    """Refresh packages, policies and policy blocks once. Single-flight."""
    if not _running.acquire(blocking=False):
        return {"skipped": True}
    try:
        if client is not None:
            result = _refresh(client)
        else:
            with _make_client() as live:
                result = _refresh(live)
        logger.info("policy_cache: refreshed %s", result)
        return result
    finally:
        _running.release()


# ── objects ──────────────────────────────────────────────────────────────────


def _refresh_object(client, scope_key: str, kind: str, call_adom: str) -> str | None:
    """Refresh one object table; returns an error label on failure."""
    try:
        scope = "global" if scope_key == policy_store.GLOBAL_KEY else "local"
        items = client.get_objects(call_adom, kind, scope, True)
        prev = policy_store.get_objects(scope_key, kind)
        if not items and prev and prev["objects"] and not _pending_confirmation(prev):
            policy_store.mark_objects_error(scope_key, kind, _EMPTY_PENDING)
            return f"{scope_key}/{kind} ({_EMPTY_PENDING})"
        fp = fingerprint_of(items)
        if prev and prev["fingerprint"] == fp:
            policy_store.touch_objects(scope_key, kind)
        else:
            policy_store.put_objects(scope_key, kind, items, fp)
        return None
    except Exception as exc:
        logger.warning("policy_cache: objects %s/%s failed: %s", scope_key, kind, exc)
        policy_store.mark_objects_error(scope_key, kind, str(exc))
        return f"{scope_key}/{kind}"


def _refresh_objects(client) -> dict:
    started = time.monotonic()
    names = _non_forti(inventory.adoms(client) or [])
    jobs: list[tuple[str, str, str]] = []
    first = names[0] if names else "root"
    jobs += [(policy_store.GLOBAL_KEY, kind, first) for kind in _GLOBAL_KINDS]
    jobs += [(adom, kind, adom) for adom in names for kind in KINDS]
    workers = max(1, int(Config.POLICY_PARALLEL_FETCH or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        errors = list(pool.map(lambda j: _refresh_object(client, *j), jobs))
    return {
        "adoms": len(names),
        "tables": len(jobs),
        "failed": [e for e in errors if e],
        "seconds": round(time.monotonic() - started, 2),
    }


def refresh_objects(client=None) -> dict:
    if client is not None:
        return _refresh_objects(client)
    with _make_client() as live:
        return _refresh_objects(live)


# ── refresh requests (the Refresh button) ────────────────────────────────────


def process_refresh_requests(client=None) -> int:
    """Fetch the packages users asked to refresh (bypassing the TTL). Returns how many."""
    with _req_lock:
        requests = policy_store.pop_refresh_requests(_REQUESTS_PER_TICK)
        if not requests:
            return 0
        own = client is None
        live = _make_client() if own else client
        try:
            if own:
                live.__enter__()
            for adom, pkg in requests:
                meta = {m["pkg"]: m for m in policy_store.package_meta(adom)}
                try:
                    status, policies = _fetch_package(live, adom, pkg, meta.get(pkg))
                    if status == "ok":
                        _refresh_blocks(live, adom, _referenced_blocks(policies), [])
                except Exception as exc:
                    logger.warning(
                        "policy_cache: requested refresh %s/%s failed: %s",
                        adom,
                        pkg,
                        exc,
                    )
                    policy_store.mark_policies_error(adom, pkg, str(exc))
            return len(requests)
        finally:
            if own:
                live.__exit__(None, None, None)


# ── scheduling ───────────────────────────────────────────────────────────────


def _guarded(fn, label: str) -> None:
    try:
        fn()
    except Exception:
        logger.exception("policy_cache: %s failed", label)


def _run_refresh(app=None) -> None:
    _guarded(refresh_once, "refresh")


def _run_objects(app=None) -> None:
    _guarded(refresh_objects, "object refresh")


def _poll_requests() -> None:
    _guarded(process_refresh_requests, "request poll")


def _first_run(app) -> None:
    _run_objects(app)
    _run_refresh(app)


def init_scheduler(app) -> bool:
    """Register the refresh jobs (collector only, ``POLICY_STORE`` on)."""
    if not Config.POLICY_STORE:
        return False
    scheduler = _make_scheduler()
    scheduler.add_job(
        func=_run_refresh,
        args=[app],
        trigger="interval",
        seconds=_CYCLE_SECONDS,
        id="policy_refresh",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        func=_run_objects,
        args=[app],
        trigger="interval",
        minutes=max(1, int(Config.POLICY_OBJECTS_REFRESH_MINUTES)),
        id="policy_objects_refresh",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        func=_poll_requests,
        trigger="interval",
        seconds=10,
        id="policy_refresh_request_poll",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    boot_warmup.defer("policy_cache", lambda: _first_run(app), 3)
    return True
