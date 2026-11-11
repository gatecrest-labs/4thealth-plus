"""What each job kind does (F6). Pure functions over a stored request.

``prepare(kind, data)`` validates a request body and returns ``(adom, request)``
(raises ``ValueError`` with a user-safe message); ``run(kind, request, progress,
should_cancel)`` executes it and returns ``(result, cancelled)``. Both reuse the
exact code the interactive endpoints run (``compute_device_review``,
``compute_hygiene_run``), so a job's result equals the synchronous response.
"""

from __future__ import annotations

KINDS = ("device_review", "hygiene_run")

# the tab that must be allowed to create/read a job of this kind
KIND_TAB = {"device_review": "audit_review", "hygiene_run": "audit_review"}


def prepare(kind: str, data: dict) -> tuple[str, dict]:
    if kind not in KINDS:
        raise ValueError(f"unknown job kind {kind!r}")
    adom = str(data.get("adom") or "").strip()
    if not adom:
        raise ValueError("adom is required")
    if kind == "device_review":
        from app.device_review import CHECKS_META

        valid = {c["key"] for c in CHECKS_META}
        checks = data.get("checks")
        if checks is not None:
            checks = [k for k in checks if k in valid]
            if not checks:
                raise ValueError("No valid check keys provided")
        devices = [str(d) for d in (data.get("devices") or [])]
        params = data.get("check_params")
        return adom, {
            "devices": devices,
            "checks": checks,
            "check_params": params if isinstance(params, dict) else {},
            "live": bool(data.get("live")),
        }
    from app.hygiene import CHECKS

    path = str(data.get("path") or data.get("package") or "").strip()
    if not path:
        raise ValueError("package is required")
    wanted = data.get("checks", list(CHECKS.keys()))
    checks = [c for c in wanted if c in CHECKS]
    if not checks:
        raise ValueError("No valid check keys provided")
    return adom, {"path": path, "checks": checks}


def run(
    kind: str, adom: str, request: dict, progress, should_cancel
) -> tuple[dict | None, bool]:
    if kind == "device_review":
        from app.routes.audit_review_routes import compute_device_review

        result = compute_device_review(
            adom,
            request.get("devices") or [],
            request.get("checks"),
            request.get("check_params") or {},
            bool(request.get("live")),
            progress=progress,
            should_cancel=should_cancel,
        )
        return result, bool(result.get("cancelled"))
    if kind == "hygiene_run":
        from app.routes.hygiene_routes import compute_hygiene_run

        if should_cancel():
            return None, True
        progress(0, 1, request["path"].rsplit("/", 1)[-1])
        result = compute_hygiene_run(adom, request["path"], request["checks"])
        progress(1, 1, "done")
        return result, False
    raise ValueError(f"unknown job kind {kind!r}")
