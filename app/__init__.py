from flask import Flask, jsonify, request, session
from werkzeug.exceptions import RequestEntityTooLarge

from app.config import Config
from app.security import csrf_error_response, ensure_csrf_token, validate_csrf_request

# Blueprint modules to import — each one calls registry.register() at import
# time.  To add a new module, append its dotted path here and nothing else.
_BLUEPRINT_MODULES = [
    "app.routes.auth_routes",
    "app.routes.dashboard_routes",
    "app.routes.api_routes",
    "app.routes.admin_routes",
    "app.routes.hygiene_routes",
    "app.routes.device_review_routes",
    "app.routes.psirt_routes",
    "app.routes.rule_review_routes",
    "app.routes.zone_routes",
    "app.routes.pending_changes_routes",
    "app.routes.map_routes",
    "app.routes.external_api_routes",
    "app.routes.backup_routes",
    # "app.routes.my_new_module",  ← add future modules here
]


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    @app.before_request
    def _security_filters():
        ensure_csrf_token()
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if request.endpoint == "static":
                return None
            # External API uses bearer-token auth — no CSRF cookie available
            if request.path.startswith("/external/api/"):
                return None
            if not validate_csrf_request():
                return csrf_error_response()
        return None

    @app.after_request
    def _set_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob: https://*.tile.openstreetmap.org; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
        if request.is_secure or forwarded_proto.lower() == "https":
            resp.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return resp

    @app.errorhandler(RequestEntityTooLarge)
    def _file_too_large(_exc):
        if (
            request.path.startswith("/api/")
            or request.path.startswith("/admin/api/")
            or request.path.startswith("/external/api/")
        ):
            return jsonify({"error": "Uploaded file is too large"}), 413
        return "Uploaded file is too large", 413

    # Import every blueprint module (triggers registry.register() calls)
    # then pull the bp object out and register it with Flask.
    import importlib

    for module_path in _BLUEPRINT_MODULES:
        mod = importlib.import_module(module_path)
        if hasattr(mod, "bp"):
            app.register_blueprint(mod.bp)

    # Sync KNOWN_TABS from the registry so groups.py and the Admin UI
    # always reflect whatever tabs are currently registered.
    from app import groups, registry

    groups.KNOWN_TABS = registry.known_tabs()

    # Start background jobs — guard against re-registration on Flask debug reload.
    if not app.config.get("TESTING") and not app.config.get("_SUMMARY_STARTED"):
        app.config["_SUMMARY_STARTED"] = True
        from app.summary_job import init_scheduler

        init_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get("_VERSIONS_CACHE_STARTED"):
        app.config["_VERSIONS_CACHE_STARTED"] = True
        from app.versions_cache import init_scheduler as init_versions_scheduler

        init_versions_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get("_ADOM_CACHE_STARTED"):
        app.config["_ADOM_CACHE_STARTED"] = True
        from app.adom_cache import init_scheduler as init_adom_scheduler

        init_adom_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get("_MAP_CACHE_STARTED"):
        app.config["_MAP_CACHE_STARTED"] = True
        from app.map_cache import init_scheduler as init_map_scheduler

        init_map_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get("_INFRA_HEALTH_STARTED"):
        app.config["_INFRA_HEALTH_STARTED"] = True
        from app.infra_health_cache import init_scheduler as init_infra_health_scheduler

        init_infra_health_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get("_HOST_METRICS_STARTED"):
        app.config["_HOST_METRICS_STARTED"] = True
        from app.host_metrics import init_scheduler as init_host_metrics_scheduler

        init_host_metrics_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get("_AI_USAGE_PRUNE_STARTED"):
        app.config["_AI_USAGE_PRUNE_STARTED"] = True
        from app.ai_usage import init_scheduler as init_ai_usage_scheduler

        init_ai_usage_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get(
        "_PENDING_STATUS_CACHE_STARTED"
    ):
        app.config["_PENDING_STATUS_CACHE_STARTED"] = True
        from app.pending_status_cache import (
            init_scheduler as init_pending_status_scheduler,
        )

        init_pending_status_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get(
        "_EXEC_SUMMARY_CACHE_STARTED"
    ):
        app.config["_EXEC_SUMMARY_CACHE_STARTED"] = True
        from app.executive_summary_cache import (
            init_scheduler as init_exec_summary_scheduler,
        )

        init_exec_summary_scheduler(app)

    if not app.config.get("TESTING") and not app.config.get(
        "_CONFIG_DIFF_SCHEDULER_STARTED"
    ):
        app.config["_CONFIG_DIFF_SCHEDULER_STARTED"] = True
        try:
            from app.config_diff_scheduler import (
                init_scheduler as init_config_diff_scheduler,
            )

            with app.app_context():
                init_config_diff_scheduler(app)
        except Exception as exc:
            app.logger.warning("Config-Diff scheduler failed to start: %s", exc)

    if not app.config.get("TESTING") and not app.config.get("_DR_SCHEDULER_STARTED"):
        app.config["_DR_SCHEDULER_STARTED"] = True
        try:
            from app.device_review_scheduler import (
                init_scheduler as init_dr_scheduler,
            )

            with app.app_context():
                init_dr_scheduler(app)
        except Exception as exc:
            app.logger.warning("Device Review scheduler failed to start: %s", exc)

    if not app.config.get("TESTING") and not app.config.get("_RH_SCHEDULER_STARTED"):
        app.config["_RH_SCHEDULER_STARTED"] = True
        try:
            from app.rule_hygiene_scheduler import (
                init_scheduler as init_rh_scheduler,
            )

            with app.app_context():
                init_rh_scheduler(app)
        except Exception as exc:
            app.logger.warning("Rule Hygiene scheduler failed to start: %s", exc)

    if not app.config.get("TESTING") and not app.config.get(
        "_BACKUP_SCHEDULER_STARTED"
    ):
        app.config["_BACKUP_SCHEDULER_STARTED"] = True
        try:
            from app.backup_scheduler import (
                init_scheduler as init_backup_scheduler,
            )

            with app.app_context():
                init_backup_scheduler(app)
        except Exception as exc:
            app.logger.warning("Backup scheduler failed to start: %s", exc)

    @app.context_processor
    def inject_session_globals():
        role = session.get("role", "viewer")
        # Admins always get all currently-registered tabs so new tabs appear
        # immediately without requiring a logout/login cycle.
        if role == "admin":
            allowed = set(registry.known_tabs().keys())
        else:
            allowed = set(session.get("allowed_tabs", []))
        return {
            "current_role": role,
            "allowed_tabs": allowed,
            "nav_registry": registry.get_registry(),
            "csrf_token": ensure_csrf_token(),
        }

    return app
