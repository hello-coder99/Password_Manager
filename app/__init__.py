"""Flask application factory and core API error/health handlers."""

import os
from typing import Any

from flask import Flask, g, jsonify, request
from flask_limiter.errors import RateLimitExceeded
from flask_wtf.csrf import CSRFError, generate_csrf
from marshmallow import ValidationError
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import BadRequest, HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from app.blueprints import auth_bp, vault_bp
from app.config import (
    CONFIG_BY_NAME,
    build_redis_client,
    validate_production_config,
)
from app.extensions import csrf, db, limiter, migrate, server_session
from app.security.headers import configure_security_headers
from app.services.auth_service import AuthError
from app.services.vault_service import VaultServiceError


class FailClosedSessionWrapper:
    """Wraps Flask-Session interface so Redis outages fail closed with HTTP 503."""

    def __init__(self, inner_interface):
        self._inner = inner_interface

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def open_session(self, app: Flask, req):
        try:
            redis_client = app.config.get("SESSION_REDIS")
            if redis_client is not None and req.path != "/api/health":
                redis_client.ping()
            return self._inner.open_session(app, req)
        except RedisError:
            req.environ["aegisvault.redis_error"] = True
            return self._inner.session_class()

    def save_session(self, app: Flask, sess, response):
        if request.environ.get("aegisvault.redis_error"):
            return
        try:
            return self._inner.save_session(app, sess, response)
        except RedisError:
            response.status_code = 503
            response.set_data(
                jsonify(
                    {
                        "error": "Session or rate-limit service is temporarily unavailable.",
                        "code": "REDIS_UNAVAILABLE",
                    }
                ).get_data()
            )
            response.mimetype = "application/json"


def create_app(
    config_name: str | None = None,
    config_overrides: dict[str, Any] | None = None,
) -> Flask:
    """Application factory creating and configuring the Flask instance."""
    app = Flask(__name__)

    env_name = (
        config_name
        or os.environ.get("FLASK_ENV")
        or "development"
    ).lower()
    config_cls = CONFIG_BY_NAME.get(env_name, CONFIG_BY_NAME["development"])
    app.config.from_object(config_cls)

    if config_overrides:
        app.config.update(config_overrides)

    if env_name == "production" and not app.config.get("TESTING"):
        validate_production_config(app.config)

    # Configure trusted reverse proxy headers (Nginx -> Gunicorn)
    proxy_count = int(app.config.get("TRUSTED_PROXY_COUNT", 1))
    if proxy_count > 0:
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app,
            x_for=proxy_count,
            x_proto=proxy_count,
            x_host=proxy_count,
            x_port=proxy_count,
        )

    # Configure Redis client for server-side sessions
    if "SESSION_REDIS" not in app.config or app.config["SESSION_REDIS"] is None:
        app.config["SESSION_REDIS"] = build_redis_client(app.config)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db, directory="app/migrations")
    csrf.init_app(app)
    server_session.init_app(app)
    app.session_interface = FailClosedSessionWrapper(app.session_interface)  # type: ignore[assignment]
    limiter.init_app(app)

    # Import models so SQLAlchemy metadata is registered
    from app import models as _models  # noqa: F401

    # Auto-create tables in development/testing SQLite if they don't exist yet
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        with app.app_context():
            db.create_all()

    # Apply security headers and log redaction
    configure_security_headers(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)

    # Register core routes and error handlers
    _register_core_routes(app)
    _register_error_handlers(app)

    return app


def _register_core_routes(app: Flask) -> None:
    """Register health check and CSRF bootstrap endpoints."""

    @app.before_request
    def check_redis_session_availability():
        if request.path == "/api/health":
            return None
        if request.environ.get("aegisvault.redis_error"):
            return (
                jsonify(
                    {
                        "error": "Session or rate-limit service is temporarily unavailable.",
                        "code": "REDIS_UNAVAILABLE",
                    }
                ),
                503,
            )
        return None

    @app.get("/api/health")
    @limiter.exempt
    def health_check():
        """Verify database and Redis connectivity for container orchestration."""
        db_ok = False
        redis_ok = False

        try:
            db.session.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False

        try:
            redis_client = app.config.get("SESSION_REDIS")
            if redis_client is not None and bool(redis_client.ping()):
                redis_ok = True
        except Exception:
            redis_ok = False

        overall_ok = db_ok and redis_ok
        status_code = 200 if overall_ok else 503
        return (
            jsonify(
                {
                    "status": "healthy" if overall_ok else "degraded",
                    "database": "connected" if db_ok else "unavailable",
                    "redis": "connected" if redis_ok else "unavailable",
                }
            ),
            status_code,
        )

    @app.get("/api/csrf-token")
    @limiter.limit("60 per minute")
    def get_csrf_token():
        """Issue a signed CSRF token bound to the current server-side session."""
        token = generate_csrf()
        return jsonify({"csrf_token": token}), 200


def _register_error_handlers(app: Flask) -> None:
    """Register uniform JSON error handlers that never leak sensitive internals."""

    @app.errorhandler(AuthError)
    def handle_auth_error(err: AuthError):
        return (
            jsonify({"error": err.message, "code": err.code}),
            err.status_code,
        )

    @app.errorhandler(VaultServiceError)
    def handle_vault_error(err: VaultServiceError):
        return (
            jsonify({"error": err.message, "code": err.code}),
            err.status_code,
        )

    @app.errorhandler(ValidationError)
    def handle_validation_error(err: ValidationError):
        return (
            jsonify(
                {
                    "error": "Request validation failed.",
                    "code": "VALIDATION_ERROR",
                    "details": err.messages,
                }
            ),
            422,
        )

    @app.errorhandler(CSRFError)
    def handle_csrf_error(err: CSRFError):
        return (
            jsonify(
                {
                    "error": "CSRF token is missing, invalid, or expired.",
                    "code": "CSRF_ERROR",
                }
            ),
            400,
        )

    @app.errorhandler(RequestEntityTooLarge)
    def handle_payload_too_large(err: RequestEntityTooLarge):
        return (
            jsonify(
                {
                    "error": "Request payload exceeds maximum allowed size.",
                    "code": "PAYLOAD_TOO_LARGE",
                }
            ),
            413,
        )

    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(err: RateLimitExceeded):
        return (
            jsonify(
                {
                    "error": "Too many requests. Please wait before retrying.",
                    "code": "RATE_LIMITED",
                }
            ),
            429,
        )

    @app.errorhandler(RedisError)
    def handle_redis_error(err: RedisError):
        return (
            jsonify(
                {
                    "error": "Session or rate-limit service is temporarily unavailable.",
                    "code": "REDIS_UNAVAILABLE",
                }
            ),
            503,
        )

    @app.errorhandler(BadRequest)
    def handle_bad_request(err: BadRequest):
        return (
            jsonify(
                {
                    "error": err.description or "Malformed request payload.",
                    "code": "BAD_REQUEST",
                }
            ),
            400,
        )

    @app.errorhandler(SQLAlchemyError)
    def handle_database_error(err: SQLAlchemyError):
        db.session.rollback()
        return (
            jsonify(
                {
                    "error": "A database error occurred while processing the request.",
                    "code": "DATABASE_ERROR",
                }
            ),
            500,
        )

    @app.errorhandler(HTTPException)
    def handle_http_exception(err: HTTPException):
        return (
            jsonify(
                {
                    "error": err.description or "HTTP error.",
                    "code": f"HTTP_{err.code or 500}",
                }
            ),
            err.code or 500,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_exception(err: Exception):
        app.logger.error("Unhandled exception type: %s", type(err).__name__)
        return (
            jsonify(
                {
                    "error": "An internal server error occurred.",
                    "code": "INTERNAL_ERROR",
                }
            ),
            500,
        )
