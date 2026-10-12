"""Application configuration classes and environment validation."""

import os
from datetime import timedelta
from pathlib import Path

import fakeredis
import redis

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"

PLACEHOLDER_SECRETS = {
    "",
    "dev-secret-key",
    "change-me",
    "replace-with-64-char-cryptographically-random-hex-secret-key",
}


class BaseConfig:
    """Base configuration shared across environments."""

    APP_NAME = "AegisVault"
    SECRET_KEY = os.environ.get("SECRET_KEY", "")

    # SQLAlchemy settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }

    # Request payload limit: 512 KB default to prevent memory exhaustion DoS
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 512 * 1024))

    # Session configuration (Flask-Session with Redis)
    SESSION_TYPE = "redis"
    SESSION_PERMANENT = True
    SESSION_KEY_PREFIX = "aegisvault:session:"
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get("SESSION_LIFETIME_MINUTES", "30"))
    )
    SESSION_COOKIE_NAME = "aegisvault_sid"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    )

    # CSRF configuration (Flask-WTF)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = False
    WTF_CSRF_HEADERS = ["X-CSRF-Token"]
    WTF_CSRF_CHECK_DEFAULT = True

    # Rate Limiting (Flask-Limiter)
    RATELIMIT_ENABLED = True
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_DEFAULT = "120 per minute"
    RATELIMIT_SWALLOW_ERRORS = False

    # Reverse proxy configuration
    TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "1"))

    # Frame ancestors policy (DENY by default; configurable for preview iframe)
    CSP_FRAME_ANCESTORS = os.environ.get("CSP_FRAME_ANCESTORS", "'none'")


class DevelopmentConfig(BaseConfig):
    """Local development configuration."""

    DEBUG = True
    TESTING = False
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-only-local-secret-key-do-not-use-in-production-9f8e7d6c5b4a3",
    )
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{INSTANCE_DIR / 'aegisvault_dev.db'}",
    )
    REDIS_URL = os.environ.get("REDIS_URL", " memory://")
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")


class TestingConfig(BaseConfig):
    """Automated testing configuration."""

    DEBUG = False
    TESTING = True
    SECRET_KEY = "test-only-secret-key-with-sufficient-entropy-for-signing-sessions"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"


class ProductionConfig(BaseConfig):
    """Production configuration with mandatory security enforcement."""

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
    )
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "")
    REDIS_URL = os.environ.get("REDIS_URL", "")
    RATELIMIT_STORAGE_URI = os.environ.get(
        "RATELIMIT_STORAGE_URI", os.environ.get("REDIS_URL", "")
    )


def validate_production_config(app_config: dict) -> None:
    """Validate that mandatory production secrets and URLs are present and non-default."""
    secret_key = (app_config.get("SECRET_KEY") or "").strip()
    if secret_key in PLACEHOLDER_SECRETS or len(secret_key) < 32:
        raise RuntimeError(
            "Production startup aborted: SECRET_KEY must be set to a strong random value "
            "of at least 32 characters."
        )

    db_uri = (app_config.get("SQLALCHEMY_DATABASE_URI") or "").strip()
    if not db_uri or "replace-with-" in db_uri or db_uri.startswith("sqlite"):
        raise RuntimeError(
            "Production startup aborted: DATABASE_URL must point to a configured "
            "MariaDB database without placeholder credentials."
        )

    redis_url = (app_config.get("REDIS_URL") or "").strip()
    if not redis_url or "replace-with-" in redis_url or not redis_url.startswith(("redis://", "rediss://")):
        raise RuntimeError(
            "Production startup aborted: REDIS_URL must point to a valid Redis instance."
        )


def build_redis_client(app_config: dict):
    """Create a Redis client for Flask-Session, falling back to FakeRedis in dev/test when configured."""
    if app_config.get("TESTING") or app_config.get("USE_FAKEREDIS"):
        return fakeredis.FakeStrictRedis()

    redis_url = (app_config.get("REDIS_URL") or "").strip()
    if redis_url.startswith(("redis://", "rediss://")):
        return redis.from_url(
            redis_url,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=False,
        )

    return fakeredis.FakeStrictRedis()


CONFIG_BY_NAME = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
