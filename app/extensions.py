"""Flask extension instances initialized via the application factory."""

from flask import request
from flask_limiter import Limiter
from flask_migrate import Migrate
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect


def get_client_ip() -> str:
    """Resolve client IP address safely after ProxyFix middleware processing."""
    return request.remote_addr or "127.0.0.1"


db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
server_session = Session()
limiter = Limiter(
    key_func=get_client_ip,
    default_limits=["120 per minute"],
    headers_enabled=True,
)
