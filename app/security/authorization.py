"""Server-side authentication and resource ownership enforcement."""

from functools import wraps
from typing import Callable

from flask import g, jsonify, session

from app.extensions import db
from app.models.user import User


def get_Authenticated_user() -> User | None:
    """Retrieve and validate the currently authenticated user from the server session."""
    if hasattr(g, "current_user"):
        return g.current_user

    user_id = session.get("user_id")
    if not user_id or not isinstance(user_id, str):
        g.current_user = None
        return None

    user = db.session.get(User, user_id)
    if user is None or not user.is_active or user.disabled_at is not None:
        session.clear()
        g.current_user = None
        return None

    g.current_user = user
    return user


def login_required(fn: Callable) -> Callable:
    """Decorator enforcing an active authenticated server-side session."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_Authenticated_user()
        if user is None:
            return (
                jsonify(
                    {
                        "error": "Authentication required.",
                        "code": "UNAUTHORIZED",
                    }
                ),
                401,
            )
        return fn(*args, **kwargs)

    return wrapper


def verify_resource_ownership(resource_user_id: str, current_user_id: str) -> bool:
    """Verify that a database resource belongs to the authenticated user."""
    return (
        isinstance(resource_user_id, str)
        and isinstance(current_user_id, str)
        and resource_user_id == current_user_id
    )
