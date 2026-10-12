"""Authentication business logic and session lifecycle management."""

from datetime import datetime, timezone

from flask import session
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.user import User
from app.security.password_hashing import (
    hash_login_password,
    needs_rehash,
    verify_login_password,
)


class AuthError(Exception):
    """Base exception for authentication failures."""

    def __init__(self, message: str, status_code: int = 400, code: str = "AUTH_ERROR"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class AccountConflictError(AuthError):
    """Raised when an account cannot be registered due to a conflict."""

    def __init__(self):
        super().__init__(
            "Unable to register account with the provided credentials.",
            status_code=409,
            code="ACCOUNT_CONFLICT",
        )


class AuthenticationFailedError(AuthError):
    """Raised when login credentials are invalid or account is disabled."""

    def __init__(self):
        super().__init__(
            "Invalid email or account password.",
            status_code=401,
            code="INVALID_CREDENTIALS",
        )


def register_user(email: str, login_password: str) -> User:
    """Create a new user account with an Argon2id password hash."""
    normalized_email = email.strip().lower()
    existing = User.query.filter_by(email=normalized_email).first()
    if existing is not None:
        # Hash password anyway to equalize response timing against enumeration
        hash_login_password(login_password)
        raise AccountConflictError()

    password_hash = hash_login_password(login_password)
    user = User(
        email=normalized_email,
        login_password_hash=password_hash,
        is_active=True,
    )
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise AccountConflictError() from exc

    return user


def authenticate_user(email: str, login_password: str) -> User:
    """Authenticate a user by email and Argon2id password hash in constant time."""
    normalized_email = email.strip().lower()
    user = User.query.filter_by(email=normalized_email).first()

    stored_hash = user.login_password_hash if user is not None else None
    is_valid = verify_login_password(stored_hash, login_password)

    if not is_valid or user is None or not user.is_active or user.disabled_at is not None:
        raise AuthenticationFailedError()

    if needs_rehash(user.login_password_hash):
        user.login_password_hash = hash_login_password(login_password)
        db.session.commit()

    return user


def establish_authenticated_session(user: User) -> None:
    """Rotate session state on authentication to prevent session fixation."""
    from flask import g

    session.clear()
    g.pop("csrf_token", None)
    g.pop("current_user", None)
    session.permanent = True
    session["user_id"] = user.id
    session["authenticated_at"] = datetime.now(timezone.utc).isoformat()
    session.modified = True


def terminate_session() -> None:
    """Invalidate the current server-side session."""
    from flask import g

    session.clear()
    g.pop("csrf_token", None)
    g.pop("current_user", None)
    session.modified = True
