"""Authentication API blueprint (/api/auth)."""

from flask import Blueprint, g, jsonify, request
from flask_wtf.csrf import generate_csrf
from werkzeug.exceptions import BadRequest

from app.extensions import limiter
from app.schemas.auth import LoginSchema, RegisterSchema
from app.security.authorization import login_required
from app.services.auth_service import (
    authenticate_user,
    establish_authenticated_session,
    register_user,
    terminate_session,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

_register_schema = RegisterSchema()
_login_schema = LoginSchema()


def _parse_json_body() -> dict:
    """Safely parse JSON request body and reject non-dict payloads."""
    if not request.is_json:
        raise BadRequest("Content-Type must be application/json.")
    payload = request.get_json(silent=False)
    if not isinstance(payload, dict):
        raise BadRequest("Request body must be a JSON object.")
    return payload


@auth_bp.post("/register")
@limiter.limit("10 per minute")
def register():
    """Register a new user account and establish an authenticated session."""
    payload = _parse_json_body()
    validated = _register_schema.load(payload)

    user = register_user(
        email=validated["email"],
        login_password=validated["login_password"],
    )
    establish_authenticated_session(user)

    return (
        jsonify(
            {
                "message": "Account registered successfully.",
                "user": user.to_dict(),
                "csrf_token": generate_csrf(),
            }
        ),
        201,
    )


@auth_bp.post("/login")
@limiter.limit("10 per minute")
def login():
    """Authenticate an existing user and rotate the server-side session."""
    payload = _parse_json_body()
    validated = _login_schema.load(payload)

    user = authenticate_user(
        email=validated["email"],
        login_password=validated["login_password"],
    )
    establish_authenticated_session(user)

    return (
        jsonify(
            {
                "message": "Authenticated successfully.",
                "user": user.to_dict(),
                "csrf_token": generate_csrf(),
            }
        ),
        200,
    )


@auth_bp.post("/logout")
@limiter.limit("30 per minute")
@login_required
def logout():
    """Invalidate the current server-side session."""
    terminate_session()
    return (
        jsonify(
            {
                "message": "Logged out successfully.",
                "csrf_token": generate_csrf(),
            }
        ),
        200,
    )


@auth_bp.get("/me")
@limiter.limit("60 per minute")
@login_required
def current_user():
    """Return the authenticated user's profile and vault initialization status."""
    user = g.current_user
    return (
        jsonify(
            {
                "user": user.to_dict(),
            }
        ),
        200,
    )
