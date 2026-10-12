"""Marshmallow request validation schemas for authentication endpoints."""

from marshmallow import (
    RAISE,
    Schema,
    ValidationError,
    fields,
    pre_load,
    validate,
    validates_schema,
)

FORBIDDEN_SERVER_FIELDS = {
    "master_password",
    "vault_master_password",
    "vek",
    "raw_vek",
    "wrapping_key",
    "plaintext",
}


class BaseStrictSchema(Schema):
    """Base schema that rejects unknown fields and forbidden client-only secrets."""

    class Meta:
        unknown = RAISE

    @pre_load
    def reject_forbidden_secrets(self, data, **kwargs):
        if not isinstance(data, dict):
            raise ValidationError("Request payload must be a JSON object.")
        present_forbidden = FORBIDDEN_SERVER_FIELDS.intersection(data.keys())
        if present_forbidden:
            raise ValidationError(
                "Forbidden client-side secret field included in server payload."
            )
        return data


class RegisterSchema(BaseStrictSchema):
    """Validates account registration payload."""

    email = fields.Email(
        required=True,
        validate=validate.Length(min=5, max=254),
    )
    login_password = fields.String(
        required=True,
        load_only=True,
        validate=validate.Length(
            min=10,
            max=256,
            error="Account password must be between 10 and 256 characters.",
        ),
    )

    @pre_load
    def normalize_email(self, data, **kwargs):
        if isinstance(data, dict) and isinstance(data.get("email"), str):
            data = dict(data)
            data["email"] = data["email"].strip().lower()
        return data

    @validates_schema
    def validate_password_strength(self, data, **kwargs):
        password = data.get("login_password", "")
        email = data.get("email", "")
        if any(ord(ch) < 32 for ch in password):
            raise ValidationError(
                {"login_password": ["Password must not contain control characters."]}
            )
        if email and password.strip().lower() == email:
            raise ValidationError(
                {"login_password": ["Account password must not match your email address."]}
            )


class LoginSchema(BaseStrictSchema):
    """Validates account login payload."""

    email = fields.Email(
        required=True,
        validate=validate.Length(min=5, max=254),
    )
    login_password = fields.String(
        required=True,
        load_only=True,
        validate=validate.Length(min=1, max=256),
    )

    @pre_load
    def normalize_email(self, data, **kwargs):
        if isinstance(data, dict) and isinstance(data.get("email"), str):
            data = dict(data)
            data["email"] = data["email"].strip().lower()
        return data
