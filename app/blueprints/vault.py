"""Encrypted Vault API blueprint (/api/vault)."""

import uuid

from flask import Blueprint, g, jsonify, request
from werkzeug.exceptions import BadRequest

from app.extensions import limiter
from app.schemas.vault import (
    MasterPasswordChangeSchema,
    VaultImportSchema,
    VaultItemCreateSchema,
    VaultItemUpdateSchema,
    VaultSetupSchema,
)
from app.security.authorization import login_required
from app.services.vault_service import (
    VaultItemNotFoundError,
    VaultNotInitializedError,
    create_vault_item,
    delete_vault_item,
    export_encrypted_vault,
    get_vault_settings,
    import_encrypted_vault,
    initialize_vault,
    list_vault_items,
    update_master_password_envelope,
    update_vault_item,
)

vault_bp = Blueprint("vault", __name__, url_prefix="/api/vault")

_setup_schema = VaultSetupSchema()
_master_pw_change_schema = MasterPasswordChangeSchema()
_item_create_schema = VaultItemCreateSchema()
_item_update_schema = VaultItemUpdateSchema()
_import_schema = VaultImportSchema()


def _parse_json_body() -> dict:
    """Safely parse JSON request body and reject non-dict payloads."""
    if not request.is_json:
        raise BadRequest("Content-Type must be application/json.")
    payload = request.get_json(silent=False)
    if not isinstance(payload, dict):
        raise BadRequest("Request body must be a JSON object.")
    return payload


def _validate_item_uuid(item_id: str) -> str:
    """Validate path parameter item_id as a canonical UUID."""
    try:
        parsed = uuid.UUID(item_id)
        if str(parsed) != item_id.lower():
            raise VaultItemNotFoundError()
        return str(parsed)
    except ValueError as exc:
        raise VaultItemNotFoundError() from exc


@vault_bp.get("/settings")
@limiter.limit("60 per minute")
@login_required
def get_settings():
    """Return the user's KDF parameters and encrypted VEK envelope."""
    user = g.current_user
    settings = get_vault_settings(user)
    if settings is None:
        raise VaultNotInitializedError()
    return jsonify({"vault_settings": settings.to_dict()}), 200


@vault_bp.post("/setup")
@limiter.limit("15 per minute")
@login_required
def setup_vault():
    """Initialize encrypted vault settings and store the wrapped VEK."""
    user = g.current_user
    payload = _parse_json_body()
    validated = _setup_schema.load(payload)

    settings = initialize_vault(user, validated)
    return (
        jsonify(
            {
                "message": "Encrypted vault initialized.",
                "vault_settings": settings.to_dict(),
            }
        ),
        201,
    )


@vault_bp.put("/settings/master-password")
@limiter.limit("10 per minute")
@login_required
def change_master_password():
    """Update wrapped VEK, salt, and nonce after re-wrapping with a new master password."""
    user = g.current_user
    payload = _parse_json_body()
    validated = _master_pw_change_schema.load(payload)

    settings = update_master_password_envelope(user, validated)
    return (
        jsonify(
            {
                "message": "Master password envelope updated.",
                "vault_settings": settings.to_dict(),
            }
        ),
        200,
    )


@vault_bp.get("/items")
@limiter.limit("60 per minute")
@login_required
def get_items():
    """Return all encrypted vault items belonging to the authenticated user."""
    user = g.current_user
    items = list_vault_items(user)
    return (
        jsonify(
            {
                "items": [item.to_dict() for item in items],
                "count": len(items),
            }
        ),
        200,
    )


@vault_bp.post("/items")
@limiter.limit("60 per minute")
@login_required
def create_item():
    """Create a new encrypted vault item."""
    user = g.current_user
    payload = _parse_json_body()
    validated = _item_create_schema.load(payload)

    item = create_vault_item(user, validated)
    return (
        jsonify(
            {
                "message": "Encrypted item stored.",
                "item": item.to_dict(),
            }
        ),
        201,
    )


@vault_bp.put("/items/<string:item_id>")
@limiter.limit("60 per minute")
@login_required
def update_item(item_id: str):
    """Update an existing encrypted vault item owned by the user."""
    user = g.current_user
    canonical_id = _validate_item_uuid(item_id)
    payload = _parse_json_body()
    validated = _item_update_schema.load(payload)

    item = update_vault_item(user, canonical_id, validated)
    return (
        jsonify(
            {
                "message": "Encrypted item updated.",
                "item": item.to_dict(),
            }
        ),
        200,
    )


@vault_bp.delete("/items/<string:item_id>")
@limiter.limit("60 per minute")
@login_required
def delete_item(item_id: str):
    """Delete an encrypted vault item owned by the user."""
    user = g.current_user
    canonical_id = _validate_item_uuid(item_id)

    delete_vault_item(user, canonical_id)
    return (
        jsonify(
            {
                "message": "Encrypted item deleted.",
                "deleted_id": canonical_id,
            }
        ),
        200,
    )


@vault_bp.get("/export")
@limiter.limit("15 per minute")
@login_required
def export_vault():
    """Export the user's encrypted vault settings and encrypted items."""
    user = g.current_user
    backup_bundle = export_encrypted_vault(user)
    return jsonify(backup_bundle), 200


@vault_bp.post("/import")
@limiter.limit("10 per minute")
@login_required
def import_vault():
    """Validate and restore an encrypted vault backup archive."""
    user = g.current_user
    payload = _parse_json_body()
    validated = _import_schema.load(payload)

    result = import_encrypted_vault(user, validated)
    return (
        jsonify(
            {
                "message": "Encrypted backup restored successfully.",
                **result,
            }
        ),
        200,
    )
