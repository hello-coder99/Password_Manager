"""Vault service handling encrypted VEK settings, CRUD operations, and encrypted backups."""

import uuid
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.user import User
from app.models.vault import VaultItem, VaultSettings
from app.security.authorization import verify_resource_ownership


class VaultServiceError(Exception):
    """Base exception for vault domain errors."""

    def __init__(self, message: str, status_code: int = 400, code: str = "VAULT_ERROR"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class VaultAlreadyInitializedError(VaultServiceError):
    """Raised when attempting to initialize an already configured vault."""

    def __init__(self):
        super().__init__(
            "Vault is already initialized for this account.",
            status_code=409,
            code="VAULT_ALREADY_INITIALIZED",
        )


class VaultNotInitializedError(VaultServiceError):
    """Raised when operating on a vault that has not been initialized yet."""

    def __init__(self):
        super().__init__(
            "Vault has not been initialized for this account.",
            status_code=404,
            code="VAULT_NOT_INITIALIZED",
        )


class VaultItemNotFoundError(VaultServiceError):
    """Raised when a vault item does not exist or belongs to another user."""

    def __init__(self):
        super().__init__(
            "Vault item not found.",
            status_code=404,
            code="ITEM_NOT_FOUND",
        )


def get_vault_settings(user: User) -> VaultSettings | None:
    """Fetch encrypted vault settings for the given user."""
    return db.session.get(VaultSettings, user.id)


def initialize_vault(user: User, validated_data: dict) -> VaultSettings:
    """Persist initial KDF parameters and wrapped VEK for the user."""
    existing = db.session.get(VaultSettings, user.id)
    if existing is not None:
        raise VaultAlreadyInitializedError()

    kdf_params = validated_data["kdf_params"]
    settings = VaultSettings(
        user_id=user.id,
        kdf_algorithm=validated_data["kdf_algorithm"],
        kdf_version=validated_data["kdf_version"],
        kdf_salt=validated_data["kdf_salt"],
        kdf_opslimit=kdf_params["opslimit"],
        kdf_memlimit=kdf_params["memlimit"],
        encrypted_vek=validated_data["encrypted_vek"],
        vek_nonce=validated_data["vek_nonce"],
        encryption_version=validated_data["encryption_version"],
        inactivity_timeout_minutes=validated_data.get(
            "inactivity_timeout_minutes", 5
        ),
    )
    db.session.add(settings)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise VaultAlreadyInitializedError() from exc

    return settings


def update_master_password_envelope(
    user: User, validated_data: dict
) -> VaultSettings:
    """Update the wrapped VEK and KDF salt/parameters when changing master password.

    Vault items are NOT re-encrypted because the underlying 256-bit VEK remains unchanged;
    only the wrapping key derived from the new master password and the VEK wrapping nonce change.
    """
    settings = db.session.get(VaultSettings, user.id)
    if settings is None:
        raise VaultNotInitializedError()

    kdf_params = validated_data["kdf_params"]
    settings.kdf_algorithm = validated_data["kdf_algorithm"]
    settings.kdf_version = validated_data["kdf_version"]
    settings.kdf_salt = validated_data["kdf_salt"]
    settings.kdf_opslimit = kdf_params["opslimit"]
    settings.kdf_memlimit = kdf_params["memlimit"]
    settings.encrypted_vek = validated_data["encrypted_vek"]
    settings.vek_nonce = validated_data["vek_nonce"]
    settings.encryption_version = validated_data["encryption_version"]
    if "inactivity_timeout_minutes" in validated_data:
        settings.inactivity_timeout_minutes = validated_data[
            "inactivity_timeout_minutes"
        ]
    settings.updated_at = datetime.now(timezone.utc)

    db.session.commit()
    return settings


def list_vault_items(user: User) -> list[VaultItem]:
    """Return all encrypted vault items owned by the authenticated user."""
    return (
        VaultItem.query.filter_by(user_id=user.id)
        .order_by(VaultItem.updated_at.desc())
        .all()
    )


def create_vault_item(user: User, validated_data: dict) -> VaultItem:
    """Store a new client-side encrypted vault item."""
    settings = db.session.get(VaultSettings, user.id)
    if settings is None:
        raise VaultNotInitializedError()

    item_id = validated_data.get("id") or str(uuid.uuid4())
    existing = db.session.get(VaultItem, item_id)
    if existing is not None:
        raise VaultServiceError(
            "Vault item identifier already exists.",
            status_code=409,
            code="ITEM_ID_CONFLICT",
        )

    item = VaultItem(
        id=item_id,
        user_id=user.id,
        ciphertext=validated_data["ciphertext"],
        nonce=validated_data["nonce"],
        encryption_version=validated_data["encryption_version"],
    )
    db.session.add(item)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise VaultServiceError(
            "Unable to save vault item due to identifier conflict.",
            status_code=409,
            code="ITEM_ID_CONFLICT",
        ) from exc

    return item


def get_owned_vault_item(user: User, item_id: str) -> VaultItem:
    """Fetch a vault item and enforce strict user ownership."""
    item = db.session.get(VaultItem, item_id)
    if item is None or not verify_resource_ownership(item.user_id, user.id):
        raise VaultItemNotFoundError()
    return item


def update_vault_item(
    user: User, item_id: str, validated_data: dict
) -> VaultItem:
    """Update ciphertext and nonce of an existing vault item owned by the user."""
    item = get_owned_vault_item(user, item_id)
    item.ciphertext = validated_data["ciphertext"]
    item.nonce = validated_data["nonce"]
    item.encryption_version = validated_data["encryption_version"]
    item.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return item


def delete_vault_item(user: User, item_id: str) -> None:
    """Delete an encrypted vault item owned by the user."""
    item = get_owned_vault_item(user, item_id)
    db.session.delete(item)
    db.session.commit()


def export_encrypted_vault(user: User) -> dict:
    """Create a complete encrypted backup archive for the user's vault."""
    settings = db.session.get(VaultSettings, user.id)
    if settings is None:
        raise VaultNotInitializedError()

    items = list_vault_items(user)
    return {
        "backup_format": "aegisvault-encrypted-backup",
        "backup_version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "user_id": user.id,
        "vault_settings": {
            "kdf_algorithm": settings.kdf_algorithm,
            "kdf_version": settings.kdf_version,
            "kdf_salt": settings.kdf_salt,
            "kdf_params": {
                "opslimit": settings.kdf_opslimit,
                "memlimit": settings.kdf_memlimit,
            },
            "encrypted_vek": settings.encrypted_vek,
            "vek_nonce": settings.vek_nonce,
            "encryption_version": settings.encryption_version,
            "inactivity_timeout_minutes": settings.inactivity_timeout_minutes,
        },
        "items": [
            {
                "id": item.id,
                "ciphertext": item.ciphertext,
                "nonce": item.nonce,
                "encryption_version": item.encryption_version,
                "created_at": (
                    item.created_at.isoformat() if item.created_at else None
                ),
                "updated_at": (
                    item.updated_at.isoformat() if item.updated_at else None
                ),
            }
            for item in items
        ],
    }


def import_encrypted_vault(user: User, validated_data: dict) -> dict:
    """Atomically restore encrypted vault settings and items from a backup archive."""
    settings_data = validated_data["vault_settings"]
    kdf_params = settings_data["kdf_params"]
    incoming_items = validated_data["items"]

    # Check for duplicate item IDs inside the backup payload itself
    seen_ids: set[str] = set()
    for item_payload in incoming_items:
        item_id = item_payload["id"]
        if item_id in seen_ids:
            raise VaultServiceError(
                "Backup contains duplicate item identifiers.",
                status_code=400,
                code="DUPLICATE_BACKUP_ITEM_ID",
            )
        seen_ids.add(item_id)

        # Ensure no item ID collides with a record owned by a DIFFERENT user
        existing_item = db.session.get(VaultItem, item_id)
        if existing_item is not None and not verify_resource_ownership(
            existing_item.user_id, user.id
        ):
            raise VaultServiceError(
                "Backup item identifier conflicts with another account.",
                status_code=409,
                code="CROSS_USER_ITEM_CONFLICT",
            )

    try:
        settings = db.session.get(VaultSettings, user.id)
        if settings is None:
            settings = VaultSettings(
                user_id=user.id,
                kdf_algorithm=settings_data["kdf_algorithm"],
                kdf_version=settings_data["kdf_version"],
                kdf_salt=settings_data["kdf_salt"],
                kdf_opslimit=kdf_params["opslimit"],
                kdf_memlimit=kdf_params["memlimit"],
                encrypted_vek=settings_data["encrypted_vek"],
                vek_nonce=settings_data["vek_nonce"],
                encryption_version=settings_data["encryption_version"],
                inactivity_timeout_minutes=settings_data.get(
                    "inactivity_timeout_minutes", 5
                ),
            )
            db.session.add(settings)
        else:
            settings.kdf_algorithm = settings_data["kdf_algorithm"]
            settings.kdf_version = settings_data["kdf_version"]
            settings.kdf_salt = settings_data["kdf_salt"]
            settings.kdf_opslimit = kdf_params["opslimit"]
            settings.kdf_memlimit = kdf_params["memlimit"]
            settings.encrypted_vek = settings_data["encrypted_vek"]
            settings.vek_nonce = settings_data["vek_nonce"]
            settings.encryption_version = settings_data["encryption_version"]
            settings.inactivity_timeout_minutes = settings_data.get(
                "inactivity_timeout_minutes",
                settings.inactivity_timeout_minutes,
            )
            settings.updated_at = datetime.now(timezone.utc)

        # Replace current user's items with the restored backup items atomically
        VaultItem.query.filter_by(user_id=user.id).delete(
            synchronize_session=False
        )
        db.session.flush()

        for item_payload in incoming_items:
            restored_item = VaultItem(
                id=item_payload["id"],
                user_id=user.id,
                ciphertext=item_payload["ciphertext"],
                nonce=item_payload["nonce"],
                encryption_version=item_payload["encryption_version"],
            )
            db.session.add(restored_item)

        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        if isinstance(exc, VaultServiceError):
            raise
        raise VaultServiceError(
            "Failed to restore encrypted backup.",
            status_code=500,
            code="IMPORT_FAILED",
        ) from exc

    return {
        "imported_count": len(incoming_items),
        "vault_settings": settings.to_dict(),
    }
