"""User account model for backend authentication."""

import uuid
from datetime import datetime, timezone

from app.extensions import db


def utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class User(db.Model):
    """Represents an authenticated user account.

    Stores only the Argon2id hash of the account login password.
    Never stores the vault master password or plaintext vault keys.
    """

    __tablename__ = "users"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    login_password_hash = db.Column(
        db.String(255),
        nullable=False,
    )
    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )
    disabled_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    vault_settings = db.relationship(
        "VaultSettings",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    vault_items = db.relationship(
        "VaultItem",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
         order_by="VaultItem.updated_at.desc()",
    )

    def to_dict(self) -> dict:
        """Serialize public user profile metadata (never exposes password hash)."""
        return {
            "id": self.id,
            "email": self.email,
            "is_active": self.is_active,
            "has_vault_setup": self.vault_settings is not None,
            "created_at": (
                self.created_at.isoformat() if self.created_at else None
            ),
        }
