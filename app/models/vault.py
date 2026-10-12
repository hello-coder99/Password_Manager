"""Encrypted vault settings and vault item models."""

import uuid
from datetime import datetime, timezone

from app.extensions import db


def utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class VaultSettings(db.Model):
    """Stores client-side key derivation parameters and wrapped Vault Encryption Key (VEK)."""

    __tablename__ = "vault_settings"

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    kdf_algorithm = db.Column(
        db.String(32),
        nullable=False,
        default="argon2id13",
    )
    kdf_version = db.Column(
        db.Integer,
        nullable=False,
        default=1,
    )
    kdf_salt = db.Column(
        db.String(128),
        nullable=False,
    )
    kdf_opslimit = db.Column(
        db.Integer,
        nullable=False,
    )
    kdf_memlimit = db.Column(
        db.Integer,
        nullable=False,
    )
    encrypted_vek = db.Column(
        db.Text,
        nullable=False,
    )
    vek_nonce = db.Column(
        db.String(128),
        nullable=False,
    )
    encryption_version = db.Column(
        db.Integer,
        nullable=False,
        default=1,
    )
    inactivity_timeout_minutes = db.Column(
        db.Integer,
        nullable=False,
        default=5,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    user = db.relationship("User", back_populates="vault_settings")

    def to_dict(self) -> dict:
        """Serialize encrypted vault envelope parameters for the browser."""
        return {
            "user_id": self.user_id,
            "kdf_algorithm": self.kdf_algorithm,
            "kdf_version": self.kdf_version,
            "kdf_salt": self.kdf_salt,
            "kdf_params": {
                "opslimit": self.kdf_opslimit,
                "memlimit": self.kdf_memlimit,
            },
            "encrypted_vek": self.encrypted_vek,
            "vek_nonce": self.vek_nonce,
            "encryption_version": self.encryption_version,
            "inactivity_timeout_minutes": self.inactivity_timeout_minutes,
            "updated_at": (
                self.updated_at.isoformat() if self.updated_at else None
            ),
        }


class VaultItem(db.Model):
    """Stores an individual encrypted credential record.

    All sensitive fields (title, username, password, URL, notes, category,
    tags, favorite status) are encrypted together inside `ciphertext` in the
    browser using XChaCha20-Poly1305 with authenticated additional data (AAD)
    binding the ciphertext to (user_id, item_id, encryption_version).
    """

    __tablename__ = "vault_items"
    __table_args__ = (
        db.Index("ix_vault_items_user_updated", "user_id", "updated_at"),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ciphertext = db.Column(
        db.Text,
        nullable=False,
    )
    nonce = db.Column(
        db.String(128),
        nullable=False,
    )
    encryption_version = db.Column(
        db.Integer,
        nullable=False,
        default=1,
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

    user = db.relationship("User", back_populates="vault_items")

    def to_dict(self) -> dict:
        """Serialize encrypted item metadata and ciphertext."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ciphertext": self.ciphertext,
            "nonce": self.nonce,
            "encryption_version": self.encryption_version,
            "created_at": (
                self.created_at.isoformat() if self.created_at else None
            ),
            "updated_at": (
                self.updated_at.isoformat() if self.updated_at else None
            ),
        }
