"""Marshmallow request validation schemas for encrypted vault operations."""

import base64
import binascii
import uuid

from marshmallow import (
    RAISE,
    Schema,
    ValidationError,
    fields,
    validate,
    validates,
)

from app.schemas.auth import BaseStrictSchema

# Cryptographic parameter bounds (Argon2id + XChaCha20-Poly1305)
SUPPORTED_KDF_ALGORITHMS = {"argon2id13"}
SUPPORTED_KDF_VERSIONS = {1}
SUPPORTED_ENCRYPTION_VERSIONS = {1}
SUPPORTED_BACKUP_VERSIONS = {1}

MIN_KDF_OPSLIMIT = 2
MAX_KDF_OPSLIMIT = 10
MIN_KDF_MEMLIMIT = 16 * 1024 * 1024       # 16 MiB minimum
MAX_KDF_MEMLIMIT = 256 * 1024 * 1024      # 256 MiB maximum (DoS ceiling)

SALT_BYTE_LENGTH = 16                     # crypto_pwhash_SALTBYTES
NONCE_BYTE_LENGTH = 24                    # crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
ENCRYPTED_VEK_BYTE_LENGTH = 48            # 32-byte VEK + 16-byte Poly1305 tag
MIN_CIPHERTEXT_BYTE_LENGTH = 18           # At least 2 bytes payload + 16-byte tag
MAX_CIPHERTEXT_BYTE_LENGTH = 64 * 1024    # 64 KB per encrypted vault item
MAX_IMPORT_ITEMS = 2000


def _decode_base64_exact(value: str, field_label: str) -> bytes:
    """Decode standard or URL-safe base64 string and reject malformed encodings."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_label} must be a non-empty base64 string.")
    cleaned = value.strip()
    # Add padding if URL-safe unpadded base64 was used
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        if "-" in cleaned or "_" in cleaned:
            return base64.urlsafe_b64decode(padded.encode("ascii"))
        return base64.b64decode(padded.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError(f"{field_label} is not valid base64 encoding.") from exc


class KdfParamsSchema(Schema):
    """Validates bounded Argon2id parameters to prevent weak keys and DoS."""

    class Meta:
        unknown = RAISE

    opslimit = fields.Integer(
        required=True,
        validate=validate.Range(
            min=MIN_KDF_OPSLIMIT,
            max=MAX_KDF_OPSLIMIT,
            error=f"kdf_params.opslimit must be between {MIN_KDF_OPSLIMIT} and {MAX_KDF_OPSLIMIT}.",
        ),
    )
    memlimit = fields.Integer(
        required=True,
        validate=validate.Range(
            min=MIN_KDF_MEMLIMIT,
            max=MAX_KDF_MEMLIMIT,
            error=f"kdf_params.memlimit must be between {MIN_KDF_MEMLIMIT} and {MAX_KDF_MEMLIMIT} bytes.",
        ),
    )


class VaultSetupSchema(BaseStrictSchema):
    """Validates initial vault setup and master password envelope parameters."""

    kdf_algorithm = fields.String(
        required=True,
        validate=validate.OneOf(
            SUPPORTED_KDF_ALGORITHMS,
            error="Unsupported KDF algorithm. Must be 'argon2id13'.",
        ),
    )
    kdf_version = fields.Integer(
        required=True,
        validate=validate.OneOf(
            SUPPORTED_KDF_VERSIONS,
            error="Unsupported KDF version.",
        ),
    )
    kdf_salt = fields.String(
        required=True,
        validate=validate.Length(min=16, max=64),
    )
    kdf_params = fields.Nested(KdfParamsSchema, required=True)
    encrypted_vek = fields.String(
        required=True,
        validate=validate.Length(min=48, max=128),
    )
    vek_nonce = fields.String(
        required=True,
        validate=validate.Length(min=24, max=64),
    )
    encryption_version = fields.Integer(
        required=True,
        validate=validate.OneOf(
            SUPPORTED_ENCRYPTION_VERSIONS,
            error="Unsupported encryption format version.",
        ),
    )
    inactivity_timeout_minutes = fields.Integer(
        load_default=5,
        validate=validate.Range(min=1, max=120),
    )

    @validates("kdf_salt")
    def validate_salt_bytes(self, value: str, **kwargs) -> None:
        raw = _decode_base64_exact(value, "kdf_salt")
        if len(raw) != SALT_BYTE_LENGTH:
            raise ValidationError(
                f"kdf_salt must decode to exactly {SALT_BYTE_LENGTH} bytes."
            )

    @validates("encrypted_vek")
    def validate_encrypted_vek_bytes(self, value: str, **kwargs) -> None:
        raw = _decode_base64_exact(value, "encrypted_vek")
        if len(raw) != ENCRYPTED_VEK_BYTE_LENGTH:
            raise ValidationError(
                f"encrypted_vek must decode to {ENCRYPTED_VEK_BYTE_LENGTH} bytes "
                "(32-byte VEK + 16-byte authentication tag)."
            )

    @validates("vek_nonce")
    def validate_vek_nonce_bytes(self, value: str, **kwargs) -> None:
        raw = _decode_base64_exact(value, "vek_nonce")
        if len(raw) != NONCE_BYTE_LENGTH:
            raise ValidationError(
                f"vek_nonce must decode to {NONCE_BYTE_LENGTH} bytes."
            )


class MasterPasswordChangeSchema(VaultSetupSchema):
    """Validates re-wrapped VEK and new salt/nonce when changing master password."""


class VaultItemCreateSchema(BaseStrictSchema):
    """Validates creation of a client-side encrypted vault item."""

    id = fields.String(
        required=False,
        validate=validate.Length(equal=36),
    )
    ciphertext = fields.String(
        required=True,
        validate=validate.Length(min=24, max=90000),
    )
    nonce = fields.String(
        required=True,
        validate=validate.Length(min=24, max=64),
    )
    encryption_version = fields.Integer(
        required=True,
        validate=validate.OneOf(
            SUPPORTED_ENCRYPTION_VERSIONS,
            error="Unsupported encryption format version.",
        ),
    )

    @validates("id")
    def validate_uuid(self, value: str, **kwargs) -> None:
        try:
            parsed = uuid.UUID(value)
            if str(parsed) != value.lower():
                raise ValidationError("Item id must be a canonical lowercase UUID.")
        except ValueError as exc:
            raise ValidationError("Item id must be a valid UUID.") from exc

    @validates("ciphertext")
    def validate_ciphertext_bytes(self, value: str, **kwargs) -> None:
        raw = _decode_base64_exact(value, "ciphertext")
        if len(raw) < MIN_CIPHERTEXT_BYTE_LENGTH:
            raise ValidationError("ciphertext is shorter than minimum authenticated payload.")
        if len(raw) > MAX_CIPHERTEXT_BYTE_LENGTH:
            raise ValidationError("ciphertext exceeds maximum allowed size.")

    @validates("nonce")
    def validate_nonce_bytes(self, value: str, **kwargs) -> None:
        raw = _decode_base64_exact(value, "nonce")
        if len(raw) != NONCE_BYTE_LENGTH:
            raise ValidationError(
                f"nonce must decode to {NONCE_BYTE_LENGTH} bytes."
            )


class VaultItemUpdateSchema(BaseStrictSchema):
    """Validates updating an existing encrypted vault item."""

    ciphertext = fields.String(
        required=True,
        validate=validate.Length(min=24, max=90000),
    )
    nonce = fields.String(
        required=True,
        validate=validate.Length(min=24, max=64),
    )
    encryption_version = fields.Integer(
        required=True,
        validate=validate.OneOf(
            SUPPORTED_ENCRYPTION_VERSIONS,
            error="Unsupported encryption format version.",
        ),
    )

    @validates("ciphertext")
    def validate_ciphertext_bytes(self, value: str, **kwargs) -> None:
        raw = _decode_base64_exact(value, "ciphertext")
        if len(raw) < MIN_CIPHERTEXT_BYTE_LENGTH:
            raise ValidationError("ciphertext is shorter than minimum authenticated payload.")
        if len(raw) > MAX_CIPHERTEXT_BYTE_LENGTH:
            raise ValidationError("ciphertext exceeds maximum allowed size.")

    @validates("nonce")
    def validate_nonce_bytes(self, value: str, **kwargs) -> None:
        raw = _decode_base64_exact(value, "nonce")
        if len(raw) != NONCE_BYTE_LENGTH:
            raise ValidationError(
                f"nonce must decode to {NONCE_BYTE_LENGTH} bytes."
            )


class VaultBackupItemSchema(VaultItemCreateSchema):
    """Validates an item inside an encrypted vault backup bundle."""

    id = fields.String(required=True, validate=validate.Length(equal=36))
    created_at = fields.String(required=False, allow_none=True)
    updated_at = fields.String(required=False, allow_none=True)


class VaultImportSchema(BaseStrictSchema):
    """Validates an encrypted backup archive for restoration."""

    backup_format = fields.String(
        required=True,
        validate=validate.Equal(
            "aegisvault-encrypted-backup",
            error="Invalid backup_format identifier.",
        ),
    )
    backup_version = fields.Integer(
        required=True,
        validate=validate.OneOf(
            SUPPORTED_BACKUP_VERSIONS,
            error="Unsupported backup format version.",
        ),
    )
    exported_at = fields.String(required=False, allow_none=True)
    vault_settings = fields.Nested(VaultSetupSchema, required=True)
    items = fields.List(
        fields.Nested(VaultBackupItemSchema),
        required=True,
        validate=validate.Length(max=MAX_IMPORT_ITEMS),
    )
