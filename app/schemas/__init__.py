"""Marshmallow schema exports."""

from app.schemas.auth import LoginSchema, RegisterSchema
from app.schemas.vault import (
    MasterPasswordChangeSchema,
    VaultImportSchema,
    VaultItemCreateSchema,
    VaultItemUpdateSchema,
    VaultSetupSchema,
)

__all__ = [
    "RegisterSchema",
    "LoginSchema",
    "VaultSetupSchema",
    "MasterPasswordChangeSchema",
    "VaultItemCreateSchema",
    "VaultItemUpdateSchema",
    "VaultImportSchema",
]
