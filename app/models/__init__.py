"""Database models package and SQLite foreign-key enforcement hook."""

from sqlalchemy import event
from sqlalchemy.engine import Engine

from app.models.user import User
from app.models.vault import VaultItem, VaultSettings


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key constraints when using SQLite in tests or local dev."""
    module_name = type(dbapi_connection).__module__
    if "sqlite" in module_name.lower():
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


__all__ = ["User", "VaultSettings", "VaultItem"]
