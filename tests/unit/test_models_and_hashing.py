"""Unit tests for Argon2id password hashing, models, and production config validation."""

import tempfile
from pathlib import Path
import pytest
from flask_migrate import upgrade as alembic_upgrade

from app import create_app
from app.config import validate_production_config
from app.extensions import db
from app.models import User, VaultItem, VaultSettings
from app.security.password_hashing import (
    hash_login_password,
    needs_rehash,
    verify_login_password,
)
from tests.conftest import make_sample_vault_setup_payload


def test_argon2id_hash_and_verification():
    """Verify Argon2id password hashing and constant-time verification."""
    raw_password = "CorrectHorseBatteryStaple!99"
    hashed = hash_login_password(raw_password)

    assert hashed.startswith("$argon2id$")
    assert raw_password not in hashed
    assert verify_login_password(hashed, raw_password) is True
    assert verify_login_password(hashed, "WrongPassword!99") is False
    assert verify_login_password(None, raw_password) is False
    assert needs_rehash(hashed) is False


def test_production_config_validation_rejects_missing_or_weak_secrets():
    """Ensure production configuration fails safely when secrets or URLs are invalid."""
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        validate_production_config({"SECRET_KEY": "short"})

    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        validate_production_config(
            {
                "SECRET_KEY": "a" * 64,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "REDIS_URL": "redis://:secret@redis:6379/0",
            }
        )

    with pytest.raises(RuntimeError, match="REDIS_URL"):
        validate_production_config(
            {
                "SECRET_KEY": "a" * 64,
                "SQLALCHEMY_DATABASE_URI": "mysql+pymysql://u:p@mariadb:3306/db",
                "REDIS_URL": "memory://",
            }
        )


def test_database_cascade_deletion_and_no_plaintext_columns(app):
    """Ensure User deletion cascades to VaultSettings and VaultItem and schema has no plaintext credential columns."""
    with app.app_context():
        item_columns = {c.name for c in VaultItem.__table__.columns}
        forbidden_columns = {
            "title",
            "username",
            "password",
            "url",
            "notes",
            "category",
            "tags",
        }
        assert item_columns.isdisjoint(forbidden_columns)

        user = User(
            email="alice@example.edu",
            login_password_hash=hash_login_password("AliceStrongLoginPass!123"),
        )
        db.session.add(user)
        db.session.commit()

        setup_data = make_sample_vault_setup_payload()
        settings = VaultSettings(
            user_id=user.id,
            kdf_algorithm=setup_data["kdf_algorithm"],
            kdf_version=setup_data["kdf_version"],
            kdf_salt=setup_data["kdf_salt"],
            kdf_opslimit=setup_data["kdf_params"]["opslimit"],
            kdf_memlimit=setup_data["kdf_params"]["memlimit"],
            encrypted_vek=setup_data["encrypted_vek"],
            vek_nonce=setup_data["vek_nonce"],
            encryption_version=setup_data["encryption_version"],
        )
        item = VaultItem(
            user_id=user.id,
            ciphertext=setup_data["encrypted_vek"],
            nonce=setup_data["vek_nonce"],
            encryption_version=1,
        )
        db.session.add_all([settings, item])
        db.session.commit()

        user_id = user.id
        item_id = item.id

        db.session.delete(user)
        db.session.commit()

        assert db.session.get(VaultSettings, user_id) is None
        assert db.session.get(VaultItem, item_id) is None


def test_alembic_migrations_apply_to_empty_database():
    """Verify that Flask-Migrate migrations cleanly initialize an empty database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "migration_test.db"
        migration_app = create_app(
            "testing",
            config_overrides={
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
            },
        )
        with migration_app.app_context():
            db.drop_all()
            alembic_upgrade(directory="app/migrations")
            inspector = db.inspect(db.engine)
            tables = set(inspector.get_table_names())
            assert {"users", "vault_settings", "vault_items"}.issubset(tables)
