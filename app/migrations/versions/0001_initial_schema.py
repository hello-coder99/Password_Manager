"""Initial database schema for users, vault_settings, and vault_items.

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-10-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "users" not in existing_tables:
        op.create_table(
            "users",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column(
                "login_password_hash", sa.String(length=255), nullable=False
            ),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    if "vault_settings" not in existing_tables:
        op.create_table(
            "vault_settings",
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("kdf_algorithm", sa.String(length=32), nullable=False),
            sa.Column("kdf_version", sa.Integer(), nullable=False),
            sa.Column("kdf_salt", sa.String(length=128), nullable=False),
            sa.Column("kdf_opslimit", sa.Integer(), nullable=False),
            sa.Column("kdf_memlimit", sa.Integer(), nullable=False),
            sa.Column("encrypted_vek", sa.Text(), nullable=False),
            sa.Column("vek_nonce", sa.String(length=128), nullable=False),
            sa.Column("encryption_version", sa.Integer(), nullable=False),
            sa.Column(
                "inactivity_timeout_minutes",
                sa.Integer(),
                nullable=False,
                server_default="5",
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(
                ["user_id"], ["users.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("user_id"),
        )

    if "vault_items" not in existing_tables:
        op.create_table(
            "vault_items",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("ciphertext", sa.Text(), nullable=False),
            sa.Column("nonce", sa.String(length=128), nullable=False),
            sa.Column("encryption_version", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(
                ["user_id"], ["users.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            op.f("ix_vault_items_user_id"),
            "vault_items",
            ["user_id"],
            unique=False,
        )
        op.create_index(
            "ix_vault_items_user_updated",
            "vault_items",
            ["user_id", "updated_at"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_index("ix_vault_items_user_updated", table_name="vault_items")
    op.drop_index(op.f("ix_vault_items_user_id"), table_name="vault_items")
    op.drop_table("vault_items")
    op.drop_table("vault_settings")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
