"""Create secrets table

Revision ID: 001
Revises: None
Create Date: 2025-01-01 00:00:00.000000

This is the initial migration that creates the secrets table.
All columns match the VaultDrop Master Build Specification exactly.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "secrets",
        # --- Primary key: random unpredictable string ---
        sa.Column("id", sa.String(64), primary_key=True),
        # --- Encrypted payload ---
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("iv", sa.Text(), nullable=False),
        # --- Secret type ---
        sa.Column("secret_type", sa.String(20), nullable=False),
        # --- Lifecycle ---
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("one_time", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("destroyed", sa.Boolean(), nullable=False, server_default="false"),
        # --- Password protection ---
        sa.Column("password_protected", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("password_salt", sa.Text(), nullable=True),
        sa.Column("password_verifier", sa.Text(), nullable=True),
        # --- Timestamps ---
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("viewed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Index on expires_at for efficient expiration queries
    op.create_index("ix_secrets_expires_at", "secrets", ["expires_at"])

    # Index on id is automatic (primary key)


def downgrade() -> None:
    op.drop_index("ix_secrets_expires_at", table_name="secrets")
    op.drop_table("secrets")
