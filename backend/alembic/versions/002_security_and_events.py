"""Add security metadata and events table

Revision ID: 002
Revises: 001
Create Date: 2026-08-23 00:00:00.000000

Adds is_locked, access_attempt_count, successful_view_count, has_suspicious_activity,
suspicious_reason, device_binding_hash, last_client_env to secrets table,
and creates the secret_events table for the security timeline.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new columns to secrets table
    op.add_column("secrets", sa.Column("is_locked", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("secrets", sa.Column("access_attempt_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("secrets", sa.Column("successful_view_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("secrets", sa.Column("has_suspicious_activity", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("secrets", sa.Column("suspicious_reason", sa.Text(), nullable=True))
    op.add_column("secrets", sa.Column("device_binding_hash", sa.String(64), nullable=True))
    op.add_column("secrets", sa.Column("last_client_env", sa.String(100), nullable=True))

    try:
        op.create_index("ix_secrets_creator_token", "secrets", ["creator_token"])
    except Exception:
        pass

    # Create secret_events table
    op.create_table(
        "secret_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("secret_id", sa.String(64), sa.ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="info"),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("client_env", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_secret_events_secret_id", "secret_events", ["secret_id"])
    op.create_index("ix_secret_events_created_at", "secret_events", ["created_at"])
    op.create_index("ix_secret_events_secret_created", "secret_events", ["secret_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_secret_events_secret_created", table_name="secret_events")
    op.drop_index("ix_secret_events_created_at", table_name="secret_events")
    op.drop_index("ix_secret_events_secret_id", table_name="secret_events")
    op.drop_table("secret_events")

    try:
        op.drop_index("ix_secrets_creator_token", table_name="secrets")
    except Exception:
        pass

    op.drop_column("secrets", "last_client_env")
    op.drop_column("secrets", "device_binding_hash")
    op.drop_column("secrets", "suspicious_reason")
    op.drop_column("secrets", "has_suspicious_activity")
    op.drop_column("secrets", "successful_view_count")
    op.drop_column("secrets", "access_attempt_count")
    op.drop_column("secrets", "is_locked")
