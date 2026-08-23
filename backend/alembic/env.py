"""
Alembic migration environment.

This file configures how Alembic connects to the database and
discovers model metadata for autogeneration. The key trick is
overriding the sqlalchemy.url from our app's Settings so we
never hardcode credentials in alembic.ini.

NOTE: Alembic migrations run synchronously, so we use the
synchronous PostgreSQL URL (postgresql:// instead of postgresql+asyncpg://).
"""

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Add the backend directory to sys.path so we can import app modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings  # noqa: E402
from app.db.base import Base  # noqa: E402

# Import all models so Base.metadata knows about them
from app.models.secret import Secret  # noqa: E402, F401

# Alembic Config object (reads alembic.ini)
config = context.config

# Set up Python logging from the config file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Tell Alembic about our models so autogenerate works
target_metadata = Base.metadata


def get_sync_url() -> str:
    """Convert the async database URL to a sync one for Alembic.

    Alembic runs migrations synchronously, so we need psycopg2 (sync)
    rather than asyncpg (async). We swap the driver in the URL.
    """
    url = settings.DATABASE_URL
    # Replace async driver with sync driver
    if "+asyncpg" in url:
        return url.replace("+asyncpg", "")
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Generates SQL scripts without connecting to the database.
    Useful for generating migration SQL for review.
    """
    url = get_sync_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Connects to the database and applies migrations directly.
    This is the normal mode used during development.
    """
    # Override the URL from alembic.ini with our app settings
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_sync_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
