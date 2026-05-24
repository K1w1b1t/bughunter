"""Alembic environment configuration for HunterOps-AI

This script is run when invoking alembic commands. It needs to be
configured so that it can access the database via the SQLAlchemy URL
(from the config file) and establish a connection to the database.

This configuration supports both sync and async operations.
"""

import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

# This is the Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import target_metadata from base (models)
# This is where the MetaData is imported to support autogenerate
# Import after setting PYTHONPATH
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from hunterops.models.base import Base  # noqa: E402

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = os.environ.get(
        "DATABASE_URL_ASYNC",
        configuration.get("sqlalchemy.url"),
    )

    context.configure(
        url=configuration["sqlalchemy.url"],
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    """Run migrations with a given database connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = os.environ.get(
        "DATABASE_URL_ASYNC",
        configuration.get("sqlalchemy.url"),
    )

    connectable = await create_async_engine(
        configuration["sqlalchemy.url"],
        poolclass=pool.NullPool,
        echo=False,
    )

    async with connectable.begin() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
