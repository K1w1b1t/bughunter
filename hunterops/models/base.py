"""SQLAlchemy ORM base configuration for HunterOps-AI.

This module defines the declarative base and metadata that Alembic uses
to track model changes for auto-generating migrations.
"""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy.ext.asyncio import AsyncSession


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models.
    
    Provides common functionality and metadata tracking for Alembic.
    """
    pass


class TimestampMixin:
    """Mixin that adds created_at and updated_at timestamps to models."""
    
    @property
    def created_at(self) -> DateTime:
        """Datetime when record was created."""
        return getattr(self, '_created_at', None)
    
    @property
    def updated_at(self) -> DateTime:
        """Datetime when record was last updated."""
        return getattr(self, '_updated_at', None)


__all__ = ['Base', 'TimestampMixin']
