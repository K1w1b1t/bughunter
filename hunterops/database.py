"""Database session and connection management for HunterOps-AI.

Provides:
- Async engine creation
- Session factory for async contexts
- Session management utilities
- Connection pooling configuration
"""

import os
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

from hunterops.models import Base


class DatabaseManager:
    """Manages database connections and sessions.
    
    Handles async SQLAlchemy setup, connection pooling, and session lifecycle.
    """
    
    _engine: Optional[AsyncEngine] = None
    _session_factory: Optional[sessionmaker] = None
    
    @classmethod
    async def init(cls, database_url: Optional[str] = None) -> AsyncEngine:
        """Initialize database engine and session factory.
        
        Args:
            database_url: PostgreSQL async DSN. If None, reads from DATABASE_URL_ASYNC env var.
            
        Returns:
            Configured AsyncEngine instance.
            
        Example:
            >>> await DatabaseManager.init()
            >>> async with DatabaseManager.get_session() as session:
            ...     result = await session.execute(select(User))
        """
        if cls._engine is not None:
            return cls._engine
        
        # Get database URL
        db_url = database_url or os.environ.get('DATABASE_URL_ASYNC')
        if not db_url:
            raise ValueError(
                'DATABASE_URL_ASYNC environment variable not set. '
                'Provide async PostgreSQL DSN (postgresql+asyncpg://...)'
            )
        
        # Create async engine with optimized settings
        cls._engine = create_async_engine(
            db_url,
            echo=os.environ.get('DB_ECHO_QUERIES', 'false').lower() == 'true',
            pool_class=QueuePool,
            pool_size=int(os.environ.get('DB_POOL_SIZE', 20)),
            max_overflow=int(os.environ.get('DB_MAX_OVERFLOW', 40)),
            pool_recycle=int(os.environ.get('DB_POOL_RECYCLE', 3600)),
            pool_pre_ping=True,  # Test connection before using
            future=True,
        )
        
        # Create session factory
        cls._session_factory = sessionmaker(
            cls._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            future=True,
        )
        
        return cls._engine
    
    @classmethod
    def get_session_factory(cls) -> sessionmaker:
        """Get configured session factory.
        
        Returns:
            sessionmaker configured for async use.
            
        Raises:
            RuntimeError: If DatabaseManager.init() was not called first.
        """
        if cls._session_factory is None:
            raise RuntimeError('DatabaseManager not initialized. Call init() first.')
        return cls._session_factory
    
    @classmethod
    async def get_session(cls) -> AsyncGenerator[AsyncSession, None]:
        """Get async database session (context manager).
        
        Yields:
            AsyncSession instance.
            
        Example:
            >>> async with DatabaseManager.get_session() as session:
            ...     result = await session.execute(select(User))
            ...     users = result.scalars().all()
        """
        factory = cls.get_session_factory()
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    @classmethod
    async def create_tables(cls) -> None:
        """Create all database tables from models.
        
        Uses metadata from Base.metadata to create tables
        for all registered models.
        
        Typical use case: Initial database setup or testing.
        
        Example:
            >>> await DatabaseManager.init()
            >>> await DatabaseManager.create_tables()
        """
        if cls._engine is None:
            raise RuntimeError('DatabaseManager not initialized. Call init() first.')
        
        async with cls._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    @classmethod
    async def drop_tables(cls) -> None:
        """Drop all database tables (DESTRUCTIVE!).
        
        WARNING: This will delete all tables and data.
        Only use in testing/development.
        
        Example:
            >>> await DatabaseManager.init()
            >>> await DatabaseManager.drop_tables()
        """
        if cls._engine is None:
            raise RuntimeError('DatabaseManager not initialized. Call init() first.')
        
        async with cls._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    
    @classmethod
    async def close(cls) -> None:
        """Close database connection pool.
        
        Call this during application shutdown.
        
        Example:
            >>> await DatabaseManager.close()
        """
        if cls._engine is not None:
            await cls._engine.dispose()
            cls._engine = None
            cls._session_factory = None


# Dependency injection helper for FastAPI
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for FastAPI to inject database sessions.
    
    Usage in FastAPI:
        @app.get("/users")
        async def list_users(session: AsyncSession = Depends(get_db)):
            result = await session.execute(select(User))
            return result.scalars().all()
    """
    manager = DatabaseManager()
    async for session in manager.get_session():
        yield session


__all__ = ['DatabaseManager', 'get_db']
