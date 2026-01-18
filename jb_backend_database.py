from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.logging_config import get_logger

# Get logger for this module
logger = get_logger(__name__)


# =============================================================================
# SQLAlchemy Base Class
# =============================================================================

class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy models.
    
    All database models inherit from this class. It provides:
    - Common metadata configuration
    - Automatic table naming
    - Shared functionality across all models
    
    WHY A BASE CLASS:
    - Centralized metadata for migrations (Alembic)
    - Can add common columns (created_at, updated_at) to all models
    - SQLAlchemy requirement for ORM functionality
    """
    pass


# =============================================================================
# Database Engine and Session Factory
# =============================================================================

# Global engine instance - will be initialized on startup
# Engine manages the connection pool
_engine: Optional[AsyncEngine] = None

# Session factory - creates new sessions
# Sessions are units of work with the database
_async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


async def init_db() -> None:
    """
    Initialize the database connection pool.
    
    This function should be called once at application startup.
    It creates:
    1. An async engine with connection pooling
    2. A session factory for creating sessions
    
    CONNECTION POOL PARAMETERS:
    
    pool_size (5):
        Number of connections to keep open at all times.
        These connections are ready for immediate use.
    
    max_overflow (10):
        Number of additional connections allowed beyond pool_size.
        These are created on-demand and closed when not needed.
        Total max = pool_size + max_overflow = 15
    
    pool_pre_ping (True):
        Check if connection is alive before using it.
        Prevents errors from stale connections.
        Small overhead but worth it for reliability.
    
    pool_recycle (3600):
        Close and recreate connections after 1 hour.
        Prevents issues with long-lived connections.
        Some databases have connection timeouts.
    
    TIME COMPLEXITY:
        - Pool creation: O(pool_size) - creates initial connections
        - Get connection from pool: O(1) - just borrows from pool
    
    Raises:
        Exception: If database connection fails
    """
    global _engine, _async_session_factory
    
    logger.info("Creating database engine and connection pool...")
    
    # Create the async engine
    # The engine manages the connection pool
    _engine = create_async_engine(
        settings.DATABASE_URL,
        
        # Connection pool settings
        pool_size=settings.DATABASE_POOL_SIZE,  # Default: 5
        max_overflow=settings.DATABASE_MAX_OVERFLOW,  # Default: 10
        
        # Pool behavior settings
        pool_pre_ping=True,  # Verify connections before use
        pool_recycle=3600,   # Recycle connections after 1 hour
        
        # Echo SQL statements in debug mode (helpful for development)
        echo=settings.DEBUG and settings.ENVIRONMENT == "development",
        
        # Future-proof settings
        future=True,
    )
    
    # Create session factory
    # This is used to create new sessions for each request
    _async_session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        
        # Don't automatically expire objects after commit
        # This allows accessing attributes after the session closes
        expire_on_commit=False,
        
        # Autocommit and autoflush settings
        autocommit=False,  # We want explicit commits
        autoflush=False,   # We want explicit flushes
    )
    
    # Test the connection
    async with _engine.begin() as conn:
        await conn.execute(text("SELECT 1"))
    
    logger.info(
        "Database connection pool created",
        extra={
            "pool_size": settings.DATABASE_POOL_SIZE,
            "max_overflow": settings.DATABASE_MAX_OVERFLOW,
        }
    )


async def close_db() -> None:
    """
    Close all database connections.
    
    This should be called when the application shuts down.
    It ensures all connections are properly closed.
    
    WHY PROPER SHUTDOWN:
    - Releases database resources
    - Prevents connection leaks
    - Allows pending transactions to complete
    """
    global _engine, _async_session_factory
    
    if _engine is not None:
        logger.info("Closing database connection pool...")
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
        logger.info("Database connection pool closed")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that provides a database session.
    
    This is used with FastAPI's dependency injection:
    
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            # Use db session here
            pass
    
    HOW IT WORKS:
    1. Creates a new session from the pool
    2. Yields it to the route handler
    3. Commits if no exception occurred
    4. Rolls back if an exception occurred
    5. Always closes the session (returns to pool)
    
    WHY YIELD (GENERATOR):
    - Allows cleanup code to run after the request
    - Session is automatically closed/returned to pool
    - Exception handling is centralized here
    
    Yields:
        AsyncSession: A database session for the request
    
    Raises:
        RuntimeError: If database is not initialized
    """
    if _async_session_factory is None:
        raise RuntimeError(
            "Database not initialized! "
            "Call init_db() before making database queries."
        )
    
    # Create a new session
    async with _async_session_factory() as session:
        try:
            # Yield the session to the route handler
            yield session
            
            # If we get here (no exception), commit the transaction
            await session.commit()
            
        except Exception:
            # If an exception occurred, rollback the transaction
            # This undoes any uncommitted changes
            await session.rollback()
            
            # Re-raise the exception so it can be handled elsewhere
            raise
            
        finally:
            # Always close the session
            # This returns the connection to the pool
            await session.close()


async def check_db_health() -> bool:
    """
    Check if the database is healthy and responding.
    
    Used by health check endpoints to verify database connectivity.
    
    HOW IT WORKS:
    - Executes a simple "SELECT 1" query
    - If it succeeds, database is healthy
    - If it fails, database is unhealthy
    
    WHY "SELECT 1":
    - Minimal query that tests connectivity
    - Works on any database
    - Very fast (no table access)
    
    Returns:
        bool: True if database is healthy, False otherwise
    
    TIME COMPLEXITY: O(1) - simple connectivity check
    """
    if _engine is None:
        return False
    
    try:
        async with _engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


# =============================================================================
# Utility Functions
# =============================================================================

def get_engine() -> Optional[AsyncEngine]:
    """
    Get the current database engine.
    
    Useful for:
    - Running raw SQL queries
    - Database migrations
    - Testing
    
    Returns:
        Optional[AsyncEngine]: The database engine or None if not initialized
    """
    return _engine


async def execute_raw_sql(sql: str, params: dict = None) -> list:
    """
    Execute raw SQL query and return results.
    
    USE WITH CAUTION:
    - Prefer ORM queries for type safety
    - This bypasses SQLAlchemy's protection
    - Always use parameterized queries (the params dict)
    
    NEVER DO THIS (SQL injection vulnerability):
        execute_raw_sql(f"SELECT * FROM users WHERE id = {user_id}")
    
    ALWAYS DO THIS (safe, parameterized):
        execute_raw_sql("SELECT * FROM users WHERE id = :id", {"id": user_id})
    
    Args:
        sql: The SQL query to execute
        params: Optional dictionary of parameters
    
    Returns:
        list: Query results as a list of rows
    
    Raises:
        RuntimeError: If database is not initialized
    """
    if _engine is None:
        raise RuntimeError("Database not initialized!")
    
    async with _engine.begin() as conn:
        if params:
            result = await conn.execute(text(sql), params)
        else:
            result = await conn.execute(text(sql))
        
        return result.fetchall()
