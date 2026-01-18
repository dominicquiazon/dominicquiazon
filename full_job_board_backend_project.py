import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

# Third-party imports
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

# Local application imports
from app.core.config import settings
from app.core.database import init_db, close_db
from app.core.cache import init_cache, close_cache
from app.api.v1 import router as api_v1_router
from app.core.logging_config import setup_logging, get_logger

# =============================================================================
# Application Lifespan Management
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Manage application startup and shutdown events.
    
    This is called when the application starts (before handling requests)
    and when it shuts down (after handling all requests).
    
    WHY ASYNC CONTEXT MANAGER:
        - Clean resource management (open on enter, close on exit)
        - Handles exceptions properly during shutdown
        - FastAPI's recommended approach for lifespan events
    
    STARTUP:
        1. Set up logging
        2. Initialize database connection pool
        3. Initialize Redis cache connection
        4. Any other initialization needed
    
    SHUTDOWN:
        1. Close all database connections
        2. Close Redis connection
        3. Cleanup any background tasks
    """
    # =========================================================================
    # STARTUP - Runs before first request
    # =========================================================================
    
    # Set up structured logging
    setup_logging()
    logger = get_logger(__name__)
    logger.info("Starting Job Board Backend API...")
    
    # Initialize database connection
    # This creates a connection pool that's shared across all requests
    # Pool size is configured in settings (default: 5-20 connections)
    logger.info("Initializing database connection pool...")
    await init_db()
    logger.info("Database connection pool ready")
    
    # Initialize Redis cache connection
    # Redis is used for caching search results and rate limiting
    logger.info("Initializing Redis cache connection...")
    await init_cache()
    logger.info("Redis cache connection ready")
    
    logger.info(
        f"Job Board API started successfully",
        extra={
            "environment": settings.ENVIRONMENT,
            "debug_mode": settings.DEBUG,
            "api_version": "v1"
        }
    )
    
    # The 'yield' statement separates startup from shutdown code
    # Everything before yield runs at startup
    # Everything after yield runs at shutdown
    yield
    
    # =========================================================================
    # SHUTDOWN - Runs when application is stopping
    # =========================================================================
    logger = get_logger(__name__)
    logger.info("Shutting down Job Board Backend API...")
    
    # Close database connections gracefully
    # This ensures all pending queries complete before shutdown
    logger.info("Closing database connections...")
    await close_db()
    
    # Close Redis connection
    logger.info("Closing Redis connection...")
    await close_cache()
    
    logger.info("Job Board API shutdown complete")


# =============================================================================
# Create FastAPI Application
# =============================================================================

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
    ## Scalable Job Board Backend API
    
    A production-ready backend service for a job board platform.
    
    ### Features:
    * **Job Listings**: Create, search, and manage job postings
    * **Applications**: Submit and track job applications
    * **User Management**: Registration, authentication, profiles
    * **Smart Search**: Full-text search with filters and pagination
    
    ### Authentication:
    This API uses JWT (JSON Web Tokens) for authentication.
    Include the token in the Authorization header:
    `Authorization: Bearer <your_token>`
    
    ### Rate Limiting:
    - Anonymous: 100 requests/minute
    - Authenticated: 1000 requests/minute
    """,
    version="1.0.0",
    
    # OpenAPI documentation URLs
    docs_url="/docs",           # Swagger UI at /docs
    redoc_url="/redoc",        # ReDoc at /redoc
    openapi_url="/openapi.json",  # OpenAPI schema
    
    # Lifespan context manager for startup/shutdown
    lifespan=lifespan,
    
    # Contact information (appears in docs)
    contact={
        "name": "Job Board API Support",
        "email": "support@jobboard.example.com",
    },
    
    # License information
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)


# =============================================================================
# Middleware Configuration
# =============================================================================

# -----------------------------------------------------------------------------
# CORS (Cross-Origin Resource Sharing) Middleware
# -----------------------------------------------------------------------------
# 
# CORS allows web applications from different domains to access this API.
# Without CORS, browsers block requests from different origins.

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,  # Configured in settings
    allow_credentials=True,  # Allow cookies/auth headers
    allow_methods=["*"],     # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],     # Allow all headers
)


# -----------------------------------------------------------------------------
# Request Logging Middleware
# -----------------------------------------------------------------------------
#
# This middleware logs every incoming request with:
# - HTTP method (GET, POST, etc.)
# - URL path
# - Processing time
# - Response status code
#
# WHY THIS MATTERS:
# - Debugging: Find slow endpoints
# - Monitoring: Track request patterns
# - Security: Audit trail of API access
#
# TIME COMPLEXITY: O(1) - just timestamps and string operations

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Log all incoming requests with timing information.
    
    Args:
        request: The incoming HTTP request
        call_next: Function to call the next middleware/handler
    
    Returns:
        The response from the handler
    """
    # Record start time for measuring request duration
    start_time = time.time()
    
    # Generate a unique request ID for tracing
    # This helps correlate logs from the same request
    request_id = f"{time.time():.6f}"
    
    # Add request ID to request state for use in handlers
    request.state.request_id = request_id
    
    # Get logger
    logger = get_logger(__name__)
    
    # Log the incoming request
    logger.info(
        f"Request started: {request.method} {request.url.path}",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "client_ip": request.client.host if request.client else "unknown",
        }
    )
    
    try:
        # Process the request
        # This calls the next middleware or the actual route handler
        response = await call_next(request)
        
        # Calculate how long the request took
        process_time = time.time() - start_time
        
        # Add timing header to response
        # X-Process-Time header shows how long the server took
        response.headers["X-Process-Time"] = f"{process_time:.4f}"
        response.headers["X-Request-ID"] = request_id
        
        # Log the completed request
        logger.info(
            f"Request completed: {request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "process_time_ms": round(process_time * 1000, 2),
            }
        )
        
        return response
        
    except Exception as e:
        # Log any unhandled exceptions
        process_time = time.time() - start_time
        logger.error(
            f"Request failed: {request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "error": str(e),
                "process_time_ms": round(process_time * 1000, 2),
            },
            exc_info=True
        )
        raise


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handle Pydantic validation errors.
    
    When request data doesn't match the expected schema, Pydantic raises
    a RequestValidationError. This handler converts it to a user-friendly
    JSON response.
    
    WHY CUSTOM HANDLER:
        - Default error messages can be confusing
        - We want consistent error format across all endpoints
        - Better for frontend developers to parse
    
    Args:
        request: The HTTP request that caused the error
        exc: The validation exception with error details
    
    Returns:
        JSONResponse with 422 status and error details
    """
    # Extract and format validation errors
    errors = []
    for error in exc.errors():
        # 'loc' is the location of the error (e.g., ['body', 'email'])
        # 'msg' is the human-readable error message
        # 'type' is the error type (e.g., 'value_error.email')
        errors.append({
            "field": " -> ".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "error",
            "message": "Validation error",
            "detail": errors,
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Handle all uncaught exceptions.
    
    This is a catch-all handler for any exception that wasn't handled
    elsewhere. It ensures we always return a proper JSON response
    instead of an HTML error page.
    
    SECURITY NOTE:
        - In production, we don't include exception details in the response
        - This prevents leaking sensitive information
        - Full details are logged server-side for debugging
    
    Args:
        request: The HTTP request that caused the error
        exc: The unhandled exception
    
    Returns:
        JSONResponse with 500 status
    """
    logger = get_logger(__name__)
    
    # Log the full exception for debugging
    logger.error(
        f"Unhandled exception: {type(exc).__name__}: {str(exc)}",
        extra={
            "request_id": getattr(request.state, "request_id", "unknown"),
            "path": request.url.path,
        },
        exc_info=True
    )
    
    # Return generic error to client
    # Don't include exception details in production
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "message": "Internal server error",
            # Only include details in debug mode
            "detail": str(exc) if settings.DEBUG else None,
        }
    )


# =============================================================================
# Register API Routers
# =============================================================================

# Include the v1 API router
# All v1 endpoints will be prefixed with /api/v1
# Example: /api/v1/jobs, /api/v1/users, /api/v1/auth
app.include_router(
    api_v1_router,
    prefix="/api/v1",
    tags=["v1"]
)


# =============================================================================
# Health Check Endpoints
# =============================================================================

@app.get(
    "/health",
    tags=["Health"],
    summary="Health check endpoint",
    description="Returns the health status of the API. Used by load balancers and monitoring systems.",
)
async def health_check():
    """
    Basic health check endpoint.
    
    This endpoint is used by:
    - Load balancers to check if the instance is healthy
    - Kubernetes liveness probes
    - Monitoring systems
    
    WHY SEPARATE FROM /health/detailed:
        - This endpoint should be as fast as possible
        - No database/cache checks here
        - Just confirms the API process is running
    
    Returns:
        dict: Status message
    
    TIME COMPLEXITY: O(1) - just returns a static response
    """
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": "1.0.0"
    }


@app.get(
    "/health/detailed",
    tags=["Health"],
    summary="Detailed health check",
    description="Returns detailed health status including database and cache connectivity.",
)
async def detailed_health_check():
    """
    Detailed health check with dependency checks.
    
    Checks connectivity to:
    - PostgreSQL database
    - Redis cache
    
    Returns:
        dict: Detailed status of all dependencies
    
    TIME COMPLEXITY: O(1) for each check (simple ping queries)
    """
    from app.core.database import check_db_health
    from app.core.cache import check_cache_health
    
    # Check each dependency
    db_healthy = await check_db_health()
    cache_healthy = await check_cache_health()
    
    # Overall health is healthy only if all dependencies are healthy
    overall_healthy = db_healthy and cache_healthy
    
    return {
        "status": "healthy" if overall_healthy else "unhealthy",
        "service": settings.PROJECT_NAME,
        "version": "1.0.0",
        "dependencies": {
            "database": {
                "status": "healthy" if db_healthy else "unhealthy",
                "type": "postgresql"
            },
            "cache": {
                "status": "healthy" if cache_healthy else "unhealthy",
                "type": "redis"
            }
        }
    }


# =============================================================================
# Root Endpoint
# =============================================================================

@app.get(
    "/",
    tags=["Root"],
    summary="API root endpoint",
    description="Returns basic API information and links to documentation.",
)
async def root():
    """
    Root endpoint with API information.
    
    Provides:
    - API name and version
    - Links to documentation
    - Link to health check
    
    This is helpful for developers discovering the API.
    
    Returns:
        dict: API information and documentation links
    """
    return {
        "name": settings.PROJECT_NAME,
        "version": "1.0.0",
        "description": "Scalable Job Board Backend API",
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json"
        },
        "health": "/health",
        "api_base": "/api/v1"
    }


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    """
    Run the application directly with Python.
    
    WHY UVICORN FOR PRODUCTION:
        - Properly handles multiple workers
        - Better signal handling (graceful shutdown)
        - Production-tested
    """
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,  # Auto-reload in debug mode
        log_level="debug" if settings.DEBUG else "info"
    )

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application settings with validation.
    
    Each attribute can be set via environment variable of the same name
    (case-insensitive).
    
    Attributes are validated on load - if a required value is missing
    or has the wrong type, the application won't start.
    """
    
    # =========================================================================
    # Application Settings
    # =========================================================================
    
    PROJECT_NAME: str = "Job Board API"
    """Name of the application, used in API docs and logs"""
    
    ENVIRONMENT: str = "development"
    """
    Current environment: development, staging, or production
    
    This affects:
    - Log verbosity
    - Error detail in responses
    - Some security settings
    """
    
    DEBUG: bool = True
    """
    Enable debug mode.
    
    When True:
    - More detailed error messages
    - Auto-reload on code changes (with uvicorn --reload)
    - More verbose logging
    
    ALWAYS set to False in production PLS!
    """
    
    # =========================================================================
    # Server Settings
    # =========================================================================
    
    HOST: str = "0.0.0.0"
    """Host to bind the server to. 0.0.0.0 allows external connections."""
    
    PORT: int = 8000
    """Port to run the server on."""
    
    # =========================================================================
    # Database Settings
    # =========================================================================
    
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/jobboard"
    """
        PostgreSQL connection URL.
        
        Format: postgresql+asyncpg://user:password@host:port/database
        
        Components:
        - postgresql+asyncpg: Use asyncpg driver for async support
        - user:password: Database credentials
        - host:port: Database server location
        - database: Database name
    
        
        DATABASE_POOL_SIZE: int = 5
    """
    
    DATABASE_MAX_OVERFLOW: int = 10
    """
    Maximum additional connections above pool_size.
    
    When all pooled connections are in use, new requests can create
    up to this many extra connections. They're closed when done.
    
    Total max connections = pool_size + max_overflow = 5 + 10 = 15
    """
    
    # =========================================================================
    # Redis Cache Settings
    # =========================================================================
    
    REDIS_URL: str = "redis://localhost:6379/0"
    """
    Redis connection URL.
    
    Format: redis://host:port/database_number 
    """
    
    CACHE_DEFAULT_TTL: int = 300
    
    CACHE_SEARCH_TTL: int = 120
    """
    Cache TTL for search results in seconds.
    
    Search results cached for 2 minutes because:
    - New jobs should appear relatively quickly
    - But caching still helps with popular searches
    """
    
    # =========================================================================
    # Authentication Settings
    # =========================================================================
    
    SECRET_KEY: str = "your-super-secret-key-change-this-in-production-please"
    """
    Secret key for JWT token signing.
    
    CRITICAL SECURITY:
    - MUST be changed in production
    - Should be at least 32 characters
    - Use: openssl rand -hex 32 to generate
    - Store in environment variable, never in code
    
    """
    
    ALGORITHM: str = "HS256"
    """
    JWT signing algorithm.
    
    HS256 = HMAC-SHA256
    - Symmetric: Same key for signing and verifying
    - Fast and widely supported
    - Suitable for most applications
    
    Alternative: RS256 for asymmetric (public/private key pairs)
    """
    
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    """
    How long access tokens are valid.
    
    30 minutes is a reasonable balance:
    - Long enough that users don't need to re-login constantly
    - Short enough to limit damage if token is stolen
    
    Combined with refresh tokens for longer sessions.
    """
    
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    """
    How long refresh tokens are valid.
    
    Refresh tokens:
    - Used to get new access tokens without re-entering password
    - Should be stored securely (httpOnly cookie)
    - Longer lived than access tokens
    """
    
    # =========================================================================
    # CORS Settings
    # =========================================================================
    
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",      # React default dev server
        "http://localhost:5173",      # Vite default dev server
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]
    """
    Allowed origins for CORS (Cross-Origin Resource Sharing).
    
    These are the domains allowed to make requests to this API.
    
    IN PRODUCTION:
    - Remove localhost entries
    - Add your actual frontend domain(s)
    - Example: ["https://myapp.com", "https://www.myapp.com"]
    """
    
    # =========================================================================
    # Rate Limiting Settings
    # =========================================================================
    
    RATE_LIMIT_ANONYMOUS: int = 100
    """
    Rate limit for unauthenticated requests per minute.
    
    Lower limit for anonymous users to prevent abuse.
    """
    
    RATE_LIMIT_AUTHENTICATED: int = 1000
    """
    Rate limit for authenticated requests per minute.
    
    Higher limit for logged-in users who we can identify and trust more.
    """
    
    # =========================================================================
    # Pagination Settings
    # =========================================================================
    
    DEFAULT_PAGE_SIZE: int = 20
    """
    Default number of items per page when not specified.
    
    20 is a common default:
    - Enough items to be useful
    - Not too many to slow down responses
    """
    
    MAX_PAGE_SIZE: int = 100
    """
    Maximum items per page.
    
    Prevents clients from requesting huge pages that could:
    - Slow down the database
    - Use too much memory
    - Create large response payloads
    """
    
    # =========================================================================
    # Background Task Settings
    # =========================================================================
    
    TASK_WORKER_COUNT: int = 2
    """Number of background task workers."""
    
    EMAIL_SIMULATION_DELAY: float = 0.5
  
    # =========================================================================
    # Logging Settings
    # =========================================================================
    
    LOG_LEVEL: str = "INFO"
    """
    Minimum log level to output.
    
    Levels (from lowest to highest):
    - DEBUG: Detailed information for debugging
    - INFO: General information about application flow
    - WARNING: Something unexpected but not an error
    - ERROR: Something failed
    - CRITICAL: Application cannot continue
    """
    
    LOG_FORMAT: str = "json"
    
    # =========================================================================
    # Pydantic Settings Configuration
    # =========================================================================
    
    model_config = SettingsConfigDict(
        # Load .env file if it exists
        env_file=".env",
        # .env file is optional
        env_file_encoding="utf-8",
        # Environment variables are case-insensitive
        case_sensitive=False,
        # Allow extra fields from environment
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """ 
    Returns:
        Settings: The application settings instance
    """
    return Settings()


# Create a module-level instance for easy importing
# Usage: from app.core.config import settings
settings = get_settings()


# =============================================================================
# Configuration Validation
# =============================================================================

def validate_settings() -> None:
    """
    Validate critical settings at startup.
    
    This function checks that settings are configured correctly
    for the current environment. It's called during application startup.
    
    Raises:
        ValueError: If critical settings are misconfigured
    """
    # Check for default secret key in production
    if settings.ENVIRONMENT == "production":
        if "change-this" in settings.SECRET_KEY.lower():
            raise ValueError(
                "SECRET_KEY contains default value! "
                "You MUST set a secure SECRET_KEY in production. "
                "Generate one with: openssl rand -hex 32"
            )
        
        if settings.DEBUG:
            raise ValueError(
                "DEBUG must be False in production! "
                "Set DEBUG=false in your environment."
            )
    
    # Validate database URL format
    if not settings.DATABASE_URL.startswith("postgresql"):
        raise ValueError(
            "DATABASE_URL must start with 'postgresql' "
            f"Got: {settings.DATABASE_URL[:20]}..."
        )


# =============================================================================
# Environment-Specific Helpers
# =============================================================================

def is_development() -> bool:
    """Check if running in development environment."""
    return settings.ENVIRONMENT.lower() == "development"


def is_production() -> bool:
    """Check if running in production environment."""
    return settings.ENVIRONMENT.lower() == "production"


def is_testing() -> bool:
    """Check if running in testing environment."""
    return settings.ENVIRONMENT.lower() == "testing"

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
    
import json
import hashlib
from typing import Any, Optional, Union
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.logging_config import get_logger

# Get logger for this module
logger = get_logger(__name__)

# Global Redis client instance
_redis_client: Optional[Redis] = None


# =============================================================================
# Connection Management
# =============================================================================

async def init_cache() -> None:
    """
    Initialize the Redis connection.
    
    This should be called once at application startup.
    
    Redis Connection URL Format:
        redis://[[username]:[password]@]host[:port][/database]
    
    Examples:
        - redis://localhost:6379/0 (local, no auth, database 0)
        - redis://:password@myredis.com:6379/1 (remote with password)
    
    DATABASE NUMBERS (0-15 by default):
        - Database 0: Main cache
        - Database 1: Sessions (if separate)
        - Database 2: Rate limiting (if separate)
    
    Raises:
        Exception: If Redis connection fails
    """
    global _redis_client
    
    logger.info("Connecting to Redis cache...")
    
    # Create Redis client
    # decode_responses=True automatically decodes bytes to strings
    _redis_client = Redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,  # Return strings instead of bytes
        socket_connect_timeout=5,  # Connection timeout in seconds
        socket_timeout=5,  # Operation timeout in seconds
    )
    
    # Test the connection
    await _redis_client.ping()
    
    logger.info(
        "Redis cache connected",
        extra={"url": settings.REDIS_URL.split("@")[-1]}  # Hide password in logs
    )


async def close_cache() -> None:
    """
    Close the Redis connection.
    
    Should be called when the application shuts down.
    """
    global _redis_client
    
    if _redis_client is not None:
        logger.info("Closing Redis connection...")
        await _redis_client.close()
        _redis_client = None
        logger.info("Redis connection closed")


def get_redis() -> Redis:
    """
    Get the Redis client instance.
    
    Returns:
        Redis: The Redis client
    
    Raises:
        RuntimeError: If Redis is not initialized
    """
    if _redis_client is None:
        raise RuntimeError(
            "Redis not initialized! "
            "Call init_cache() before using cache."
        )
    return _redis_client


async def check_cache_health() -> bool:
    """
    Check if Redis is healthy and responding.
    
    Used by health check endpoints.
    
    Returns:
        bool: True if Redis is healthy, False otherwise
    """
    if _redis_client is None:
        return False
    
    try:
        await _redis_client.ping()
        return True
    except RedisError as e:
        logger.error(f"Redis health check failed: {e}")
        return False


# =============================================================================
# Core Cache Operations
# =============================================================================

async def cache_get(key: str) -> Optional[str]:
    """
    Get a value from the cache.
    
    TIME COMPLEXITY: O(1)
    
    Args:
        key: The cache key to retrieve
    
    Returns:
        Optional[str]: The cached value or None if not found
    
    Example:
        value = await cache_get("job:123")
        if value:
            job = json.loads(value)
    """
    if _redis_client is None:
        return None
    
    try:
        value = await _redis_client.get(key)
        if value:
            logger.debug(f"Cache HIT: {key}")
        else:
            logger.debug(f"Cache MISS: {key}")
        return value
    except RedisError as e:
        # Log error but don't crash - cache is optional
        logger.warning(f"Cache get failed for {key}: {e}")
        return None


async def cache_set(
    key: str,
    value: str,
    ttl: int = None
) -> bool:
    """
    Set a value in the cache with optional TTL.
    
    TIME COMPLEXITY: O(1)
    
    TTL (Time To Live):
        - After TTL seconds, key is automatically deleted
        - If not specified, uses default from settings
        - Set to 0 or None for no expiration (not recommended)
    
    Args:
        key: The cache key
        value: The value to store (must be a string)
        ttl: Time to live in seconds (optional)
    
    Returns:
        bool: True if successful, False otherwise
    
    Example:
        job_json = json.dumps(job.dict())
        await cache_set("job:123", job_json, ttl=300)
    """
    if _redis_client is None:
        return False
    
    # Use default TTL if not specified
    if ttl is None:
        ttl = settings.CACHE_DEFAULT_TTL
    
    try:
        if ttl > 0:
            # SETEX: SET with EXpiration
            await _redis_client.setex(key, ttl, value)
        else:
            # SET without expiration
            await _redis_client.set(key, value)
        
        logger.debug(f"Cache SET: {key} (TTL: {ttl}s)")
        return True
    except RedisError as e:
        logger.warning(f"Cache set failed for {key}: {e}")
        return False


async def cache_delete(key: str) -> bool:
    """
    Delete a key from the cache.
    
    TIME COMPLEXITY: O(1)
    
    Used for cache invalidation when data changes.
    
    Args:
        key: The cache key to delete
    
    Returns:
        bool: True if key existed and was deleted, False otherwise
    
    Example:
        # When job is updated
        await cache_delete(f"job:{job_id}")
    """
    if _redis_client is None:
        return False
    
    try:
        result = await _redis_client.delete(key)
        logger.debug(f"Cache DELETE: {key} (existed: {result > 0})")
        return result > 0
    except RedisError as e:
        logger.warning(f"Cache delete failed for {key}: {e}")
        return False


async def cache_delete_pattern(pattern: str) -> int:
    """
    Delete all keys matching a pattern.
    
    TIME COMPLEXITY: O(n) where n is the number of keys
    
    PATTERNS:
        - * matches any characters
        - ? matches one character
        - [abc] matches a, b, or c
    
    Args:
        pattern: Redis pattern (e.g., "search:*" deletes all search keys)
    
    Returns:
        int: Number of keys deleted
    
    Example:
        # Invalidate all search results when jobs change
        await cache_delete_pattern("search:*")
    """
    if _redis_client is None:
        return 0
    
    try:
        # Find all matching keys
        keys = []
        async for key in _redis_client.scan_iter(match=pattern):
            keys.append(key)
        
        # Delete them (if any exist)
        if keys:
            deleted = await _redis_client.delete(*keys)
            logger.debug(f"Cache DELETE pattern {pattern}: {deleted} keys")
            return deleted
        return 0
    except RedisError as e:
        logger.warning(f"Cache delete pattern failed for {pattern}: {e}")
        return 0


# =============================================================================
# JSON Cache Helpers
# =============================================================================

async def cache_get_json(key: str) -> Optional[Any]:
    """
    Get a JSON value from the cache and deserialize it.
    
    This is a convenience wrapper around cache_get that handles
    JSON deserialization automatically.
    
    Args:
        key: The cache key
    
    Returns:
        Optional[Any]: The deserialized Python object or None
    
    """
    value = await cache_get(key)
    if value is None:
        return None
    
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to decode cached JSON for {key}: {e}")
        # Delete corrupted cache entry
        await cache_delete(key)
        return None


async def cache_set_json(
    key: str,
    value: Any,
    ttl: int = None
) -> bool:
    """
    Serialize a Python object to JSON and store in cache.
    
    Args:
        key: The cache key
        value: Any JSON-serializable Python object
        ttl: Time to live in seconds (optional)
    
    Returns:
        bool: True if successful, False otherwise
    
    """
    try:
        json_value = json.dumps(value, default=str)
        return await cache_set(key, json_value, ttl)
    except (TypeError, ValueError) as e:
        logger.warning(f"Failed to serialize value for {key}: {e}")
        return False


# =============================================================================
# Cache Key Generators
# =============================================================================

def make_cache_key(prefix: str, *args, **kwargs) -> str:
    """
    Generate a consistent cache key from arguments.
    
    This creates deterministic keys for caching query results.
    
    KEY FORMAT:
        prefix:hash_of_args
    
    Args:
        prefix: Key prefix (e.g., "search", "job", "user")
        *args: Positional arguments to include in key
        **kwargs: Keyword arguments to include in key
    
    Returns:
        str: A cache key like "search:abc123def456"
    """
    # Create a string representation of all arguments
    key_data = json.dumps({
        "args": args,
        "kwargs": kwargs
    }, sort_keys=True, default=str)
    
    # Hash it for consistent length
    hash_value = hashlib.md5(key_data.encode()).hexdigest()
    
    return f"{prefix}:{hash_value}"


def make_job_cache_key(job_id: str) -> str:
    """Generate cache key for a job."""
    return f"job:{job_id}"


def make_user_cache_key(user_id: str) -> str:
    """Generate cache key for a user."""
    return f"user:{user_id}"


def make_search_cache_key(**search_params) -> str:
    """
    Generate cache key for search results.
    
    Search results are cached by their query parameters.
    Same query = same cache key = cache hit.
    
    Args:
        **search_params: All search parameters (query, filters, page, etc.)
    
    Returns:
        str: Cache key for these search parameters
    """
    return make_cache_key("search", **search_params)


# =============================================================================
# Cache-Aside Pattern Helper
# =============================================================================

async def get_or_set(
    key: str,
    fetch_func,
    ttl: int = None
) -> Optional[Any]:
   
    # Try cache first
    cached = await cache_get_json(key)
    if cached is not None:
        return cached
    
    # Cache miss - fetch the data
    result = await fetch_func()
    
    # Store in cache if we got a result
    if result is not None:
        await cache_set_json(key, result, ttl)
    
    return result


# =============================================================================
# Rate Limiting (Bonus Feature)
# =============================================================================

async def rate_limit_check(
    key: str,
    limit: int,
    window_seconds: int
) -> tuple[bool, int]:
    """
    Check and update rate limit counter.
    
    Uses a sliding window counter in Redis.
    
    HOW IT WORKS:
    - Key stores the count of requests in the current window
    - Key expires after window_seconds
    - Each request increments the counter
    - If counter > limit, request is rate limited
    
    Args:
        key: Unique identifier (e.g., "ratelimit:ip:192.168.1.1")
        limit: Maximum requests allowed in window
        window_seconds: Time window in seconds
    
    Returns:
        tuple[bool, int]: (allowed, remaining)
            - allowed: True if request is allowed
            - remaining: Number of requests remaining in window
    
    Example:
        allowed, remaining = await rate_limit_check(
            f"ratelimit:user:{user_id}",
            limit=100,
            window_seconds=60
        )
        if not allowed:
            raise HTTPException(429, "Too many requests")
    """
    if _redis_client is None:
        # If Redis is down, allow all requests
        return True, limit
    
    try:
        # INCR increments the counter and returns the new value
        # If key doesn't exist, it's created with value 1
        count = await _redis_client.incr(key)
        
        # Set expiration on first request in window
        if count == 1:
            await _redis_client.expire(key, window_seconds)
        
        # Check if over limit
        allowed = count <= limit
        remaining = max(0, limit - count)
        
        return allowed, remaining
        
    except RedisError as e:
        logger.warning(f"Rate limit check failed: {e}")
        # Fail open - allow the request
        return True, limit
    
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db
from app.core.logging_config import get_logger
from app.models.user import User

# Get logger for this module
logger = get_logger(__name__)


# =============================================================================
# Password Hashing Configuration
# =============================================================================

# CryptContext manages password hashing algorithms
# We use bcrypt as the primary scheme
pwd_context = CryptContext(
    schemes=["bcrypt"],
    # deprecated="auto" means if we add new schemes in the future,
    # old hashes will still work but will be upgraded on next login
    deprecated="auto"
)


# =============================================================================
# OAuth2 Scheme Configuration
# =============================================================================

# This tells FastAPI where to look for the token
# tokenUrl is the endpoint where clients can get a token
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    # auto_error=True means it will automatically raise 401 if no token
    auto_error=True
)

# Optional version - doesn't raise error if no token
oauth2_scheme_optional = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=False
)


# =============================================================================
# Password Functions
# =============================================================================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    #Verify a password against its hash.
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    #Hash a password using bcrypt.
    return pwd_context.hash(password)


# =============================================================================
# JWT Token Functions
# =============================================================================

def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    additional_claims: dict = None
) -> str:
    """
    Create a JWT access token.
    
    TOKEN STRUCTURE:
        {
            "sub": "user_id",        # Subject (who the token is for)
            "exp": 1234567890,       # Expiration time
            "iat": 1234567800,       # Issued at time
            "type": "access",        # Token type
            ...additional_claims
        }
    
    Args:
        subject: Usually the user ID
        expires_delta: How long until token expires
        additional_claims: Extra data to include in token
    
    Returns:
        str: The encoded JWT token
    
    Example:
        token = create_access_token(
            subject=user.id,
            additional_claims={"role": "employer"}
        )
    """
    # Set expiration time
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    # Build the payload
    to_encode = {
        "sub": str(subject),  # Subject (user ID)
        "exp": expire,        # Expiration time
        "iat": datetime.now(timezone.utc),  # Issued at
        "type": "access"      # Token type
    }
    
    # Add any additional claims
    if additional_claims:
        to_encode.update(additional_claims)
    
    # Encode the token
    # jwt.encode(payload, secret_key, algorithm)
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    logger.debug(f"Created access token for subject: {subject}")
    return encoded_jwt


def create_refresh_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT refresh token.
    
    REFRESH TOKENS vs ACCESS TOKENS:
    
    Access Token:
        - Short-lived (30 minutes)
        - Sent with every API request
        - Contains user claims
    
    Refresh Token:
        - Long-lived (7 days)
        - Used only to get new access tokens
        - Stored securely (httpOnly cookie)
    
    WHY TWO TOKENS:
        - If access token is stolen, damage is limited (30 min)
        - Refresh token is used less frequently, harder to steal
        - Can revoke refresh tokens without logging everyone out
    
    Args:
        subject: Usually the user ID
        expires_delta: How long until token expires
    
    Returns:
        str: The encoded JWT refresh token
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
    
    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh"  # Different type than access token
    }
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    logger.debug(f"Created refresh token for subject: {subject}")
    return encoded_jwt


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    
    VALIDATION CHECKS:
    1. Signature is valid (not tampered with)
    2. Token is not expired
    3. Token structure is correct
    
    Args:
        token: The JWT token string
    
    Returns:
        dict: The decoded token payload
    
    Raises:
        JWTError: If token is invalid or expired
    """
    # jwt.decode automatically validates signature and expiration
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    return payload


# =============================================================================
# Authentication Dependencies
# =============================================================================

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    FastAPI dependency that returns the current authenticated user.
    
    HOW FASTAPI DEPENDENCIES WORK:
        Dependencies are called automatically before your route handler.
        They can have their own dependencies (like this one depends on
        oauth2_scheme and get_db).
    
    FLOW:
        1. oauth2_scheme extracts token from Authorization header
        2. We decode and validate the token
        3. We look up the user in the database
        4. We return the user object
    
    Usage in route:
        @app.get("/profile")
        async def get_profile(user: User = Depends(get_current_user)):
            return user
    
    Args:
        token: JWT token (injected by oauth2_scheme)
        db: Database session (injected by get_db)
    
    Returns:
        User: The authenticated user object
    
    Raises:
        HTTPException: 401 if authentication fails
    """
    # Define the exception we'll raise on auth failure
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode the token
        payload = decode_token(token)
        
        # Extract user ID from the "sub" (subject) claim
        user_id: str = payload.get("sub")
        if user_id is None:
            logger.warning("Token missing 'sub' claim")
            raise credentials_exception
        
        # Verify it's an access token (not a refresh token)
        token_type = payload.get("type")
        if token_type != "access":
            logger.warning(f"Invalid token type: {token_type}")
            raise credentials_exception
            
    except JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        raise credentials_exception
    
    # Look up the user in the database
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if user is None:
        logger.warning(f"User not found for ID: {user_id}")
        raise credentials_exception
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )
    
    return user


async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme_optional),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """
    Get current user if authenticated, None otherwise.
    
    Useful for endpoints that work for both authenticated and
    anonymous users, but behave differently.
    
    Example:
        @app.get("/jobs")
        async def list_jobs(user: Optional[User] = Depends(get_current_user_optional)):
            if user:
                # Return personalized results
                pass
            else:
                # Return generic results
                pass
    """
    if token is None:
        return None
    
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None


async def get_current_active_employer(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency that ensures the current user is an employer.
    
    This is a layered dependency:
        1. get_current_user runs first (validates token, gets user)
        2. Then this checks if the user has employer role
    
    Usage:
        @app.post("/jobs")
        async def create_job(employer: User = Depends(get_current_active_employer)):
            # Only employers can reach this code
            pass
    
    Args:
        current_user: The authenticated user (from get_current_user)
    
    Returns:
        User: The employer user
    
    Raises:
        HTTPException: 403 if user is not an employer
    """
    if current_user.role != "employer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only employers can perform this action"
        )
    return current_user


async def get_current_active_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency that ensures the current user is an admin.
    
    Admins have special privileges like:
        - View all users
        - Moderate content
        - System configuration
    
    Args:
        current_user: The authenticated user
    
    Returns:
        User: The admin user
    
    Raises:
        HTTPException: 403 if user is not an admin
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


# =============================================================================
# Utility Functions
# =============================================================================

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    REQUIREMENTS:
        - At least 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
    
    WHY THESE REQUIREMENTS:
        - Longer passwords are harder to crack
        - Mixed characters increase the search space
        - Makes dictionary attacks harder
    
    Args:
        password: The password to validate
    
    Returns:
        tuple[bool, str]: (is_valid, error_message)
    
    Example:
        valid, error = validate_password_strength("weak")
        # valid = False, error = "Password must be at least 8 characters"
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    return True, ""


def generate_password_reset_token(email: str) -> str:
    """
    Generate a token for password reset.
    
    Similar to access token but:
        - Shorter expiration (1 hour)
        - Includes email for verification
        - Type is "password_reset"
    
    Args:
        email: The user's email address
    
    Returns:
        str: The password reset token
    """
    expire = datetime.now(timezone.utc) + timedelta(hours=1)
    
    to_encode = {
        "sub": email,
        "exp": expire,
        "type": "password_reset"
    }
    
    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )


def verify_password_reset_token(token: str) -> Optional[str]:
    """
    Verify a password reset token and return the email.
    
    Args:
        token: The password reset token
    
    Returns:
        Optional[str]: The email address if valid, None otherwise
    """
    try:
        payload = decode_token(token)
        
        # Verify it's a password reset token
        if payload.get("type") != "password_reset":
            return None
        
        return payload.get("sub")
        
    except JWTError:
        return None

import logging
import sys
from typing import Optional

import structlog
from structlog.types import Processor

from app.core.config import settings


def setup_logging() -> None:
    """
    Configure structured logging for the application.
    
    This should be called once at application startup.
    
    """
    
    # Determine if we're in development
    is_dev = settings.ENVIRONMENT == "development"
    
    # Convert log level string to logging constant
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    
    # ==========================================================================
    # Configure Standard Library Logging
    # ==========================================================================
    
    # Reset any existing configuration
    logging.root.handlers = []
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Set format based on environment
    if is_dev:
        # Human-readable format for development
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        # JSON-ish format for production (structlog will handle actual JSON)
        formatter = logging.Formatter(
            fmt="%(message)s"
        )
    
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    logging.root.setLevel(log_level)
    logging.root.addHandler(console_handler)
    
    # ==========================================================================
    # Configure Structlog
    # ==========================================================================
    
    # Shared processors for all environments
    # Processors transform log events before output
    shared_processors: list[Processor] = [
        # Add log level to the event
        structlog.stdlib.add_log_level,
        # Add logger name
        structlog.stdlib.add_logger_name,
        # Add timestamp in ISO format
        structlog.processors.TimeStamper(fmt="iso"),
        # Add call location (file, function, line number) in debug mode
        structlog.processors.CallsiteParameterAdder(
            [
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            ]
        ) if is_dev else structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        # Process stack info for exceptions
        structlog.processors.StackInfoRenderer(),
        # Format exceptions nicely
        structlog.processors.format_exc_info,
    ]
    
    if is_dev:
        # Development: Pretty, colored console output
        processors = shared_processors + [
            # Remove internal structlog keys
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            # Render to colored, readable format
            structlog.dev.ConsoleRenderer(colors=True)
        ]
    else:
        # Production: JSON output for log aggregation
        processors = shared_processors + [
            # Remove internal structlog keys
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            # Render to JSON
            structlog.processors.JSONRenderer()
        ]
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # ==========================================================================
    # Configure Third-Party Loggers
    # ==========================================================================
    
    # Reduce noise from third-party libraries
    # These can be very verbose at DEBUG level
    
    # SQLAlchemy - only show warnings and above
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)
    
    # Uvicorn - reduce access log noise
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    # HTTPX - HTTP client library
    logging.getLogger("httpx").setLevel(logging.WARNING)
    
    # AsyncIO - can be noisy
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a logger instance for a module.
    
    This returns a structlog logger that supports both:
    - Traditional logging: logger.info("message")
    - Structured logging: logger.info("event", user_id=123, action="login")
    
    Args:
        name: Usually __name__ (module name)
    
    Returns:
        structlog.BoundLogger: A logger instance
    
    Example:
        from app.core.logging_config import get_logger
        
        logger = get_logger(__name__)
        
        # Simple message
        logger.info("Application started")
        
        # With context
        logger.info(
            "User logged in",
            user_id=123,
            ip_address="192.168.1.1",
            method="password"
        )
        
        # With exception
        try:
            risky_operation()
        except Exception:
            logger.exception("Operation failed")
    """
    return structlog.get_logger(name)


class LoggingContextManager:
    """
    Context manager for adding temporary context to logs.
    
    Useful when you want to add context to all logs within a block,
    like a request ID or user ID.
    
    """
    
    def __init__(self, **context):
        """
        Initialize with context to add to all logs.
        
        Args:
            **context: Key-value pairs to add to log context
        """
        self.context = context
        self.token = None
    
    def __enter__(self):
        """Add context when entering the block."""
        self.token = structlog.contextvars.bind_contextvars(**self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Remove context when exiting the block."""
        structlog.contextvars.unbind_contextvars(*self.context.keys())
        return False  # Don't suppress exceptions


# =============================================================================
# Utility Functions
# =============================================================================

def log_request(
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    request_id: Optional[str] = None,
    user_id: Optional[str] = None,
    **extra
) -> None:
    """
    Log an HTTP request with standard fields.
    
    This ensures consistent request logging across the application.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        path: Request path
        status_code: Response status code
        duration_ms: Request duration in milliseconds
        request_id: Optional request ID for tracing
        user_id: Optional authenticated user ID
        **extra: Additional fields to log
    """
    logger = get_logger("http")
    
    log_data = {
        "method": method,
        "path": path,
        "status_code": status_code,
        "duration_ms": round(duration_ms, 2),
    }
    
    if request_id:
        log_data["request_id"] = request_id
    if user_id:
        log_data["user_id"] = user_id
    
    log_data.update(extra)
    
    # Choose log level based on status code
    if status_code >= 500:
        logger.error("HTTP request failed", **log_data)
    elif status_code >= 400:
        logger.warning("HTTP request error", **log_data)
    else:
        logger.info("HTTP request completed", **log_data)


def log_database_query(
    query_type: str,
    table: str,
    duration_ms: float,
    rows_affected: Optional[int] = None,
    **extra
) -> None:
    """
    Log a database query with standard fields.
    
    Args:
        query_type: Type of query (SELECT, INSERT, UPDATE, DELETE)
        table: Table being queried
        duration_ms: Query duration in milliseconds
        rows_affected: Number of rows affected (for mutations)
        **extra: Additional fields to log
    """
    logger = get_logger("database")
    
    log_data = {
        "query_type": query_type,
        "table": table,
        "duration_ms": round(duration_ms, 2),
    }
    
    if rows_affected is not None:
        log_data["rows_affected"] = rows_affected
    
    log_data.update(extra)
    
    # Only log at debug level to avoid noise
    logger.debug("Database query executed", **log_data)


def log_cache_operation(
    operation: str,
    key: str,
    hit: Optional[bool] = None,
    **extra
) -> None:
    """
    Log a cache operation.
    
    Args:
        operation: Operation type (GET, SET, DELETE)
        key: Cache key
        hit: Whether it was a cache hit (for GET operations)
        **extra: Additional fields to log
    """
    logger = get_logger("cache")
    
    log_data = {
        "operation": operation,
        "key": key,
    }
    
    if hit is not None:
        log_data["hit"] = hit
    
    log_data.update(extra)
    
    logger.debug("Cache operation", **log_data)

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.job import Job


# Application status options
APPLICATION_STATUSES = [
    "pending",     # Just submitted, waiting for review
    "reviewing",   # Employer is actively reviewing
    "accepted",    # Application accepted (interview/offer)
    "rejected",    # Application rejected
    "withdrawn",   # Applicant withdrew their application
]


class Application(Base):
    """
    Application model representing a job application.
    
    TABLE STRUCTURE:
    
        applications
        ├── id (UUID, PRIMARY KEY)        - Unique identifier
        ├── job_id (UUID, FK)             - Job being applied to
        ├── applicant_id (UUID, FK)       - User who applied
        ├── status (VARCHAR)              - Application status
        ├── cover_letter (TEXT)           - Optional cover letter
        ├── resume_url (VARCHAR)          - Link to resume file
        ├── notes (TEXT)                  - Internal notes (employer only)
        ├── created_at (TIMESTAMP)        - When application was submitted
        └── updated_at (TIMESTAMP)        - Last status change
    
    CONSTRAINTS:
        - UNIQUE(job_id, applicant_id) - One application per job per user
        - FK to jobs table
        - FK to users table
    
    INDEXES:
        - PRIMARY KEY on id
        - INDEX on job_id (find all applications for a job)
        - INDEX on applicant_id (find all applications by a user)
        - INDEX on status (filter by status)
        - INDEX on created_at (sort by date)
    """
    
    __tablename__ = "applications"
    
    # ==========================================================================
    # Columns
    # ==========================================================================
    
    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        comment="Unique identifier for the application"
    )
    
    job_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False,
        comment="Job being applied to"
    )
    """
    Foreign key to the job.
    
    ondelete="CASCADE": When job is deleted, applications are too.
    This makes sense - can't have applications for non-existent jobs.
    """
    
    applicant_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        comment="User who submitted this application"
    )
    """Foreign key to the applicant (user)."""
    
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending",
        index=True,
        comment="Application status: pending, reviewing, accepted, rejected, withdrawn"
    )
    """
    Current status of the application.
    
    Status can only be changed by:
    - Employer: pending → reviewing → accepted/rejected
    - Applicant: any → withdrawn
    """
    
    cover_letter: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Optional cover letter from the applicant"
    )
    """
    Optional cover letter.
    
    Stored as TEXT to allow long form content.
    Could be enhanced with Markdown support.
    """
    
    resume_url: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="URL to the applicant's resume file"
    )
    
    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Internal notes for the employer (not visible to applicant)"
    )
    
    # ==========================================================================
    # Relationships
    # ==========================================================================
    
    job: Mapped["Job"] = relationship(
        "Job",
        back_populates="applications",
        lazy="joined"  # Always load job info with application
    )
    
    applicant: Mapped["User"] = relationship(
        "User",
        back_populates="applications",
        lazy="joined"  # Always load applicant info
    )
    
    # ==========================================================================
    # Table Configuration
    # ==========================================================================
    
    __table_args__ = (
        # Unique constraint: One application per job per user
        # This prevents duplicate applications
        UniqueConstraint(
            "job_id",
            "applicant_id",
            name="uq_application_job_applicant"
        ),
        
        # Index for finding all applications for a job
        # Common query: "Show me all applications for job X"
        Index("ix_applications_job_id", "job_id"),
        
        # Index for finding all applications by a user
        # Common query: "Show me all my applications"
        Index("ix_applications_applicant_id", "applicant_id"),
        
        # Index for filtering by status
        # Common query: "Show me pending applications"
        Index("ix_applications_status", "status"),
        
        # Composite index for common query patterns
        # "Show me pending applications for job X"
        Index("ix_applications_job_status", "job_id", "status"),
        
        # Index for sorting by date
        Index("ix_applications_created_at", "created_at"),
        
        {"comment": "Job applications submitted by job seekers"}
    )
    
    # ==========================================================================
    # Methods
    # ==========================================================================
    
    def __repr__(self) -> str:
        return f"<Application {self.applicant_id} → {self.job_id} ({self.status})>"
    
    def to_dict(
        self,
        include_job: bool = False,
        include_applicant: bool = False,
        include_notes: bool = False
    ) -> dict:
        """
        Convert application to dictionary for JSON serialization.
        
        Args:
            include_job: Include job details
            include_applicant: Include applicant details
            include_notes: Include internal notes (employer only)
        
        Returns:
            dict: Application data safe for API responses
        """
        result = {
            "id": str(self.id),
            "job_id": str(self.job_id),
            "applicant_id": str(self.applicant_id),
            "status": self.status,
            "cover_letter": self.cover_letter,
            "resume_url": self.resume_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        # Only include notes if explicitly requested (employer viewing)
        if include_notes:
            result["notes"] = self.notes
        
        # Include related entities if requested
        if include_job and self.job:
            result["job"] = {
                "id": str(self.job.id),
                "title": self.job.title,
                "company_name": self.job.company_name,
                "location": self.job.location,
            }
        
        if include_applicant and self.applicant:
            result["applicant"] = {
                "id": str(self.applicant.id),
                "full_name": self.applicant.full_name,
                "email": self.applicant.email,
            }
        
        return result
    
    def can_transition_to(self, new_status: str) -> bool:
        """
        Check if the application can transition to a new status.
        
        This enforces the status workflow rules.
        
        Args:
            new_status: The proposed new status
        
        Returns:
            bool: True if transition is allowed
        
        """
        # Define valid transitions
        # Key: current status
        # Value: list of valid next statuses
        valid_transitions = {
            "pending": ["reviewing", "rejected", "withdrawn"],
            "reviewing": ["accepted", "rejected", "withdrawn"],
            "accepted": ["withdrawn"],  # Can still withdraw after acceptance
            "rejected": [],  # Terminal state
            "withdrawn": [],  # Terminal state
        }
        
        allowed = valid_transitions.get(self.status, [])
        return new_status in allowed
    
    @property
    def is_terminal(self) -> bool:
        """Check if application is in a terminal state (no more changes)."""
        return self.status in ["rejected", "withdrawn"]
    
    @property
    def is_active(self) -> bool:
        """Check if application is actively being considered."""
        return self.status in ["pending", "reviewing"]
    
# Import all models so they can be accessed from this package
from app.models.user import User
from app.models.job import Job
from app.models.application import Application

# Define what gets exported with "from app.models import *"
# (Though explicit imports are preferred)
__all__ = [
    "User",
    "Job",
    "Application",
]

from datetime import datetime
from typing import Optional, List, Tuple
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Application, Job, User
from app.schemas.application import (
    ApplicationCreate,
    ApplicationUpdate,
    ApplicationStatusUpdate,
)
from app.core.logging_config import get_logger
from app.services.background_tasks import schedule_email_notification

logger = get_logger(__name__)


# Valid status transitions
# Key: current status
# Value: list of allowed next statuses
STATUS_TRANSITIONS = {
    "pending": ["reviewing", "rejected", "withdrawn"],
    "reviewing": ["accepted", "rejected", "withdrawn"],
    "accepted": ["withdrawn"],
    "rejected": [],  # Terminal state
    "withdrawn": [],  # Terminal state
}


class ApplicationService:
    """
    Service class for application-related business logic.
    
    KEY CONCEPTS:
    
    1. Status Workflow
       Applications follow a defined workflow:
       pending → reviewing → accepted/rejected
       Any state can transition to withdrawn (by applicant)
    
    2. Permissions
       - Applicants can: submit, view own, withdraw
       - Employers can: view for their jobs, update status, add notes
    
    3. Notifications
       Status changes trigger background email notifications.
    """
    
    def __init__(self, db: AsyncSession):
        """Initialize with database session."""
        self.db = db
    
    async def submit_application(
        self,
        application_data: ApplicationCreate,
        applicant: User
    ) -> Application:
        """
        Submit a new job application.
        
        BUSINESS RULES:
        1. Can only apply to active jobs
        2. Can only apply once per job (unique constraint)
        3. Cannot apply to your own job postings
        
        WORKFLOW:
        1. Validate job exists and is active
        2. Check for existing application
        3. Create application
        4. Schedule notification email to employer
        
        Args:
            application_data: Validated application data
            applicant: The authenticated job seeker
        
        Returns:
            Application: The created application
        
        Raises:
            ValueError: If application is invalid
        """
        # Get the job
        job_result = await self.db.execute(
            select(Job).where(Job.id == application_data.job_id)
        )
        job = job_result.scalar_one_or_none()
        
        if not job:
            raise ValueError("Job not found")
        
        if job.status != "active":
            raise ValueError("Cannot apply to inactive job")
        
        # Check if trying to apply to own job
        if str(job.employer_id) == str(applicant.id):
            raise ValueError("Cannot apply to your own job posting")
        
        # Check for existing application
        # The database has a unique constraint, but checking first gives
        # a better error message
        existing_result = await self.db.execute(
            select(Application).where(
                and_(
                    Application.job_id == application_data.job_id,
                    Application.applicant_id == str(applicant.id)
                )
            )
        )
        existing = existing_result.scalar_one_or_none()
        
        if existing:
            raise ValueError("You have already applied to this job")
        
        # Create the application
        application = Application(
            job_id=application_data.job_id,
            applicant_id=str(applicant.id),
            cover_letter=application_data.cover_letter,
            resume_url=application_data.resume_url,
            status="pending",
        )
        
        self.db.add(application)
        await self.db.flush()
        
        logger.info(
            "Application submitted",
            extra={
                "application_id": str(application.id),
                "job_id": application_data.job_id,
                "applicant_id": str(applicant.id),
            }
        )
        
        # Schedule notification to employer
        # This runs in the background so we don't block the API response
        await schedule_email_notification(
            template="new_application",
            recipient_id=str(job.employer_id),
            context={
                "job_title": job.title,
                "applicant_name": applicant.full_name,
                "application_id": str(application.id),
            }
        )
        
        return application
    
    async def get_application(
        self,
        application_id: str,
        user: User
    ) -> Optional[Application]:
        """
        Get an application by ID with permission check.
        
        PERMISSIONS:
        - Applicant can view their own applications
        - Employer can view applications for their jobs
        
        Args:
            application_id: The application's UUID
            user: The authenticated user
        
        Returns:
            Optional[Application]: The application if found and authorized
        """
        # Load application with relationships
        result = await self.db.execute(
            select(Application)
            .options(
                selectinload(Application.job),
                selectinload(Application.applicant)
            )
            .where(Application.id == application_id)
        )
        application = result.scalar_one_or_none()
        
        if not application:
            return None
        
        # Check permissions
        is_applicant = str(application.applicant_id) == str(user.id)
        is_employer = str(application.job.employer_id) == str(user.id)
        
        if not (is_applicant or is_employer):
            logger.warning(
                "Unauthorized application access attempt",
                extra={
                    "application_id": application_id,
                    "user_id": str(user.id),
                }
            )
            return None
        
        return application
    
    async def get_applicant_applications(
        self,
        applicant_id: str,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[Application], int]:
        """
        Get all applications for a job seeker.
        
        This is what a job seeker sees when viewing their applications.
        
        TIME COMPLEXITY:
        - O(log n) with index on applicant_id
        
        Args:
            applicant_id: The job seeker's user ID
            status: Optional filter by status
            page: Page number
            per_page: Items per page
        
        Returns:
            Tuple[List[Application], int]: (applications, total_count)
        """
        # Base filter
        filters = [Application.applicant_id == applicant_id]
        
        if status:
            filters.append(Application.status == status)
        
        # Count query
        count_query = select(func.count(Application.id)).where(and_(*filters))
        count_result = await self.db.execute(count_query)
        total = count_result.scalar_one()
        
        # Applications query with job details
        offset = (page - 1) * per_page
        query = (
            select(Application)
            .options(selectinload(Application.job))
            .where(and_(*filters))
            .order_by(Application.created_at.desc())
            .offset(offset)
            .limit(per_page)
        )
        
        result = await self.db.execute(query)
        applications = list(result.scalars().all())
        
        return applications, total
    
    async def get_job_applications(
        self,
        job_id: str,
        employer: User,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[Application], int]:
        """
        Get all applications for a job (employer view).
        
        This is what an employer sees when reviewing applications.
        Includes applicant details and internal notes.
        
        Args:
            job_id: The job's UUID
            employer: The authenticated employer
            status: Optional filter by status
            page: Page number
            per_page: Items per page
        
        Returns:
            Tuple[List[Application], int]: (applications, total_count)
        
        Raises:
            PermissionError: If user doesn't own the job
        """
        # Verify job ownership
        job_result = await self.db.execute(
            select(Job).where(Job.id == job_id)
        )
        job = job_result.scalar_one_or_none()
        
        if not job:
            raise ValueError("Job not found")
        
        if str(job.employer_id) != str(employer.id):
            raise PermissionError("You can only view applications for your own jobs")
        
        # Build filters
        filters = [Application.job_id == job_id]
        
        if status:
            filters.append(Application.status == status)
        
        # Count query
        count_query = select(func.count(Application.id)).where(and_(*filters))
        count_result = await self.db.execute(count_query)
        total = count_result.scalar_one()
        
        # Applications query with applicant details
        offset = (page - 1) * per_page
        query = (
            select(Application)
            .options(selectinload(Application.applicant))
            .where(and_(*filters))
            .order_by(Application.created_at.desc())
            .offset(offset)
            .limit(per_page)
        )
        
        result = await self.db.execute(query)
        applications = list(result.scalars().all())
        
        return applications, total
    
    async def update_application_status(
        self,
        application_id: str,
        status_update: ApplicationStatusUpdate,
        employer: User
    ) -> Optional[Application]:
        """
        Update application status (employer action).
        
        STATUS WORKFLOW:
        - pending → reviewing → accepted/rejected
        - Invalid transitions are rejected
        
        BUSINESS RULES:
        1. Only employer who owns the job can update status
        2. Status must follow valid transition paths
        3. Status change triggers notification to applicant
        
        Args:
            application_id: The application's UUID
            status_update: New status and optional notes
            employer: The authenticated employer
        
        Returns:
            Optional[Application]: Updated application or None
        
        Raises:
            ValueError: If status transition is invalid
            PermissionError: If user doesn't own the job
        """
        # Get application with relationships
        result = await self.db.execute(
            select(Application)
            .options(
                selectinload(Application.job),
                selectinload(Application.applicant)
            )
            .where(Application.id == application_id)
        )
        application = result.scalar_one_or_none()
        
        if not application:
            return None
        
        # Verify ownership
        if str(application.job.employer_id) != str(employer.id):
            raise PermissionError("can only update applications for your own jobs")
        
        # Validate status transition
        current_status = application.status
        new_status = status_update.status
        
        allowed_transitions = STATUS_TRANSITIONS.get(current_status, [])
        if new_status not in allowed_transitions:
            raise ValueError(
                f"Cannot transition from '{current_status}' to '{new_status}'. "
                f"Allowed transitions: {allowed_transitions}"
            )
        
        # Update the application
        application.status = new_status
        application.updated_at = datetime.utcnow()
        
        if status_update.notes:
            application.notes = status_update.notes
        
        await self.db.flush()
        
        logger.info(
            "Application status updated",
            extra={
                "application_id": application_id,
                "old_status": current_status,
                "new_status": new_status,
            }
        )
        
        # Notify applicant
        await schedule_email_notification(
            template="status_update",
            recipient_id=str(application.applicant_id),
            context={
                "job_title": application.job.title,
                "company_name": application.job.company_name,
                "new_status": new_status,
            }
        )
        
        return application
    
    async def withdraw_application(
        self,
        application_id: str,
        applicant: User
    ) -> Optional[Application]:
        """
        Withdraw an application (applicant action).
        
        Applicants can withdraw from any non-terminal state.
        
        Args:
            application_id: The application's UUID
            applicant: The authenticated job seeker
        
        Returns:
            Optional[Application]: Updated application or None
        
        Raises:
            ValueError: If application cannot be withdrawn
            PermissionError: If user doesn't own the application
        """
        # Get application
        result = await self.db.execute(
            select(Application)
            .options(selectinload(Application.job))
            .where(Application.id == application_id)
        )
        application = result.scalar_one_or_none()
        
        if not application:
            return None
        
        # Verify ownership
        if str(application.applicant_id) != str(applicant.id):
            raise PermissionError("You can only withdraw your own applications")
        
        # Check if can be withdrawn
        if application.status in ["rejected", "withdrawn"]:
            raise ValueError(f"Cannot withdraw application with status '{application.status}'")
        
        # Update status
        old_status = application.status
        application.status = "withdrawn"
        application.updated_at = datetime.utcnow()
        
        await self.db.flush()
        
        logger.info(
            "Application withdrawn",
            extra={
                "application_id": application_id,
                "old_status": old_status,
            }
        )
        
        return application
    
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any
from app.core.logging_config import get_logger
from app.core.config import settings

logger = get_logger(__name__)

# Task queue (in-memory for demo)
# In production, this would be Redis, RabbitMQ, or similar
_task_queue: asyncio.Queue = asyncio.Queue()

# Track running tasks
_running_tasks: set = set()


async def schedule_email_notification(
    template: str,
    recipient_id: str,
    context: Dict[str, Any]
) -> None:
    """
    Schedule an email notification to be sent.
    
    This doesn't send the email immediately - it queues it for
    background processing so the API response isn't delayed.
    
    TEMPLATES:
    - new_application: Notify employer of new application
    - status_update: Notify applicant of status change
    - job_expiring: Remind employer their job is expiring
    - welcome: Welcome new users
    
    Args:
        template: Email template name
        recipient_id: User ID of recipient
        context: Template variables
    """
    task = {
        "type": "email",
        "template": template,
        "recipient_id": recipient_id,
        "context": context,
        "created_at": datetime.utcnow().isoformat(),
    }
    
    # Add to queue
    await _task_queue.put(task)
    
    logger.info(
        "Email task queued",
        extra={
            "template": template,
            "recipient_id": recipient_id,
        }
    )


async def process_email_task(task: Dict[str, Any]) -> bool:
    template = task["template"]
    recipient_id = task["recipient_id"]
    context = task["context"]
    
    logger.info(
        "Processing email task",
        extra={
            "template": template,
            "recipient_id": recipient_id,
        }
    )
    
    # Simulate email sending
    # In production: actual SMTP/API call here
    await asyncio.sleep(settings.EMAIL_SIMULATION_DELAY)
    
    # Build simulated email content
    email_content = _build_email_content(template, context)
    
    logger.info(
        "Email sent (simulated)",
        extra={
            "template": template,
            "recipient_id": recipient_id,
            "subject": email_content["subject"],
        }
    )
    
    return True


def _build_email_content(template: str, context: Dict[str, Any]) -> Dict[str, str]:
    """
    Build email content from template and context.
    
    Args:
        template: Template name
        context: Template variables
    
    Returns:
        Dict with 'subject' and 'body'
    """
    templates = {
        "new_application": {
            "subject": f"New application for {context.get('job_title', 'your job')}",
            "body": f"""
            Hello,
            
            You have a new application from {context.get('applicant_name', 'a candidate')}
            for the position: {context.get('job_title', 'your job posting')}.
            
            Log in to review the application.
            
            Best regards,
            Job Board Team
            """
        },
        "status_update": {
            "subject": f"Application update: {context.get('job_title', 'Your application')}",
            "body": f"""
            Hello,
            
            Your application for {context.get('job_title', 'the position')} at 
            {context.get('company_name', 'the company')} has been updated.
            
            New status: {context.get('new_status', 'Updated')}
            
            Log in to see more details.
            
            Best regards,
            Job Board Team
            """
        },
        "welcome": {
            "subject": "Welcome to Job Board!",
            "body": f"""
            Hello {context.get('name', 'there')}!
            
            Welcome to Job Board. We're excited to have you!
            
            {'Start posting jobs to find great candidates.' if context.get('role') == 'employer' else 'Start applying to find your dream job.'}
            
            Best regards,
            Job Board Team
            """
        },
        "job_expiring": {
            "subject": f"Your job posting is expiring soon",
            "body": f"""
            Hello,
            
            Your job posting "{context.get('job_title', 'Your job')}" is expiring soon.
            
            Log in to extend it if you're still hiring.
            
            Best regards,
            Job Board Team
            """
        },
    }
    
    # Get template or use default
    return templates.get(template, {
        "subject": "Notification from Job Board",
        "body": "You have a new notification. Please log in to see details."
    })


async def schedule_status_update(
    job_id: str,
    new_status: str,
    reason: Optional[str] = None
) -> None:
    """
    Schedule a job status update.
    
    Used for automated status changes like:
    - Expiring old job listings
    - Closing jobs that have been filled
    
    Args:
        job_id: The job to update
        new_status: The new status
        reason: Optional reason for the change
    """
    task = {
        "type": "status_update",
        "job_id": job_id,
        "new_status": new_status,
        "reason": reason,
        "created_at": datetime.utcnow().isoformat(),
    }
    
    await _task_queue.put(task)
    
    logger.info(
        "Status update task queued",
        extra={
            "job_id": job_id,
            "new_status": new_status,
        }
    )


async def task_worker() -> None:
    """
    Background worker that processes tasks from the queue.
    
    This runs as a long-lived coroutine that:
    1. Waits for tasks in the queue
    2. Processes each task
    3. Handles errors gracefully
    
    ERROR HANDLING:
    - Failed tasks are logged but not retried in this demo
    - Production systems would retry with exponential backoff
    """
    logger.info("Task worker started")
    
    while True:
        try:
            # Wait for a task (blocks until one is available)
            task = await _task_queue.get()
            
            task_type = task.get("type")
            
            if task_type == "email":
                await process_email_task(task)
            elif task_type == "status_update":
                await process_status_update_task(task)
            else:
                logger.warning(f"Unknown task type: {task_type}")
            
            # Mark task as done
            _task_queue.task_done()
            
        except asyncio.CancelledError:
            # Worker is being shut down
            logger.info("Task worker shutting down")
            break
        except Exception as e:
            logger.error(
                f"Task processing error: {e}",
                exc_info=True
            )


async def process_status_update_task(task: Dict[str, Any]) -> bool:
    """
    Process a status update task.
    
    Args:
        task: The status update task
    
    Returns:
        bool: True if successful
    """
    # In a real implementation, this would:
    # 1. Get a database session
    # 2. Update the job status
    # 3. Send notifications if needed
    
    logger.info(
        "Processing status update (simulated)",
        extra={
            "job_id": task.get("job_id"),
            "new_status": task.get("new_status"),
        }
    )
    
    await asyncio.sleep(0.1)  # Simulate processing
    
    return True


def start_task_worker() -> asyncio.Task:
    """
    Start the background task worker.
    
    Returns the task so it can be cancelled during shutdown.
    
    Returns:
        asyncio.Task: The worker task
    """
    task = asyncio.create_task(task_worker())
    _running_tasks.add(task)
    task.add_done_callback(_running_tasks.discard)
    return task


async def stop_task_worker() -> None:
    """
    Stop all background workers gracefully.
    
    Waits for current task to complete before stopping.
    """
    logger.info("Stopping task workers...")
    
    # Cancel all running tasks
    for task in _running_tasks:
        task.cancel()
    
    # Wait for all tasks to complete
    if _running_tasks:
        await asyncio.gather(*_running_tasks, return_exceptions=True)
    
    logger.info("Task workers stopped")


# =============================================================================
# Scheduled Tasks
# =============================================================================

async def expire_old_jobs() -> int:
    """
    Find and expire old job listings.
    
    This would typically be run by a scheduler (APScheduler, cron)
    to automatically clean up expired listings.
    
    Returns:
        int: Number of jobs expired
    """
    logger.info("Running job expiration check...")
    
    # In a real implementation:
    # 1. Query for jobs where expires_at < now() and status = 'active'
    # 2. Update their status to 'expired'
    # 3. Notify employers
    
    # This is a placeholder - actual implementation would use database
    expired_count = 0
    
    logger.info(f"Expired {expired_count} jobs")
    return expired_count


async def cleanup_old_sessions() -> int:
    logger.info("Running session cleanup...")
    
    # Placeholder - would actually clean Redis cache
    cleaned_count = 0
    
    logger.info(f"Cleaned up {cleaned_count} sessions")
    return cleaned_count


async def send_job_expiry_reminders() -> int:
    logger.info("Sending job expiry reminders...")
    
    # Would query for jobs expiring in 3 days and notify
    reminders_sent = 0
    
    logger.info(f"Sent {reminders_sent} expiry reminders")
    return reminders_sent

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
)
from app.core.config import settings
from app.core.logging_config import get_logger
from app.models import User
from app.schemas.user import (
    UserCreate,
    UserResponse,
    TokenResponse,
    LoginRequest,
    RefreshTokenRequest,
)

logger = get_logger(__name__)

# Create router with prefix and tags
router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="""
    Create a new user account.
    
    **Requirements:**
    - Email must be unique
    - Password must be at least 8 characters with uppercase, lowercase, and digit
    - Role must be 'job_seeker' or 'employer'
    """,
)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user.
    
    FLOW:
    1. Validate email is unique
    2. Hash the password (bcrypt)
    3. Create user record
    4. Return user (without password)
    
    Args:
        user_data: Validated registration data
        db: Database session
    
    Returns:
        UserResponse: The created user
    
    Raises:
        HTTPException 400: Email already registered
    """
    # Check if email already exists
    # TIME COMPLEXITY: O(log n) with unique index on email
    result = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash the password
    # TIME COMPLEXITY: O(1) but deliberately slow (~100ms for security)
    hashed_password = hash_password(user_data.password)
    
    # Create the user
    user = User(
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        role=user_data.role,
    )
    
    db.add(user)
    await db.commit()
    await db.refresh(user)  # Reload to get generated values (id, timestamps)
    
    logger.info(
        "User registered",
        extra={
            "user_id": str(user.id),
            "email": user.email,
            "role": user.role,
        }
    )
    
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and get tokens",
    description="""
    Authenticate with email and password to receive JWT tokens.
    
    **Response includes:**
    - `access_token`: Short-lived token for API requests (30 min)
    - `refresh_token`: Long-lived token to get new access tokens (7 days)
    - `token_type`: Always "bearer"
    - `expires_in`: Access token lifetime in seconds
    """,
)
async def login(
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return tokens.
    
    Args:
        login_data: Email and password
        db: Database session
    
    Returns:
        TokenResponse: Access and refresh tokens
    
    Raises:
        HTTPException 401: Invalid credentials
    """
    # Find user by email
    result = await db.execute(
        select(User).where(User.email == login_data.email)
    )
    user = result.scalar_one_or_none()
    
    # Verify user exists and password is correct
    # IMPORTANT: Same error message whether user doesn't exist or password wrong
    # This prevents email enumeration attacks
    if not user or not verify_password(login_data.password, user.hashed_password):
        logger.warning(
            "Login failed",
            extra={"email": login_data.email}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )
    
    # Create tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=str(user.id),
        expires_delta=access_token_expires,
        additional_claims={"role": user.role}
    )
    
    refresh_token = create_refresh_token(subject=str(user.id))
    
    logger.info(
        "User logged in",
        extra={
            "user_id": str(user.id),
            "email": user.email,
        }
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # Convert to seconds
    )


@router.post(
    "/login/form",
    response_model=TokenResponse,
    summary="Login with OAuth2 form",
    description="Login endpoint compatible with OAuth2 form-based authentication (used by Swagger UI)",
    include_in_schema=False,  # Hide from docs (it's just for Swagger)
)
async def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    OAuth2 compatible login endpoint.
    
    This exists because Swagger UI uses OAuth2PasswordRequestForm
    for the "Authorize" button functionality.
    
    The form sends:
    - username (we use email)
    - password
    """
    # Find user by email (form uses 'username' field)
    result = await db.execute(
        select(User).where(User.email == form_data.username)
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=str(user.id),
        expires_delta=access_token_expires,
        additional_claims={"role": user.role}
    )
    
    refresh_token = create_refresh_token(subject=str(user.id))
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="""
    Use a refresh token to get a new access token.
    
    **When to use:**
    - Access token has expired (401 error)
    - Proactively before expiration
    
    **Returns:**
    New access and refresh tokens (old refresh token should be discarded)
    """,
)
async def refresh_token(
    token_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Get new tokens using refresh token
    
    Args:
        token_data: The refresh token
        db: Database session
    
    Returns:
        TokenResponse: New access and refresh tokens
    
    Raises:
        HTTPException 401: Invalid or expired refresh token
    """
    try:
        # Decode and validate refresh token
        payload = decode_token(token_data.refresh_token)
        
        # Verify it's a refresh token (not access token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Verify user still exists and is active
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )
    
    # Create new tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(
        subject=str(user.id),
        expires_delta=access_token_expires,
        additional_claims={"role": user.role}
    )
    
    new_refresh_token = create_refresh_token(subject=str(user.id))
    
    logger.info(
        "Token refreshed",
        extra={"user_id": str(user.id)}
    )
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Get the profile of the currently authenticated user.",
)
async def get_me(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user's profile.
    
    This endpoint requires authentication.
    The get_current_user dependency:
    1. Extracts token from Authorization header
    2. Validates the token
    3. Loads the user from database
    4. Returns the user or raises 401
    
    Args:
        current_user: Injected by get_current_user dependency
    
    Returns:
        UserResponse: Current user's profile
    """
    return current_user

from math import ceil
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models import User
from app.schemas.application import (
    ApplicationCreate,
    ApplicationStatusUpdate,
    ApplicationResponse,
    ApplicationDetailResponse,
    ApplicationListResponse,
)
from app.services.application_service import ApplicationService
from app.core.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/applications", tags=["Applications"])


@router.post(
    "",
    response_model=ApplicationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit application",
    description="""
    Submit an application for a job.
    
    **Requirements:**
    - Must be authenticated
    - Can only apply to active jobs
    - Can only apply once per job
    - Cannot apply to your own job postings
    """,
)
async def submit_application(
    application_data: ApplicationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Submit a new job application.
    
    Creates an application with 'pending' status and triggers
    an email notification to the employer.
    """
    service = ApplicationService(db)
    
    try:
        application = await service.submit_application(application_data, current_user)
        await db.commit()
        
        logger.info(
            "Application submitted",
            extra={
                "application_id": str(application.id),
                "job_id": application_data.job_id,
                "applicant_id": str(current_user.id),
            }
        )
        
        return ApplicationResponse.model_validate(application)
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "",
    response_model=ApplicationListResponse,
    summary="List my applications",
    description="Get all applications submitted by the current user.",
)
async def list_my_applications(
    status_filter: str = Query(None, alias="status", description="Filter by status"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all applications for the current job seeker.
    
    Includes job details for each application.
    """
    service = ApplicationService(db)
    
    applications, total = await service.get_applicant_applications(
        applicant_id=str(current_user.id),
        status=status_filter,
        page=page,
        per_page=per_page,
    )
    
    pages = ceil(total / per_page) if total > 0 else 1
    
    # Build response with job details
    app_responses = []
    for app in applications:
        response = ApplicationDetailResponse.model_validate(app)
        if app.job:
            response.job = {
                "id": str(app.job.id),
                "title": app.job.title,
                "company_name": app.job.company_name,
                "location": app.job.location,
            }
        app_responses.append(response)
    
    return ApplicationListResponse(
        applications=app_responses,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.get(
    "/job/{job_id}",
    response_model=ApplicationListResponse,
    summary="List applications for a job",
    description="Get all applications for a specific job (employer only).",
)
async def list_job_applications(
    job_id: str,
    status_filter: str = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all applications for a job.
    
    Only the job owner (employer) can view these.
    Includes applicant details and internal notes.
    """
    service = ApplicationService(db)
    
    try:
        applications, total = await service.get_job_applications(
            job_id=job_id,
            employer=current_user,
            status=status_filter,
            page=page,
            per_page=per_page,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    
    pages = ceil(total / per_page) if total > 0 else 1
    
    # Build response with applicant details and notes
    app_responses = []
    for app in applications:
        response = ApplicationDetailResponse.model_validate(app)
        response.notes = app.notes  # Include notes for employer
        if app.applicant:
            response.applicant = {
                "id": str(app.applicant.id),
                "full_name": app.applicant.full_name,
                "email": app.applicant.email,
            }
        app_responses.append(response)
    
    return ApplicationListResponse(
        applications=app_responses,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.get(
    "/{application_id}",
    response_model=ApplicationDetailResponse,
    summary="Get application details",
)
async def get_application(
    application_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get details of a specific application.
    
    - Applicants can view their own applications
    - Employers can view applications for their jobs
    """
    service = ApplicationService(db)
    
    application = await service.get_application(application_id, current_user)
    
    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found or access denied"
        )
    
    response = ApplicationDetailResponse.model_validate(application)
    
    # Include job details
    if application.job:
        response.job = {
            "id": str(application.job.id),
            "title": application.job.title,
            "company_name": application.job.company_name,
            "location": application.job.location,
        }
    
    # Check if viewer is the employer
    is_employer = str(application.job.employer_id) == str(current_user.id)
    
    if is_employer:
        # Include applicant details and notes for employer
        response.notes = application.notes
        if application.applicant:
            response.applicant = {
                "id": str(application.applicant.id),
                "full_name": application.applicant.full_name,
                "email": application.applicant.email,
            }
    
    return response


@router.patch(
    "/{application_id}/status",
    response_model=ApplicationDetailResponse,
    summary="Update application status",
    description="""
    Update the status of an application (employer only).
    
    **Valid status transitions:**
    - pending → reviewing, rejected
    - reviewing → accepted, rejected
    - accepted → (no further transitions)
    - rejected → (terminal state)
    """,
)
async def update_application_status(
    application_id: str,
    status_update: ApplicationStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update application status.
    
    Only the job owner can update status.
    Triggers email notification to the applicant.
    """
    service = ApplicationService(db)
    
    try:
        application = await service.update_application_status(
            application_id=application_id,
            status_update=status_update,
            employer=current_user,
        )
        
        if not application:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Application not found"
            )
        
        await db.commit()
        
        response = ApplicationDetailResponse.model_validate(application)
        response.notes = application.notes
        
        return response
        
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{application_id}/withdraw",
    response_model=ApplicationResponse,
    summary="Withdraw application",
    description="Withdraw your application from a job.",
)
async def withdraw_application(
    application_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Withdraw an application.
    
    Can withdraw from any non-terminal state.
    Only the applicant can withdraw their own application.
    """
    service = ApplicationService(db)
    
    try:
        application = await service.withdraw_application(application_id, current_user)
        
        if not application:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Application not found"
            )
        
        await db.commit()
        
        logger.info(
            "Application withdrawn",
            extra={
                "application_id": application_id,
                "user_id": str(current_user.id),
            }
        )
        
        return ApplicationResponse.model_validate(application)
        
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.jobs import router as jobs_router
from app.api.v1.applications import router as applications_router

# main v1 router
router = APIRouter()

# Include all sub-routers
# Each router has its own prefix defined in its file
router.include_router(auth_router)
router.include_router(jobs_router)
router.include_router(applications_router)

from app.services.job_service import JobService
from app.services.application_service import ApplicationService

__all__ = ["JobService", "ApplicationService"]

from app.services.job_service import JobService
from app.services.application_service import ApplicationService

__all__ = ["JobService", "ApplicationService"]

