"""
=============================================================================
This is the main FastAPI application file. It:
1. Creates the FastAPI application instance
2. Configures middleware (CORS, logging, error handling)
3. Registers all API routes
4. Sets up startup/shutdown events for database connections
=============================================================================
"""

# Standard library imports
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
