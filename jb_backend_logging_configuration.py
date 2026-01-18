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
