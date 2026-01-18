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
