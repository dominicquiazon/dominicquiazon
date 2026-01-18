"""
=============================================================================
Cache Module - Redis Caching Layer
=============================================================================

This module provides a caching layer using Redis. Caching is essential for:
1. Reducing database load (fewer queries)
2. Improving response times (Redis is much faster)
3. Scaling the application (cache can be shared across instances)

WHY REDIS:
    - In-memory: Sub-millisecond read/write operations
    - Persistence: Can survive restarts (optional)
    - Rich data types: Strings, hashes, lists, sets
    - Built-in expiration: Keys auto-delete after TTL
    - Widely used: LinkedIn, Twitter, GitHub all use Redis

CACHING PATTERNS:

1. CACHE-ASIDE (Read-Through):
   - Check cache first
   - If miss, query database
   - Store result in cache
   - Return result
   
   This is what we use here.

2. WRITE-THROUGH:
   - Write to cache and database simultaneously
   - Good for consistency, more complex

3. WRITE-BEHIND:
   - Write to cache immediately
   - Async write to database later
   - Fast but risk of data loss

TIME COMPLEXITY:
    - Redis GET: O(1)
    - Redis SET: O(1)
    - Redis DELETE: O(1)
    - Database query: O(log n) with index, O(n) without

    With caching, most reads become O(1) instead of O(log n)!

=============================================================================
"""

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
