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
