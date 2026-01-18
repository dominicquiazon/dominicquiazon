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
