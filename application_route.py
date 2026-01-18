"""
=============================================================================
Applications Routes - Job Application Management
=============================================================================

Endpoints for managing job applications:
- POST /applications - Submit an application
- GET /applications - List my applications (job seeker)
- GET /applications/{id} - Get application details
- PATCH /applications/{id}/status - Update status (employer)
- POST /applications/{id}/withdraw - Withdraw application
"""

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