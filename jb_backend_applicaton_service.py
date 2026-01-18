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
