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
