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
