# Import all models so they can be accessed from this package
from app.models.user import User
from app.models.job import Job
from app.models.application import Application

# Define what gets exported with "from app.models import *"
# (Though explicit imports are preferred)
__all__ = [
    "User",
    "Job",
    "Application",
]