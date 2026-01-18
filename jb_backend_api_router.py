from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.jobs import router as jobs_router
from app.api.v1.applications import router as applications_router

# main v1 router
router = APIRouter()

# Include all sub-routers
# Each router has its own prefix defined in its file
router.include_router(auth_router)
router.include_router(jobs_router)
router.include_router(applications_router)

