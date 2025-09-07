from fastapi import APIRouter, Depends, HTTPException, Header
import os
from ..job import job_update_scores, job_settle_ready, job_seed_future
from .auth import get_current_user
from ..core.constants import HTTPStatus, ErrorMessages

router = APIRouter(prefix="/internal/jobs", tags=["internal-jobs"])

def require_admin(me: dict = Depends(get_current_user)):
    user_id = str(me["id"])
    
    admins = set((os.getenv("ADMIN_TOKEN") or "").split(","))
    if user_id in admins:
        return user_id
    raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.ADMIN_PRIVILEGES_REQUIRED)

@router.post("/update-scores", dependencies=[Depends(require_admin)])
def run_update_scores():
    job_update_scores()
    return {"ok": True}

@router.post("/settle-ready", dependencies=[Depends(require_admin)])
def run_settle_ready():
    job_settle_ready()
    return {"ok": True}

@router.post("/seed_future", dependencies=[Depends(require_admin)])
def run_seed_future(days_ahead: int = 7):
    job_seed_future(days_ahead=days_ahead)
    return {"ok": True, "days_ahead": days_ahead}