from fastapi import APIRouter, Depends, HTTPException, Header
import os
from ..job import job_update_scores, job_settle_ready, job_seed_future
from .auth import get_current_user

router = APIRouter(prefix="/internal/jobs", tags=["internal-jobs"])

def require_admin(x_admin_token: str = Header(None)):
    if not x_admin_token or x_admin_token != os.getenv("ADMIN_TOKEN"):
        raise HTTPException(403, "Admin privileges required")

@router.post("/update-scores", dependencies=[Depends(require_admin)])
def run_update_scores():
    job_update_scores()
    return {"ok": True}

@router.post("/settle-ready", dependencies=[Depends(require_admin)])
def run_settle_ready():
    job_settle_ready()
    return {"ok": True}

@router.post("/seed_future", dependencies=[Depends(require_admin)])
def run_settle_ready():
    job_seed_future()
    return {"ok": True}