from fastapi import APIRouter, Depends, HTTPException, Header, Query
from sqlalchemy.orm import Session
from typing import Optional, List
import datetime as dt

from app import models, schemas, database

router = APIRouter(prefix="/predictions", tags=["predictions"])
try:
    from app.auth import get_current_user
except Exception:
    get_current_user = None

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def _current_user_id(x_user_id: Optional[str] = Header(None), user=Depends(lambda: None)):
    if get_current_user:
        u = get_current_user()
        if hasattr(u, "id"):
            return str(u.id)
        if isinstance(u, dict) and u.get("id"):
            return str(u["id"])
        if x_user_id:
            return x_user_id
        raise HTTPException(status_code=401, detail="Unauthorized: missing user")

LOCK_MINUTES = 1  # minutes before match start

def is_locked(match: models.Match) -> bool:
    if not match or not match.match_date:
        return False
    now = dt.datetime.utcnow()
    lock_time = match.match_date - dt.timedelta(minutes=LOCK_MINUTES)
    return now >= lock_time

@router.post("", response_model=schemas.PredictionOut)
def creat_or_update_prediction(payload: schemas.PredictionCreate,
    db: Session = Depends(get_db),
    user_id: str = Depends(_current_user_id)):
    