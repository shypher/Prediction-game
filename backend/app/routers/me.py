from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..core import database
from ..db import models
from .auth import get_current_user

router = APIRouter(prefix="/me", tags=["me"])

def get_db():
    db = database.SessionLocal()
    try: yield db
    finally: db.close()
    
@router.get("/summary")
def my_summary(db: Session = Depends(get_db), me: dict = Depends(get_current_user)):
    user_id = me["id"]
    total_points = db.query(func.coalesce(func.sum(models.Prediction.points_awarded), 0))\
                     .filter(models.Prediction.user_id == user_id, models.Prediction.is_final == True)\
                     .scalar() or 0
    bets_done = db.query(func.count(models.Prediction.id))\
                  .filter(models.Prediction.user_id == user_id)\
                  .scalar() or 0
    sub = db.query(models.Prediction.user_id.label("uid"),
                   func.coalesce(func.sum(models.Prediction.points_awarded),0).label("pts"))\
            .filter(models.Prediction.is_final == True)\
            .group_by(models.Prediction.user_id)\
            .subquery()
    my_pts = db.query(sub.c.pts).filter(sub.c.uid == user_id).scalar() or 0
    better = db.query(func.count()).filter(sub.c.pts > my_pts).scalar() or 0
    rank_global = better + 1 if my_pts is not None else None

    last10 = (
        db.query(models.Prediction)
          .filter(models.Prediction.user_id == user_id)
          .order_by(models.Prediction.created_at.desc())
          .limit(10).all()
    )
    out = [{
        "id": p.id,
        "match_id": p.match_id,
        "pick": p.pick,
        "margin": p.margin,
        "points_awarded": p.points_awarded,
        "is_final": p.is_final,
        "created_at": p.created_at,
    } for p in last10]
    return {
        "user_id": user_id,
        "total_points": int(total_points),
        "bets": int(bets_done),
        "rank_global": int(rank_global),
        "last_predictions": out
    }