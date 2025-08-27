# app/routers/leaderboard.py
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
from app import models, schemas, database

router = APIRouter(prefix="/leaderboard", tags=["leaderboard"])

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("", response_model=List[schemas.LeaderboardEntry])
def leaderboard(
    db: Session = Depends(get_db),
    league: Optional[str] = Query(None),
    season: Optional[int] = Query(None),
    group_id: Optional[int] = Query(None),
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):

    q = (
        db.query(
            models.Prediction.user_id.label("user_id"),
            func.coalesce(func.sum(models.Prediction.points_awarded), 0).label("total_points"),
            func.count(models.Prediction.id).label("bets"),
        )
        .join(models.Match, models.Match.id == models.Prediction.match_id)
        .filter(models.Prediction.is_final == True)
    )

    if league:
        q = q.filter(models.Match.league_name == league)
    if season:
        q = q.filter(models.Match.season == season)
    if since:
        q = q.filter(models.Match.match_date >= since)
    if until:
        q = q.filter(models.Match.match_date <= until + " 23:59:59")

    if group_id is not None:
        g = db.get(models.Group, group_id)
        if not g:
            raise HTTPException(404, "Group not found")
        q = q.join(models.GroupMember, models.GroupMember.user_id == models.Prediction.user_id)\
             .filter(models.GroupMember.group_id == group_id)

    q = q.group_by(models.Prediction.user_id)\
         .order_by(func.coalesce(func.sum(models.Prediction.points_awarded), 0).desc())

    rows = q.offset(offset).limit(limit).all()

    entries = []
    last_points = None
    last_rank = 0
    idx = 0
    for r in rows:
        idx += 1
        pts = int(r.total_points or 0)
        if pts != last_points:
            last_rank = idx
            last_points = pts
        entries.append(schemas.LeaderboardEntry(
            user_id=r.user_id, total_points=pts, bets=int(r.bets), rank=last_rank
        ))
    return entries
