from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
import datetime as dt
from typing import Optional, List
from ..core.database import SessionLocal
from ..db import models
from .auth import get_current_user
from ..core.constants import HTTPStatus, ErrorMessages
import os
router = APIRouter(prefix="/admin/fix", tags=["admin-fix"])
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def require_admin(me: dict = Depends(get_current_user)):
    user_id = str(me["id"])
    
    admins = set((os.getenv("ADMIN_TOKEN") or "").split(","))
    if user_id in admins:
        return user_id
    raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.ADMIN_PRIVILEGES_REQUIRED)


def _compose_dt(d: dt.date, t_str: Optional[str], is_start: bool, dependencies=[Depends(require_admin)]) -> dt.datetime:
    if t_str:
        hh, mm = [int(x) for x in t_str.split(":", 1)]
        return dt.datetime.combine(d, dt.time(hour=hh, minute=mm))
    return dt.datetime.combine(d, dt.time.min if is_start else dt.time.max)


@router.post("/shift-time-window")
def fix_time_window(
    start_date: Optional[dt.date] = Query(None, description="תחילת טווח (כולל)"),
    end_date:   Optional[dt.date] = Query(None, description="סוף טווח (כולל)"),
    start_time: Optional[str]     = Query(None, pattern=r"^\d{2}:\d{2}$"),
    end_time:   Optional[str]     = Query(None, pattern=r"^\d{2}:\d{2}$"),
    ids: Optional[List[int]]      = Query(None, description="לדוגמה ?ids=101&ids=102"),
    delta_hours: int              = Query(3, description="חיובי=קדימה, שלילי=אחורה"),
    dry_run: bool                 = Query(True),
    league: str                   = Query("EuroBasket"),
    source: Optional[str]         = Query(None, description="למשל 'thesportsdb'"),
    db: Session = Depends(get_db),
    dependencies=[Depends(require_admin)]
):

    q = db.query(models.Match)

    mode = "ids" if ids else "window"

    if ids:
        if len(ids) == 0:
            return {"updated": 0, "note": "empty ids list", "mode": mode}
        q = q.filter(models.Match.id.in_(ids))
    else:
        if not start_date or not end_date:
            return {
                "updated": 0,
                "error": "Must provide either ids OR (start_date & end_date)",
                "mode": mode,
            }
        start_dt = _compose_dt(start_date, start_time, is_start=True)
        end_dt   = _compose_dt(end_date,   end_time,   is_start=False)
        q = q.filter(models.Match.match_date >= start_dt,
                     models.Match.match_date <= end_dt)
        if league:
            q = q.filter(models.Match.league_name == league)

    if source:
        q = q.filter(models.Match.source == source)

    total = q.count()
    if total == 0:
        resp = {"updated": 0, "mode": mode, "delta_hours": delta_hours}
        if not ids:
            resp["window"] = {
                "start": _compose_dt(start_date, start_time, True).isoformat(),
                "end":   _compose_dt(end_date,   end_time,   False).isoformat(),
                "league": league,
            }
        else:
            resp["ids"] = ids
        resp["source"] = source
        resp["note"] = "no rows matched"
        return resp

    sample_before = [
        {"id": m.id, "home": m.home_team, "away": m.away_team, "date": m.match_date}
        for m in q.order_by(models.Match.match_date.asc()).limit(5).all()
    ]

    if dry_run:
        resp = {
            "would_update": total,
            "mode": mode,
            "delta_hours": delta_hours,
            "sample_before": sample_before,
            "hint": "Set dry_run=false to apply.",
            "source": source,
        }
        if ids:
            resp["ids"] = ids
        else:
            resp["window"] = {
                "start": _compose_dt(start_date, start_time, True).isoformat(),
                "end":   _compose_dt(end_date,   end_time,   False).isoformat(),
                "league": league,
            }
        return resp

    upd = db.query(models.Match)
    if ids:
        upd = upd.filter(models.Match.id.in_(ids))
    else:
        upd = upd.filter(models.Match.match_date >= _compose_dt(start_date, start_time, True),
                         models.Match.match_date <= _compose_dt(end_date,   end_time,   False))
        if league:
            upd = upd.filter(models.Match.league_name == league)
    if source:
        upd = upd.filter(models.Match.source == source)

    updated = upd.update(
        {models.Match.match_date: text(f"match_date + interval '{delta_hours} hour'")},
        synchronize_session=False
    )
    db.commit()

    ids_sample = [s["id"] for s in sample_before]
    after_rows = (db.query(models.Match)
                    .filter(models.Match.id.in_(ids_sample))
                    .order_by(models.Match.match_date.asc()).all())
    sample_after = [
        {"id": m.id, "home": m.home_team, "away": m.away_team, "date": m.match_date}
        for m in after_rows
    ]

    resp = {
        "updated": updated,
        "mode": mode,
        "delta_hours": delta_hours,
        "sample_before": sample_before,
        "sample_after": sample_after,
        "source": source,
    }
    if ids:
        resp["ids"] = ids
    else:
        resp["window"] = {
            "start": _compose_dt(start_date, start_time, True).isoformat(),
            "end":   _compose_dt(end_date,   end_time,   False).isoformat(),
            "league": league,
        }
    return resp




@router.post("/eurobasket-refresh-results", dependencies=[Depends(require_admin)])
def refresh_eurobasket_results(
    start: dt.date, end: dt.date, db: Session = Depends(get_db)
):
    from app.services import thesportsdb
    cur = start
    updated = 0
    while cur <= end:
        events = thesportsdb.events_day(cur, league_name="FIBA EuroBasket")
        by_ext = {e.get("idEvent"): e for e in events if e.get("idEvent")}
        rows = (db.query(models.Match)
                  .filter(models.Match.league_name=="EuroBasket")
                  .filter(models.Match.match_date >= dt.datetime.combine(cur, dt.time.min))
                  .filter(models.Match.match_date <= dt.datetime.combine(cur, dt.time.max))
                  .all())
        for m in rows:
            ev = by_ext.get(m.external_id)
            if not ev: 
                continue
            hs = ev.get("intHomeScore"); as_ = ev.get("intAwayScore")
            if hs is not None and as_ is not None:
                try:
                    m.home_score = int(hs); m.away_score = int(as_)
                    m.status = "finished"
                    updated += 1
                except:
                    pass
        cur += dt.timedelta(days=1)
    db.commit()
    return {"updated": updated}

#@router.post("/refresh")
#def refresh_bots(db: Session = Depends(get_db)):
   # res = job_bots_refresh(db)
   # return res