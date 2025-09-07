import datetime as dt
from math import ceil
from typing import Optional, Tuple, List, Dict
from sqlalchemy import func, case, and_
from sqlalchemy.orm import Session
import os, random
from app.db import models
from ..core.constants import BotID
from ..routers.predictions import get_match_stats
from ..core.database import SessionLocal
from ..core.constants import BotDefaults

BOT_LOOKAHEAD_HOURS = os.getenv("BOT_LOOKAHEAD_HOURS")

BotIds = [b.value for b in BotID]
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        

def _crowd_pick_and_margin(db: Session, match_id: int) -> Dict[str, Optional[float]]:
    with Session() as db:
        stat = get_match_stats(match_id, db)
    avg_margin = stat["avg_signed_margin"]
    median = stat["median_signed_margin"]
    favorite =stat["favorite"]
    med_side: Optional[str] = None
    median_mag: int = 0
    if median>0:
        median_mag = round(median)
        med_side = "home"
    elif median<0:
        median_mag = round(-median)
        med_side = "away"
    elif favorite:
        med_side = favorite
        median = 1
        
    avg_side: Optional[str] = None
    avg_mag: int = 0

    
    if avg_margin > 0:
        avg_mag = round(-avg_margin)
        avg_side = "home"
    elif avg_margin < 0:
        avg_mag = round(-avg_margin)
        avg_side = "away"
    elif favorite :
        med_side = favorite
        avg_mag = 1
    else:
        avg_side = med_side
        avg_margin = med_side
    
    return {
        "avg_side":avg_side,
        "avg_margin":avg_margin,
        "med_side":med_side,
        "median": median_mag,
    }    
    
def _cfg_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None: return default
    return v.strip().lower() in ("1","true","yes","on","y")

def _cfg_float(name, default): 
    try: return float(os.getenv(name, default))
    except: return default

def _cfg_int(name: str, default: int) -> int:
    try:
        return int(float(os.getenv(name, "").strip() or default))
    except Exception:
        return default

def _cfg_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v not in (None, "") else default


RANDOM_HOME_PROB_DEFAULT     = _cfg_float("BOT_RANDOM_HOME_PROB", BotDefaults.RANDOM_HOME_PROB)
RANDOM_MARGIN_CENTER_DEFAULT  = _cfg_float("BOT_RANDOM_MARGIN_CENTER",   BotDefaults.RANDOM_MARGIN_CENTER)
RANDOM_MARGIN_SPREAD_DEFAULT  = _cfg_float("BOT_RANDOM_MARGIN_SPREAD",   BotDefaults.RANDOM_MARGIN_SPREAD)
RANDOM_MARGIN_MIN_DEFAULT     = _cfg_int  ("BOT_RANDOM_MARGIN_MIN",      BotDefaults.RANDOM_MARGIN_MIN)
RANDOM_MARGIN_MAX_DEFAULT     = _cfg_int  ("BOT_RANDOM_MARGIN_MAX",      BotDefaults.RANDOM_MARGIN_MAX)
RANDOM_DISTRIBUTION_DEFAULT   = _cfg_str  ("BOT_RANDOM_DISTRIBUTION",    BotDefaults.RANDOM_DISTRIBUTION)
CROWD_OFFSET_MINUTES          = _cfg_int  ("BOT_CROWD_OFFSET_MINUTES",    BotDefaults.CROWD_OFFSET_MINUTES)
CROWD_OVERWRITE               = _cfg_bool ("BOT_CROWD_OVERWRITE",         BotDefaults.CROWD_OVERWRITE)
def _upsert_bot_prediction(db: Session, match_id: int, bot_user_id: int, pick: Optional[str], margin: int) -> bool:
    P = models.Prediction
    uid = bot_user_id
    pred = db.query(P).filter(P.match_id == match_id, P.user_id == uid).one_or_none()

    eff_pick = None if margin == 0 else pick
    eff_margin = 0 if margin == 0 else max(1, margin)

    if pred is None:
        db.add(P(match_id=match_id, user_id=uid, pick=eff_pick, margin=eff_margin))
        return True

    changed = False
    if pred.pick != eff_pick:
        pred.pick = eff_pick; changed = True
    if pred.margin != eff_margin:
        pred.margin = eff_margin; changed = True
    return changed


def _random_params_for_bot(key: str):
    """Allow per-bot overrides via env, else fallback to global defaults."""
    prefix = f"BOT_{key.upper()}_"
    return {
        "home_prob":   _cfg_float(prefix + "HOME_PROB",      RANDOM_HOME_PROB_DEFAULT),
        "center":      _cfg_float(prefix + "MARGIN_CENTER",  RANDOM_MARGIN_CENTER_DEFAULT),
        "spread":      _cfg_float(prefix + "MARGIN_SPREAD",  RANDOM_MARGIN_SPREAD_DEFAULT),
        "min_margin":  _cfg_int  (prefix + "MARGIN_MIN",     RANDOM_MARGIN_MIN_DEFAULT),
        "max_margin":  _cfg_int  (prefix + "MARGIN_MAX",     RANDOM_MARGIN_MAX_DEFAULT),
        "dist":        _cfg_str  (prefix + "DISTRIBUTION",   RANDOM_DISTRIBUTION_DEFAULT).lower(),
    }
    

def _random_pick_and_margin(home_prob: float, center: float, spread: float,
                            min_margin: int, max_margin: int, dist: str) -> Tuple[str, int]:
    side = "home" if random.random() < max(0.0, min(1.0, home_prob)) else "away"

    if dist == "triangular":
        low  = max(1.0, center - spread)
        high = max(low + 1.0, center + spread)
        val = random.triangular(low, high, center)
    elif dist == "normal":
        sigma = max(0.1, spread / 2.0)
        val = random.gauss(center, sigma)
    else:
        low  = max(1.0, center - spread)
        high = max(low + 1.0, center + spread)
        val = random.uniform(low, high)

    margin = int(max(min_margin, min(max_margin, round(val))))
    return side, margin

def _candidates_random(db: Session) -> List[models.Match]:
    now = dt.datetime.utcnow()
    M = models.Match
    rows = (db.query(M)
              .filter(M.status == "scheduled", M.match_date > now)
              .order_by(M.match_date.asc())
              .all())
    out = []
    for m in rows:
        trigger_at = max(m.match_date - dt.timedelta(days=7), _match_created_at(m))
        if now >= trigger_at:
            out.append(m)
    return out

def _candidates_crowd(db: Session, offset_minutes: int) -> List[models.Match]:
    """Crowd bots trigger at (match_time - offset). Default offset=0."""
    now = dt.datetime.utcnow()
    M = models.Match
    rows = (db.query(M)
              .filter(M.status == "scheduled", M.match_date > now)
              .order_by(M.match_date.asc())
              .all())
    out = []
    for m in rows:
        if now >= (m.match_date - dt.timedelta(minutes=offset_minutes)):
            out.append(m)
    return out


def _candidates_book(db: Session, window_seconds: int = 60) -> List[models.Match]:
    now = dt.datetime.utcnow()
    M = models.Match
    rows = (db.query(M)
              .filter(M.status == "scheduled", M.match_date > now)
              .order_by(M.match_date.asc())
              .all())
    return [m for m in rows if 0 < (m.match_date - now).total_seconds() <= window_seconds]


def job_bots_random(db: Session) -> Dict[str, int]:
    matches = _candidates_random(db)
    if not matches: return {"matches": 0, "created_or_updated": 0}
    changed = 0

    for m in matches:
        for key in (BotID.RANDOM_01, BotID.RANDOM_02, BotID.RANDOM_03):
            bot_id = int(key.value)
            if _has_pred_for_bot(db, m.id, bot_id):
                continue
            params = _random_params_for_bot(key.name.lower())  
            p, mg = _random_pick_and_margin(**params)
            if _upsert_bot_prediction(db, m.id, bot_id, p, mg):
                changed += 1

    if changed: db.commit()
    return {"matches": len(matches), "created_or_updated": changed}

def _match_created_at(m: models.Match) -> dt.datetime:
    return getattr(m, "last_update", None) or dt.datetime.utcnow()


def _has_pred_for_bot(db: Session, match_id: int, bot_user_id: int) -> bool:
    P = models.Prediction
    return db.query(func.count()).filter(
        P.match_id == match_id,
        P.user_id == bot_user_id
    ).scalar() > 0
    
    
def _upsert_bot_prediction(db: Session, match_id: int, bot_user_id: int,
                           pick: str | None, margin: int) -> bool:
    P = models.Prediction
    pred = db.query(P).filter(P.match_id == match_id, P.user_id == bot_user_id).one_or_none()

    eff_pick = None if margin == 0 else pick
    eff_margin = 0 if margin == 0 else max(1, margin)

    if pred is None:
        db.add(P(match_id=match_id, user_id=bot_user_id, pick=eff_pick, margin=eff_margin))
        return True

    changed = False
    if pred.pick != eff_pick:
        pred.pick = eff_pick; changed = True
    if pred.margin != eff_margin:
        pred.margin = eff_margin; changed = True
    return changed



def _book_pick_and_margin(match: models.Match) -> Tuple[Optional[str], int]:
    # TODO: hook to odds API (spread -> side & ceil(abs(spread)); else from moneyline -> implied probability)
    return (None, 0)

def job_bots_book(db: Session, window_seconds: int = 60) -> Dict[str, int]:
    matches = _candidates_book(db, window_seconds=window_seconds)
    if not matches: return {"matches": 0, "created_or_updated": 0}
    changed = 0

    bot_id = int(BotID.BOOK_THEODDS.value)
    if not _has_pred_for_bot(db, m.id, bot_id):
        p, mg = _book_pick_and_margin(m)
        if _upsert_bot_prediction(db, m.id, bot_id, p, mg):
            changed += 1

    if changed: db.commit()
    return {"matches": len(matches), "created_or_updated": changed}


def job_bots_crowd(db: Session) -> dict:
    matches = _candidates_crowd(db, offset_minutes=CROWD_OFFSET_MINUTES)  # כמו שהיה
    if not matches:
        return {"matches": 0, "created_or_updated": 0}

    changed = 0
    for m in matches:
        stats = _crowd_pick_and_margin(db, m.id)

        if (not _has_pred_for_bot(db, m.id, int(BotID.CROWD_MEDIAN.value))) or CROWD_OVERWRITE:
            side, margin = stats["med_side"], stats["median"]
            if _upsert_bot_prediction(db, m.id, int(BotID.CROWD_MEDIAN.value), side, margin):
                changed += 1

        if (not _has_pred_for_bot(db, m.id, int(BotID.CROWD_MEAN.value))) or CROWD_OVERWRITE:
            side, margin = stats["avg_side"], stats["avg_margin"]
            if _upsert_bot_prediction(db, m.id, int(BotID.CROWD_MEAN.value), side, margin):
                changed += 1

    if changed:
        db.commit()
    return {"matches": len(matches), "created_or_updated": changed}