from fastapi import APIRouter, Depends, HTTPException, Header, Query
from sqlalchemy.orm import Session
from typing import Optional, List
import datetime as dt
import os
from ..core import database
from sqlalchemy import text
from statistics import median
from sqlalchemy import func, case, text
from sqlalchemy.exc import IntegrityError

from ..db import models, schemas
from .auth import get_current_user
from ..core.constants import HTTPStatus, ErrorMessages, AppConstants
from ..services.prediction_service import PredictionService

router = APIRouter(prefix="/predictions", tags=["predictions"])


def require_admin(me: dict = Depends(get_current_user)):
    user_id = me["id"]
    admins = set((os.getenv("ADMIN_USERS") or "").split(","))
    if user_id in admins:
        return user_id
    raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.ADMIN_PRIVILEGES_REQUIRED)


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
# def current_user_id(x_user_id: Optional[str] = Header(None)) -> str:
#     if not x_user_id:
#         raise HTTPException(401, "Unauthorized: provide X-User-Id for now")
#     return x_user_id





@router.post("", response_model=schemas.PredictionOut)
def create_or_update_prediction(
    payload: schemas.PredictionCreate,
    db: Session = Depends(get_db),
    me: dict = Depends(get_current_user), 
):
    uid = me["id"]
    prediction_service = PredictionService(db)
    
    try:
        result = prediction_service.create_prediction(
            user_id=uid,
            match_id=payload.match_id,
            pick=payload.pick,
            margin=payload.margin
        )
        return result
    except ValueError as e:
        if "Match not found" in str(e):
            raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.MATCH_NOT_FOUND)
        elif "Predictions are locked" in str(e):
            raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.PREDICTIONS_LOCKED)
        elif "margin must be >= 0" in str(e):
            raise HTTPException(HTTPStatus.UNPROCESSABLE_ENTITY, "margin must be >= 0")
        elif "pick is required when margin>=1" in str(e):
            raise HTTPException(HTTPStatus.UNPROCESSABLE_ENTITY, "pick is required when margin>=1")
        elif "Prediction already settled" in str(e):
            raise HTTPException(HTTPStatus.CONFLICT, ErrorMessages.PREDICTION_ALREADY_SETTLED)
        else:
            raise HTTPException(HTTPStatus.BAD_REQUEST, str(e))


@router.patch("/{prediction_id}", response_model=schemas.PredictionOut)
def update_prediction(
    prediction_id: int,
    payload: schemas.PredictionUpdate,
    db: Session = Depends(get_db),
    me: dict = Depends(get_current_user),
):
    uid = me["id"]
    prediction_service = PredictionService(db)
    
    try:
        result = prediction_service.update_prediction(
            user_id=uid,
            match_id=prediction_id,
            pick=payload.pick,
            margin=payload.margin
        )
        return result
    except ValueError as e:
        if "Match not found" in str(e):
            raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.MATCH_NOT_FOUND)
        elif "Predictions are locked" in str(e):
            raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.PREDICTIONS_LOCKED)
        elif "margin must be >= 0" in str(e):
            raise HTTPException(HTTPStatus.UNPROCESSABLE_ENTITY, "margin must be >= 0")
        elif "pick is required when margin>=1" in str(e):
            raise HTTPException(HTTPStatus.UNPROCESSABLE_ENTITY, "pick is required when margin>=1")
        elif "Prediction already settled" in str(e):
            raise HTTPException(HTTPStatus.CONFLICT, ErrorMessages.PREDICTION_ALREADY_SETTLED)
        else:
            raise HTTPException(HTTPStatus.BAD_REQUEST, str(e))

@router.get("/my", response_model=List[schemas.PredictionOut])
def my_predictions(
    upcoming_only: bool = Query(False),
    db: Session = Depends(get_db),
    me: dict = Depends(get_current_user),
):
    user_id = me["id"]
    q = db.query(models.Prediction).filter(models.Prediction.user_id == user_id)
    if upcoming_only:
        now = dt.datetime.utcnow()
        q = (q.join(models.Match, models.Match.id == models.Prediction.match_id)
               .filter(models.Match.match_date >= now))
    return q.order_by(models.Prediction.created_at.desc()).all()

@router.get("/me/{match_id}", response_model=schemas.PredictionOut)
def get_my_prediction(
    match_id: int,
    db: Session = Depends(get_db),
    me: dict = Depends(get_current_user),
):
    user_id = me["id"]
    prediction_service = PredictionService(db)
    
    pred = prediction_service.get_prediction(user_id, match_id)
    if not pred:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Prediction not found (or not yours)")

    return pred

@router.get("/{prediction_id}", response_model=schemas.PredictionOut)
def get_prediction(
    prediction_id: int,
    db: Session = Depends(get_db),
):
    pred = db.get(models.Prediction, prediction_id)
    if not pred:
        raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.PREDICTION_NOT_FOUND)
    return pred


@router.post("/settle/{match_id}", dependencies=[Depends(require_admin)])
def settleGame(match_id: int, db: Session = Depends(get_db)):
    m = db.get(models.Match, match_id) if hasattr(db, "get") else db.query(models.Match).get(match_id)
    if not m:
        raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.MATCH_NOT_FOUND)
    home_score, away_score, status = m.home_score, m.away_score, m.status 
    if home_score is None or away_score is None or status != "finished":
        raise HTTPException(HTTPStatus.PRECONDITION_FAILED, ErrorMessages.MATCH_NOT_FINISHED)
    if home_score == away_score:
        raise HTTPException(HTTPStatus.PRECONDITION_FAILED, ErrorMessages.MATCH_NOT_FINISHED_DRAW)
    
    winner = "home" if (home_score > away_score) else "away"
    real_margin = abs(home_score-away_score)
    update_sql = text("""
        UPDATE predictions
        SET points_awarded = CASE
            WHEN pick IS NULL OR margin = 0 THEN 0
            WHEN pick <> CAST(:winner AS pick_enum) THEN -2
            WHEN ABS(:real_margin - margin) = 0 THEN 8
            WHEN ABS(:real_margin - margin) = 1 THEN 6
            WHEN ABS(:real_margin - margin) = 2 THEN 5
            WHEN ABS(:real_margin - margin) = 3 THEN 4
            ELSE 3
        END,
            is_final = TRUE
        WHERE match_id = :match_id
          AND is_final = FALSE
    """)
    res = db.execute(update_sql, {"winner": winner, "real_margin": real_margin, "match_id": match_id})
    updated_now = res.rowcount or 0
    db.commit()
    total_sql = text("SELECT COUNT(*) FROM predictions WHERE match_id = :match_id AND is_final = TRUE")
    settled_total = db.execute(total_sql, {"match_id": match_id}).scalar() or 0

    return {
        "match_id": match_id,
        "updated_now": updated_now,
        "settled_total": settled_total,
        "actual_winner": winner,
        "actual_margin": real_margin,
        "scores": {"home": home_score, "away": away_score},
        "status": status,
    }
    ####### ----------------- MORE CODE AFTER ------------------------########
    #Simpler, less effective, if the above doesn't work O(1) vs O(N)
    #predictions =  db.query(models.Prediction).filter(models.Prediction.match_id == match_id).all()
    # updated_now = 0 
    # for pred in predictions:
    #     if pred.is_final:
    #         continue
    #     if pred.pick is None or pred.margin == 0:
    #         pred.points_awarded = 0
    #         pred.is_final = True
    #         updated_now += 1
    #         continue
    #     dist = abs(real_margin - pred.margin)
    #     if pred.pick != winner:
    #         pred.points_awarded =-2
    #     elif dist == 0:
    #         pred.points_awarded = 8
    #     elif dist == 1:
    #         pred.points_awarded = 6
    #     elif dist == 2:   
    #         pred.points_awarded = 5
    #     elif dist == 3:   
    #         pred.points_awarded = 4
    #     else:
    #         pred.points_awarded = 3
    #     pred.is_final = True
    #     updated_now += 1
    # db.commit()
    # settled_total = sum(1 for p in predictions if p.is_final)
    # return {
    #     "match_id": match_id,
    #     "updated_now": updated_now,         # settled in THIS call
    #     "settled_total": settled_total,     # all predictions now final
    #     "actual_winner": winner,
    #     "actual_margin": real_margin,
    #     "scores": {"home": home_score, "away": away_score},
    #     "status": status,
    # }
    
    

@router.get("/predictions/by-match/{match_id}")
def get_match_stats(match_id: int, db: Session = Depends(get_db)):
    signed_margin = case(
        (models.Prediction.pick == "home", models.Prediction.margin),
        (models.Prediction.pick == "away", -models.Prediction.margin),
    )

    base = db.query(models.Prediction).filter(
        models.Prediction.match_id == match_id,
        models.Prediction.margin >= 1
    )

    total = base.count()
    if total == 0:
        return {
            "match_id": match_id,
            "total": 0,
            "favorite": None,
            "confidence_pct": None,
            "avg_signed_margin": None,
            "median_signed_margin": None,
            "margin_histogram": [
                {"range":"-10-","count":0},
                {"range":"-9--7","count":0},
                {"range":"-6--4","count":0},
                {"range":"-3--1","count":0},
                {"range":"1-3","count":0},
                {"range":"4-6","count":0},
                {"range":"7-9","count":0},
                {"range":"10+","count":0},
            ],
        }

    # Favorite side & confidence
    pick_home = db.query(func.count()).filter(
        models.Prediction.match_id == match_id,
        models.Prediction.margin >= 1,
        models.Prediction.pick == "home"
    ).scalar()

    pick_away = total - pick_home

    if pick_home > pick_away:
        favorite = "home"
        confidence_pct = round(pick_home / total * 100, 1)
    elif pick_away > pick_home:
        favorite = "away"
        confidence_pct = round(pick_away / total * 100, 1)
    else:
        favorite = None
        confidence_pct = 50.0

    # Weighted averages
    avg_margin_val = db.query(func.avg(signed_margin)).filter(
        models.Prediction.match_id == match_id,
        models.Prediction.margin >= 1
    ).scalar()
    avg_signed_margin = round(float(avg_margin_val), 2) if avg_margin_val is not None else None

    median_signed_margin = db.query(
        func.percentile_cont(0.5).within_group(signed_margin)
    ).filter(
        models.Prediction.match_id == match_id,
        models.Prediction.margin >= 1
    ).scalar()

    # Histogram (negative for away, positive for home)
    bucket_expr = case(
        (signed_margin <= -10, "-10-"),
        (signed_margin.between(-9, -7), "-9--7"),
        (signed_margin.between(-6, -4), "-6--4"),
        (signed_margin.between(-3, -1), "-3--1"),
        (signed_margin.between(1, 3), "1-3"),
        (signed_margin.between(4, 6), "4-6"),
        (signed_margin.between(7, 9), "7-9"),
        else_="10+"
    ).label("rng")

    rows = db.query(bucket_expr, func.count().label("count")).filter(
        models.Prediction.match_id == match_id,
        models.Prediction.margin >= 1
    ).group_by(bucket_expr).all()

    buckets = {"-10-": 0, "-9--7": 0, "-6--4": 0, "-3--1": 0, "1-3": 0, "4-6": 0, "7-9": 0, "10+": 0}
    for r in rows:
        buckets[r.rng] = r.count

    histogram = [{"range": k, "count": buckets[k]} for k in buckets.keys()]

    return {
        "match_id": match_id,
        "total": total,
        "home_pick": pick_home,
        "away_pick":pick_away,
        "favorite": favorite,
        "confidence_pct": confidence_pct,
        "avg_signed_margin": avg_signed_margin,
        "median_signed_margin": median_signed_margin,
        "margin_histogram": histogram,
    }
    
    
@router.get("/predictions/preview/{match_id}")
def preview_my_prediction(match_id: int, db: Session = Depends(get_db), me: dict = Depends(get_current_user)):
    m = db.get(models.Match, match_id)
    user_id = me["id"]
    if not m: raise HTTPException(404, "Match not found")
    pred = db.query(models.Prediction).filter_by(match_id=match_id, user_id=user_id).first()
    if not pred: 
        return {"match_id": match_id, "preview_points": None, "reason": "no_prediction"}
    from app.scoring import preview_points
    pts = preview_points(pred.pick, pred.margin, m.home_score, m.away_score)
    return {"match_id": match_id, "preview_points": pts}


#Simpler, less effective, if the above doesn't work O(1) vs O(N)
# @router.get("/predictions/by-match/{match_id}")
# def get_match_stats_py(match_id: int, db: Session = Depends(get_db)):
#     preds = (
#         db.query(models.Prediction)
#         .filter(models.Prediction.match_id == match_id, models.Prediction.margin >= 1)
#         .all()
#     )
#     if not preds:
#         return {
#             "match_id": match_id,
#             "total": 0,
#             "pick_home": 0,
#             "pick_away": 0,
#             "favorite": None,
#             "confidence_pct": None,
#             "avg_margin": None,
#             "median_margin": None,
#             "avg_points": 0,
#             "margin_histogram": [
#                 {"range":"1-3","count":0},
#                 {"range":"4-6","count":0},
#                 {"range":"7-9","count":0},
#                 {"range":"10+","count":0},
#             ],
#         }

#     total = len(preds)
#     pick_home = sum(1 for p in preds if p.pick == "home")
#     pick_away = total - pick_home

#     if pick_home > pick_away:
#         favorite = "home"
#         confidence_pct = round(100 * pick_home / total, 1)
#     elif pick_away > pick_home:
#         favorite = "away"
#         confidence_pct = round(100 * pick_away / total, 1)
#     else:
#         favorite = None
#         confidence_pct = 50.0

#     margins = [p.margin for p in preds]
#     avg_margin = round(sum(margins) / total, 2)
#     median_margin = median(margins)

#     buckets = {"1-3": 0, "4-6": 0, "7-9": 0, "10+": 0}
#     for m in margins:
#         if 1 <= m <= 3:
#             buckets["1-3"] += 1
#         elif 4 <= m <= 6:
#             buckets["4-6"] += 1
#         elif 7 <= m <= 9:
#             buckets["7-9"] += 1
#         else:
#             buckets["10+"] += 1
#     histogram = [{"range": k, "count": buckets[k]} for k in ["1-3","4-6","7-9","10+"]]

#     avg_points = round(sum(p.points_awarded for p in preds) / total, 2)

#     return {
#         "match_id": match_id,
#         "total": total,
#         "pick_home": pick_home,
#         "pick_away": pick_away,
#         "favorite": favorite,
#         "confidence_pct": confidence_pct,
#         "avg_margin": avg_margin,
#         "median_margin": median_margin,
#         "avg_points": avg_points,
#         "margin_histogram": histogram,
#     }