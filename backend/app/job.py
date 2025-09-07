import datetime as dt
import logging
from typing import Dict, Any, Iterable
from sqlalchemy import text, exists, and_
from .core.database import SessionLocal
from .db import models
from app.services import balldontlie
from app.services import euroleague_open 
from app.services import thesportsdb
from .db.db_upsert import bulk_upsert_by_external_id
from .core import database
from .realtime import hub
import asyncio
import os
from typing import List, Dict, Any
from .core.constants import League
from .services.bot import _upsert_bot_prediction, _has_pred_for_bot,_random_params_for_bot,_random_pick_and_margin,_crowd_pick_and_margin,CROWD_OVERWRITE
from .core.constants import BotID
from datetime import timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from typing import Optional


def set_scheduler(s: AsyncIOScheduler):
    global _SCHED
    _SCHED = s
def _is_enabled(name: str, default: bool = True) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "on", "yes", "y")

def _enabled_leagues_from_env():
    csv = os.getenv("SEED_LEAGUES")
    if csv:
        return {name.strip() for name in csv.split(",") if name.strip()}
    active = set()
    if _is_enabled("ENABLE_SEED_NBA", True): active.add("NBA")
    if _is_enabled("ENABLE_SEED_EUROLEAGUE", True): active.add("EuroLeague")
    if _is_enabled("ENABLE_SEED_EUROBASKET", True): active.add("EuroBasket")
    if _is_enabled("ENABLE_SEED_ISRAEL", True): active.add("Israel")
    return active

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

logger = logging.getLogger("jobs")

def _update_existing_match(db, external_id: str, fields: Dict[str, Any]) -> bool:

    m = (
        db.query(models.Match)
        .filter(models.Match.external_id == external_id)
        .one_or_none()
    )
    if not m:
        return False
    changed = False
    for key, val in fields.items():
        if hasattr(m, key) and getattr(m, key) != val:
            setattr(m, key, val)
            changed = True
    if changed:
        m.last_update = dt.datetime.utcnow()
    return changed

def settle_match_bulk(db, match_id: int, winner: str, real_margin: int) -> int:

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
    res = db.execute(update_sql, {
        "winner": winner,
        "real_margin": real_margin,
        "match_id": match_id
    })
    return res.rowcount or 0

def job_settle_ready():
    with SessionLocal() as db:
        try:
            ready = (
                db.query(models.Match)
                .filter(models.Match.status == "finished")
                .filter(models.Match.home_score.isnot(None))
                .filter(models.Match.away_score.isnot(None))
                .filter(
                    db.query(models.Prediction)
                        .filter(models.Prediction.match_id == models.Match.id)
                        .filter(models.Prediction.is_final == False)
                        .exists()
                )
                .all()
            )
            total_updates = 0
            for m in ready:
                if m.home_score == m.away_score:
                    logger.warning("Skip settle match_id=%s (draw/invalid)", m.id)
                    continue
                winner = "home" if m.home_score > m.away_score else "away"
                real_margin = abs(m.home_score - m.away_score)
                updated = settle_match_bulk(db, m.id, winner, real_margin)
                total_updates += updated
                
            affected = (
            db.query(models.Match.id)
              .filter(models.Match.status.in_(["canceled"]))
              .filter(
                  db.query(models.Prediction)
                    .filter(models.Prediction.match_id == models.Match.id)
                    .filter(models.Prediction.is_final == False)
                    .exists()
              ).all()
            )
            if affected:
                db.execute(text("""
                    UPDATE predictions
                    SET points_awarded = 0,
                        is_final = TRUE
                    WHERE match_id = ANY(:ids)
                    AND is_final = FALSE
                """), {"ids": [x.id for x in affected]})
                total_updates += len(affected)

            if total_updates:
                db.commit()
            logger.info("[job_settle_ready] matches=%d preds_updated=%d", len(ready), total_updates)
        finally:
            db.close()

def _norm_status(s: str | None) -> str:
    if not s:
        return "scheduled"
    t = s.strip().lower()
    if t in {"finished", "final", "full time", "ft", "aet", "after extra time"}:
        return "finished"
    if t in {"live", "in progress", "in_progress", "playing", "in play", "1h", "2h", "ht", "ot"}:
        return "live"
    if t in {"postponed"}:
        return "postponed"
    if t in {"canceled", "cancelled", "abandoned"}:
        return "canceled"
    return "scheduled"

def job_update_scores(window_hours: int = 24):

    with SessionLocal() as db:
        updated_fields = 0
        inserted = 0

        now = dt.datetime.utcnow()
        sdt = dt.datetime.combine((now - dt.timedelta(hours=window_hours)).date(), dt.time.min)
        edt = dt.datetime.combine((now + dt.timedelta(hours=window_hours)).date(), dt.time.max)

        enabled = _enabled_leagues_from_env()
        new_rows: list[dict] = []

        def _apply_row(r: dict) -> None:
            nonlocal updated_fields, inserted

            ext_id = r.get("external_id")
            when = r.get("match_date")
            if not ext_id or when is None:
                return
            if not (sdt <= when <= edt):
                return
            st = _norm_status(r.get("status"))
            hs = r.get("home_score")
            as_ = r.get("away_score")
            if (hs is not None and as_ is not None) and st not in {"canceled", "postponed"}:
                st = "finished"

            fields = {"status": st}
            if hs is not None:
                fields["home_score"] = hs
            if as_ is not None:
                fields["away_score"] = as_

            if _update_existing_match(db, ext_id, fields):
                updated_fields += 1
            else:
                new_rows.append(r)

        try:
            for league in League:
                lname = league.value
                if lname not in enabled:
                    logger.info("%s update disabled by config", lname)
                    continue

                try:
                    rows = LEAGUE_HANDLERS[league](sdt, edt) 
                    if not rows:
                        continue
                    for r in rows:
                        _apply_row(r)
                except Exception as e:
                    logger.exception("%s update failed: %s", lname, e)

            if new_rows:
                seen = set()
                deduped = []
                for r in new_rows:
                    ext = r.get("external_id")
                    if not ext or ext in seen:
                        continue
                    seen.add(ext)
                    deduped.append(r)
                if deduped:
                    bulk_upsert_by_external_id(db, deduped)
                    inserted = len(deduped)

            if updated_fields or inserted:
                db.commit()

            logger.info(
                "[job_update_scores] updated=%d, inserted=%d, window=%s..%s",
                updated_fields, inserted, sdt, edt
            )
        finally:
            db.close()
    job_settle_ready()
        
       
def _schedule_or_now(sched: AsyncIOScheduler, func, when: dt.datetime,
                     job_id: str, args: list[int], until: dt.datetime | None):
    now = dt.datetime.utcnow().replace(tzinfo=sched.timezone)
    when  = _aware(when,  sched.timezone)
    until = _aware(until, sched.timezone) if until else None

    if when <= now and (until is None or now < until):
        when = now + dt.timedelta(seconds=5)
    elif when <= now:
        return

    sched.add_job(func, "date",
                  run_date=when, id=job_id, args=args,
                  replace_existing=True, misfire_grace_time=300) 
def job_seed_future(days_ahead: int = 30):
    db = SessionLocal()
    try:
        now = dt.datetime.utcnow()
        end = now + dt.timedelta(days=days_ahead)
        all_rows = []

        enabled = _enabled_leagues_from_env()

        for league in League:
            if league.value not in enabled:
                logger.info("%s seeding disabled by config", league.value)
                continue

            try:
                rows = LEAGUE_HANDLERS[league](now, end)
                all_rows.extend([r for r in rows if r.get("external_id")])
            except Exception as e:
                logger.exception("%s seed failed: %s", league.value, e)

        if all_rows:
            seen, deduped = set(), []
            for r in all_rows:
                ext = r.get("external_id")
                if not ext or ext in seen:
                    continue
                seen.add(ext)
                deduped.append(r)

            bulk_upsert_by_external_id(db, deduped)
            
            db.commit()
            ext_ids = [r["external_id"] for r in deduped if r.get("external_id")]
            if _SCHED and ext_ids:
                try:
                    schedule_bots_for_ext_ids(_SCHED, SessionLocal, ext_ids)
                except Exception as e:
                    logger.exception("schedule_bots_for_ext_ids failed: %s", e)
            logger.info("[job_seed_future] upserted=%d (window %s..%s)",
                        len(deduped), now.date(), end.date())
        else:
            logger.info("[job_seed_future] nothing to seed (window %s..%s)", now.date(), end.date())
    finally:
        db.close()
        
def _exists_reminder(db, match_id: int, user_id: int, kind: str = "one_hour") -> bool:  # שנה מ-str ל-int
    sql = text("SELECT 1 FROM ws_reminders_sent WHERE match_id=:m AND user_id=:u AND kind=:k")
    res = db.execute(sql, {"m": match_id, "u": user_id, "k": kind}).first()
    return res is not None

def _mark_reminder_sent(db, match_id: int, user_id: int, kind: str = "one_hour") -> None:  # שנה מ-str ל-int
    sql = text("""
        INSERT INTO ws_reminders_sent (match_id, user_id, kind)
        VALUES (:m, :u, :k)
        ON CONFLICT (match_id, user_id, kind) DO NOTHING
    """)
    db.execute(sql, {"m": match_id, "u": user_id, "k": kind})


def _user_has_active_prediction(db, match_id: int, user_id: int) -> bool:  # שנה מ-str ל-int
    return db.query(
        exists().where(
            and_(
                models.Prediction.match_id == match_id,
                models.Prediction.user_id == user_id,
                models.Prediction.margin >= 1
            )
        )
    ).scalar()

def _match_to_payload(m: models.Match) -> dict:
    return {
        "id": m.id,
        "league": m.league_name,
        "home": m.home_team,
        "away": m.away_team,
        "date_utc": m.match_date.isoformat() if m.match_date else None,
        "status": m.status,
        "season": m.season,
        "external_id": m.external_id,
    }

def job_ws_reminders_one_hour():
    db = SessionLocal()
    try:
        now = dt.datetime.utcnow()
        start = now + dt.timedelta(hours=1)
        window_start = start.replace(second=0, microsecond=0)
        window_end   = window_start + dt.timedelta(hours=1)

        matches = (
            db.query(models.Match)
              .filter(models.Match.status == "scheduled")
              .filter(models.Match.match_date >= window_start)
              .filter(models.Match.match_date <  window_end)
              .all()
        )
        if not matches:
            return

        
        online_users = list(hub.users())
        if not online_users:
            return

        for m in matches:
            match_payload = _match_to_payload(m)
            for uid in online_users:
                if _exists_reminder(db, m.id, uid, "one_hour"):
                    continue
                has_pred = _user_has_active_prediction(db, m.id, uid)
                action = "update" if has_pred else "create"
                payload = {
                    "type": "prediction_reminder",
                    "kind": "one_hour",
                    "action": action,  
                    "lock_hint_minutes": 60,
                    "match": match_payload,
                }
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(hub.send_to_user(uid, payload))
                    else:
                        asyncio.run(hub.send_to_user(uid, payload))
                except RuntimeError:
                    pass

        db.commit()
    finally:
        db.close()
        
def job_housekeeping():
    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM ws_reminders_sent WHERE sent_at < NOW() - INTERVAL '14 days'"))
        db.commit()
    finally:
        db.close()
        
        
        
        
        
def _seed_nba(now: dt.datetime, end: dt.datetime) -> List[Dict[str, Any]]:
    raw = balldontlie.get_games_range(now.date(), end.date())
    return [balldontlie.map_game_to_row(g) for g in raw if g.get("id")]


def _seed_euroleague(now: dt.datetime, end: dt.datetime) -> List[Dict[str, Any]]:
    season_code = f"E{now.year if now.month >= 7 else (now.year - 1)}"
    return euroleague_open.get_games_range(now.date(), end.date(), season_code=season_code) or []


def _seed_eurobasket(start: dt.datetime, end: dt.datetime) -> List[Dict[str, Any]]:
    rows = []
    window_start = dt.datetime.combine(start.date(), dt.time.min)
    day = window_start.date()

    calls = 0
    while day <= end.date():
        evs = thesportsdb.events_day(day, league_name="FIBA EuroBasket")
        for ev in evs:
            r = thesportsdb.map_event_to_row(ev, "EuroBasket")
            md = r.get("match_date")
            if md and window_start <= md <= end:
                rows.append(r)
        calls += 1
        if calls % 5 == 0:
            import time
            time.sleep(15)
        day += dt.timedelta(days=1)
    return rows


def _seed_israel(now: dt.datetime, end: dt.datetime) -> List[Dict[str, Any]]:
    rows = []
    day = now.date()
    calls = 0
    while day <= end.date():
        evs = thesportsdb.events_day(day, league_name="Israel Super League")
        for ev in evs:
            r = thesportsdb.map_event_to_row(ev, "Israel Super League")
            if r.get("match_date") and now <= r["match_date"] <= end:
                rows.append(r)
        calls += 1
        if calls % 5 == 0:
            import time
            time.sleep(15)
        day += dt.timedelta(days=1)
    return rows


LEAGUE_HANDLERS = {
    League.NBA: _seed_nba,
    League.EUROLEAGUE: _seed_euroleague,
    League.EUROBASKET: _seed_eurobasket,
    League.ISRAEL: _seed_israel,
}


def run_random_bots_for_match_job(match_id: int):
    with SessionLocal() as db:
        m = db.get(models.Match, match_id)
        if not m or m.status != "scheduled":
            return
        changed = 0
        for key, enum_id in (("random_01", BotID.RANDOM_01),
                             ("random_02", BotID.RANDOM_02),
                             ("random_03", BotID.RANDOM_03)):
            bot_id = int(enum_id.value)
            if _has_pred_for_bot(db, m.id, bot_id):
                continue
            params = _random_params_for_bot(key)
            side, mg = _random_pick_and_margin(**params)
            if _upsert_bot_prediction(db, m.id, bot_id, side, mg):
                changed += 1
        if changed:
            db.commit()

def run_crowd_bots_for_match_job(match_id: int):
    print("s2")
    with SessionLocal() as db:
        m = db.get(models.Match, match_id)
        if not m or m.status != "scheduled":
            return
        stats = _crowd_pick_and_margin(db, m.id)
        changed = 0
        mid = int(BotID.CROWD_MEDIAN.value)
        if (not _has_pred_for_bot(db, m.id, mid)) or CROWD_OVERWRITE:
            side, mg = stats["med_side"], stats["median"]
            if _upsert_bot_prediction(db, m.id, mid, side, mg):
                changed += 1
        aid = int(BotID.CROWD_MEAN.value)
        if (not _has_pred_for_bot(db, m.id, aid)) or CROWD_OVERWRITE:
            side, mg = stats["avg_side"], stats["avg_margin"]
            if _upsert_bot_prediction(db, m.id, aid, side, mg):
                changed += 1
        if changed:
            db.commit()

def run_book_bot_for_match_job(match_id: int):
    with SessionLocal() as db:
        m = db.get(models.Match, match_id)
        if not m or m.status != "scheduled":
            return
        # TODO
        side, mg = (None, 0)
        bid = int(BotID.BOOK_THEODDS.value)
        if not _has_pred_for_bot(db, m.id, bid):
            if _upsert_bot_prediction(db, m.id, bid, side, mg):
                db.commit()

def run_book_bot_for_match_job(match_id: int):
    with SessionLocal() as db:
        m = db.get(models.Match, match_id)
        if not m or m.status != "scheduled":
            return
        # TODO yippe
        side, mg = (None, 0)
        bid = int(BotID.BOOK_THEODDS.value)
        if not _has_pred_for_bot(db, m.id, bid):
            if _upsert_bot_prediction(db, m.id, bid, side, mg):
                db.commit()
                

_SCHED: Optional[AsyncIOScheduler] = None
def set_scheduler(s: AsyncIOScheduler):
    global _SCHED
    _SCHED = s

def _aware(dtobj: dt.datetime, tz) -> dt.datetime:
    if dtobj.tzinfo is None:
        return dtobj.replace(tzinfo=tz)
    return dtobj.astimezone(tz)

def _safe_run_date(sched: AsyncIOScheduler, func, run_date: dt.datetime, job_id: str, args: list[int]):
    now_utc = dt.datetime.utcnow().replace(tzinfo=sched.timezone) 
    run_date = _aware(run_date, sched.timezone)
    if run_date <= now_utc:
        return
    sched.add_job(func, "date", run_date=run_date, id=job_id,
                  args=args, replace_existing=True, misfire_grace_time=300)
async def arun_random_bots_for_match_job(match_id: int):
    await asyncio.to_thread(run_random_bots_for_match_job, match_id)

async def arun_crowd_bots_for_match_job(match_id: int):
    await asyncio.to_thread(run_crowd_bots_for_match_job, match_id)

async def arun_book_bot_for_match_job(match_id: int):
    await asyncio.to_thread(run_book_bot_for_match_job, match_id)


def schedule_bots_for_match(scheduler: AsyncIOScheduler, m: models.Match, now: Optional[dt.datetime] = None):
    if not m.match_date or m.status != "scheduled":
        return
    tz = scheduler.timezone
    now = now or dt.datetime.utcnow()
    created = m.last_update or now

    random_at = max(m.match_date - timedelta(days=7), created)
    crowd_at  = m.match_date
    book_at   = m.match_date - timedelta(seconds=60)

    _schedule_or_now(scheduler, arun_random_bots_for_match_job, random_at, f"bot_random_{m.id}", [m.id], m.match_date)
    _schedule_or_now(scheduler, arun_crowd_bots_for_match_job,  crowd_at,  f"bot_crowd_{m.id}",  [m.id], m.match_date)
    _schedule_or_now(scheduler, arun_book_bot_for_match_job,    book_at,   f"bot_book_{m.id}",   [m.id], m.match_date)

def schedule_bots_for_ext_ids(scheduler: AsyncIOScheduler, db_factory, ext_ids: list[str]):
    with db_factory() as s:
        now = dt.datetime.utcnow()
        matches = (s.query(models.Match)
                     .filter(models.Match.external_id.in_(ext_ids))
                     .filter(models.Match.status == "scheduled")
                     .filter(models.Match.match_date > now)
                     .all())
        for m in matches:
            schedule_bots_for_match(scheduler, m, now)

def schedule_bots_for_all_future(scheduler: AsyncIOScheduler):
    with SessionLocal() as s:
        now = dt.datetime.utcnow()
        matches = (s.query(models.Match)
                     .filter(models.Match.status == "scheduled")
                     .filter(models.Match.match_date > now)
                     .all())
        for m in matches:
            schedule_bots_for_match(scheduler, m, now)