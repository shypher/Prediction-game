import datetime as dt
import logging
from typing import Dict, Any, Iterable
from sqlalchemy import text, exists, and_
from app.database import SessionLocal
from .db import models
from app.services import balldontlie
from app.services import euroleague_open 
from app.services import thesportsdb
from .db.db_upsert import bulk_upsert_by_external_id
from . import database
from .realtime import hub
import asyncio
import os

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

def job_update_scores(window_hours: int = 6):
    with SessionLocal() as db:
        
        updated = 0
        now = dt.datetime.utcnow()
        sdt = dt.datetime.combine((now - dt.timedelta(hours=window_hours)).date(), dt.time.min)
        edt = dt.datetime.combine((now + dt.timedelta(hours=window_hours)).date(), dt.time.max)

        try:
            # === NBA (balldontlie) ===
            try:
                nba_games = balldontlie.get_games_range(sdt.date(), edt.date())
                for g in nba_games:
                    try:
                        row = balldontlie.map_game_to_row(g)
                    except Exception:
                        row = {
                            "external_id": f"nba_{g.get('id')}",
                            "status": ("finished" if g.get("status", "").lower().startswith("final")
                                    else "live" if "progress" in g.get("status", "").lower()
                                    else "scheduled"),
                            "home_score": g.get("home_team_score"),
                            "away_score": g.get("visitor_team_score"),
                        }
                    ext_id = row.get("external_id")
                    if not ext_id:
                        continue
                    fields = {"status": row.get("status")}
                    if row.get("home_score") is not None:
                        fields["home_score"] = row.get("home_score")
                    if row.get("away_score") is not None:
                        fields["away_score"] = row.get("away_score")
                    if _update_existing_match(db, ext_id, fields):
                        updated += 1
            except Exception as e:
                logger.exception("NBA update failed: %s", e)

            # === EuroLeague (XML schedules) ===
            try:
                el_rows = euroleague_open.get_games_range(sdt.date(), edt.date())
                for r in el_rows or []:
                    ext_id = r.get("external_id")
                    if not ext_id:
                        continue
                    status_raw = (r.get("status") or "").strip().lower()    
                    if status_raw == "finished":
                        if _update_existing_match(db, ext_id, {"status": "finished"}):
                            updated += 1
                    elif status_raw in {"in progress", "in_progress", "live", "playing"}:
                        m = (
                            db.query(models.Match)
                            .filter(models.Match.external_id == ext_id)
                            .one_or_none()
                        )
                        if m and m.status not in {"finished", "live"}:
                            if _update_existing_match(db, ext_id, {"status": "live"}):
                                updated += 1
                    
            except Exception as e:
                logger.exception("EuroLeague XML update failed: %s", e)

            # === EuroBasket  TheSportsDB ===
            try:
                tsdb_leagues = [
                    ("EuroBasket", thesportsdb.tsdb_season_for_eurobasket),
                    # ("Israel Super League", thesportsdb.tsdb_season_for_israel),
                ]

                def _norm_tsdb_status(ev_status: str | None, mapped_status: str | None) -> str:

                    if mapped_status:
                        ms = mapped_status.strip().lower()
                        if ms in {"finished", "ft", "full time", "aet", "after extra time", "final"}:
                            return "finished"
                        if ms in {"live", "in_progress", "playing"}:
                            return "live"
                        if ms in {"postponed"}:
                            return "postponed"
                        if ms in {"canceled", "cancelled", "abandoned"}:
                            return "canceled"

                    raw = (ev_status or "").strip().lower()
                    if raw in {"ft", "full time", "finished", "match finished", "final"}:
                        return "finished"
                    if raw in {"aet", "after extra time", "ft-pens", "penalties"}:
                        return "finished"
                    if raw in {"in play", "live", "playing", "1h", "2h", "ht", "ot"}:
                        return "live"
                    if raw in {"postponed"}:
                        return "postponed"
                    if raw in {"canceled", "cancelled", "abandoned"}:
                        return "canceled"
                    return "scheduled"

                for league_name, season_fn in tsdb_leagues:
                    season = season_fn(now.date())
                    events = thesportsdb.events_season_by_league(league_name, season)
                    if not events:
                        continue

                    for ev in events:
                        mapped = thesportsdb.map_event_to_row(ev, league_name)
                        when = mapped.get("match_date")
                        if when is None:
                            try:
                                d = ev.get("dateEvent")
                                t = ev.get("strTimestamp") or (ev.get("strTime") and f"{ev['strTime']}")
                                if d:
                                    when = dt.datetime.fromisoformat(f"{d}T{(t or '00:00:00')[:8]}")
                            except Exception:
                                pass
                        if when is None or not (sdt <= when <= edt):
                            continue

                        id_event = ev.get("idEvent")
                        if not id_event:
                            continue
                        ext_id = f"tsdb_{id_event}"
                        status = _norm_tsdb_status(ev.get("strStatus"), mapped.get("status"))
                        def _to_int(x):
                            try:
                                return int(x) if x is not None else None
                            except (TypeError, ValueError):
                                return None

                        hs = mapped.get("home_score")
                        as_ = mapped.get("away_score")
                        if hs is None:
                            hs = _to_int(ev.get("intHomeScore"))
                        if as_ is None:
                            as_ = _to_int(ev.get("intAwayScore"))

                        fields = {"status": status}
                        if hs is not None:
                            fields["home_score"] = hs
                        if as_ is not None:
                            fields["away_score"] = as_

                        if _update_existing_match(db, ext_id, fields):
                            updated += 1
            except Exception as e:
                logger.exception("EuroBasket (TSDB) update failed: %s", e)
            if updated:
                db.commit()
            logger.info("[job_update_scores] updated=%d window=%s..%s", updated, sdt, edt)

        finally:
            db.close()
        
        job_settle_ready()
        
        
def job_seed_future(days_ahead: int = 30):
    db = SessionLocal()
    try:
        now = dt.datetime.utcnow()
        end = now + dt.timedelta(days=days_ahead)
        all_rows = []

        enabled = _enabled_leagues_from_env()  # <<< חדש

        # --- NBA ---
        if "NBA" in enabled:  # <<< חדש
            try:
                raw = balldontlie.get_games_range(now.date(), end.date())
                nba_rows = [balldontlie.map_game_to_row(g) for g in raw]
                all_rows.extend([r for r in nba_rows if r.get("external_id")])
            except Exception as e:
                logger.exception("NBA seed failed: %s", e)
        else:
            logger.info("NBA seeding disabled by config")

        # --- EuroLeague (XML) ---
        if "EuroLeague" in enabled:  # <<< חדש
            try:
                season_code = f"E{now.year if now.month >= 7 else (now.year - 1)}"
                el_rows = euroleague_open.get_games_range(now.date(), end.date(), season_code=season_code)
                all_rows.extend([r for r in (el_rows or []) if r.get("external_id")])
            except Exception as e:
                logger.exception("EuroLeague seed failed: %s", e)
        else:
            logger.info("EuroLeague seeding disabled by config")

        # --- EuroBasket (TSDB via eventsday) ---
        if "EuroBasket" in enabled: 
            try:
                eb_rows = []
                day = now.date()
                calls = 0
                while day <= end.date():
                    evs = thesportsdb.events_day(day, league_name="FIBA EuroBasket")
                    for ev in evs:
                        r = thesportsdb.map_event_to_row(ev, "EuroBasket")
                        if r.get("match_date") and now <= r["match_date"] <= end:
                            eb_rows.append(r)
                    calls += 1
                    if calls % 5 == 0:
                        import time
                        time.sleep(15)  
                    day += dt.timedelta(days=1)

                all_rows.extend([r for r in eb_rows if r.get("external_id")])
            except Exception as e:
                logger.exception("EuroBasket seed failed: %s", e)
        else:
            logger.info("EuroBasket seeding disabled by config")

        # --- Israel Super League (TSDB via eventsday) ---
        if "Israel" in enabled:
            try:
                il_rows = []  
                day = now.date()
                calls = 0
                while day <= end.date():
                    evs = thesportsdb.events_day(day, league_name="Israel Super League")
                    for ev in evs:
                        r = thesportsdb.map_event_to_row(ev, "Israel Super League")
                        if r.get("match_date") and now <= r["match_date"] <= end:
                            il_rows.append(r)
                    calls += 1
                    if calls % 5 == 0:
                        import time
                        time.sleep(15)
                    day += dt.timedelta(days=1)

                all_rows.extend([r for r in il_rows if r.get("external_id")])
            except Exception as e:
                logger.exception("Israel Super League seed failed: %s", e)  # <<< תיקון הודעה
        else:
            logger.info("Israel Super League seeding disabled by config")

        # --- UPSERT + COMMIT ---
        if all_rows:
            seen = set()
            deduped = []
            for r in all_rows:
                ext = r.get("external_id")
                if not ext or ext in seen:
                    continue
                seen.add(ext)
                deduped.append(r)

            bulk_upsert_by_external_id(db, deduped)
            db.commit()
            logger.info("[job_seed_future] upserted=%d (window %s..%s)", len(deduped), now.date(), end.date())
        else:
            logger.info("[job_seed_future] nothing to seed (window %s..%s)", now.date(), end.date())

    finally:
        db.close()
        
def _exists_reminder(db, match_id: int, user_id: str, kind: str = "one_hour") -> bool:
    sql = text("SELECT 1 FROM ws_reminders_sent WHERE match_id=:m AND user_id=:u AND kind=:k")
    res = db.execute(sql, {"m": match_id, "u": user_id, "k": kind}).first()
    return res is not None

def _mark_reminder_sent(db, match_id: int, user_id: str, kind: str = "one_hour") -> None:
    sql = text("""
        INSERT INTO ws_reminders_sent (match_id, user_id, kind)
        VALUES (:m, :u, :k)
        ON CONFLICT (match_id, user_id, kind) DO NOTHING
    """)
    db.execute(sql, {"m": match_id, "u": user_id, "k": kind})

def _user_has_active_prediction(db, match_id: int, user_id: str) -> bool:
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
        window_end   = window_start + dt.timedelta(minutes=1)

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
                    asyncio.get_event_loop().create_task(hub.send_to_user(uid, payload))
                except RuntimeError:
                    pass
                _mark_reminder_sent(db, m.id, uid, "one_hour")

        db.commit()
    finally:
        db.close()
        
def job_housekeeping():
    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM ws_reminders_sent WHERE sent_at < NOW() - INTERVAL '14 days'"))

        # db.execute(text("""
        #   DELETE FROM matches m
        #   WHERE m.match_date < NOW() - INTERVAL '3 years'
        #     AND NOT EXISTS (SELECT 1 FROM predictions p WHERE p.match_id = m.id)
        # """))
        db.commit()
    finally:
        db.close()