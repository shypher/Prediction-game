from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
import datetime as dt
from . import models, database
from .services import balldontlie, euroleague_open, thesportsdb
from .schemas import NextGameOut
router = APIRouter(prefix="/games", tags=["games"])
from sqlalchemy import text
from .utils.db_upsert import bulk_upsert_by_external_id


LEAGUE_RESOLVER = {
    "NBA": {"source": "balldontlie"},
    "EuroLeague": {"source": "apisports", "id": 120},
    "EuroBasket": {"source": "apisports", "id": 197},
    "Israel Super League": {"source": "apisports", "id": 51},
    "Israel": {"source": "apisports", "id": 51},
    "Israeli Super League": {"source": "apisports", "id": 51},
}

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _upsert_match(db: Session, row: dict) -> models.Match:
    q = None
    if row.get("external_id"):
        q = db.query(models.Match).filter(models.Match.external_id == row["external_id"]).first()
    if not q:
        q = (db.query(models.Match)
               .filter(models.Match.match_date == row.get("match_date"))
               .filter(models.Match.home_team == row.get("home_team"))
               .filter(models.Match.away_team == row.get("away_team"))
               .first())
    if q:
        for k, v in row.items():
            setattr(q, k, v)
        return q
    m = models.Match(**row)
    db.add(m)
    return m

def _resolve_league(league: str) -> dict:
    if league not in LEAGUE_RESOLVER:
        raise HTTPException(404, f"Unknown league '{league}'. Use one of: {', '.join(LEAGUE_RESOLVER.keys())}")
    return LEAGUE_RESOLVER[league]

EUROLEAGUE_SEASONCODE = lambda d: f"E{d.year if d.month >= 7 else d.year - 1}"

@router.get("/upcoming")
def upcoming(
    league: str,
    days: int = 30,
    db: Session = Depends(get_db),
):
    now = dt.datetime.utcnow()
    end = now + dt.timedelta(days=days)
    rows = []

    if league == "NBA":
        raw = balldontlie.get_games_range(now.date(), end.date())
        rows = [balldontlie.map_game_to_row(g) for g in raw]

    elif league == "EuroLeague":
        season_code = f"E{now.year if now.month >= 7 else (now.year - 1)}"
        rows = []
        try:
            rows = euroleague_open.get_games_range(now.date(), end.date(), season_code=season_code)
        except Exception:
            rows = []

        if not rows:
            season_str = thesportsdb.tsdb_season_for_euroleague(now.date())
            events = thesportsdb.events_season_by_league("EuroLeague", season_str)
            for ev in events:
                r = thesportsdb.map_event_to_row(ev, "EuroLeague")
                if r["match_date"] and now <= r["match_date"] <= end:
                    rows.append(r)

        if rows:
            bulk_upsert_by_external_id(db, rows)
            db.commit()

    elif league == "EuroBasket":
        # TSDB לפי עונה 2025 (טורניר) + סינון חלון
        season_str = thesportsdb.tsdb_season_for_eurobasket(now.date())
        events = thesportsdb.events_season_by_league("EuroBasket", season_str)
        rows = []
        for ev in events:
            r = thesportsdb.map_event_to_row(ev, "EuroBasket")
            if r["match_date"] and now <= r["match_date"] <= end:
                rows.append(r)
        # אם עדיין אין (לפעמים TSDB לא עודכן) – אפשר להוסיף פה fallback של FIBA HTML/ICS

    elif league == "Israel Super League":
        season_str = thesportsdb.tsdb_season_for_israel(now.date())
        events = thesportsdb.events_season_by_league("Israel Super League", season_str)
        rows = []
        for ev in events:
            r = thesportsdb.map_event_to_row(ev, "Israel Super League")
            if r["match_date"] and now <= r["match_date"] <= end:
                rows.append(r)

    else:
        raise HTTPException(404, f"Unknown league '{league}'")

    if rows:
        bulk_upsert_by_external_id(db, rows)
        db.commit()

    q = (db.query(models.Match)
           .filter(models.Match.league_name == league)
           .filter(models.Match.match_date.isnot(None))
           .filter(models.Match.match_date >= now)
           .filter(models.Match.match_date <= end)
           .order_by(models.Match.match_date.asc()))
    return [{
        "id": r.id,
        "external_id": r.external_id,
        "league": r.league_name,
        "home": r.home_team,
        "away": r.away_team,
        "date": r.match_date,
        "status": r.status,
        "source": r.source,
        "season": r.season,
    } for r in q.all()]
    
    
@router.get("/_probe_tsdb")
def probe_tsdb(league: str, days: int = 30):
    """
    Probe ל-TheSportsDB: מחזיר כמה אירועים בעונת TSDB מתאימים לחלון now..now+days.
    """
    now_dt = dt.datetime.utcnow()
    end_dt = now_dt + dt.timedelta(days=days)

    # קבע עונת TSDB לפי הליגה
    if league == "EuroLeague":
        season = thesportsdb.tsdb_season_for_euroleague(now_dt.date())  # למשל "2025-2026"
    elif league == "Israel Super League":
        season = thesportsdb.tsdb_season_for_israel(now_dt.date())      # למשל "2025-2026"
    elif league == "EuroBasket":
        season = thesportsdb.tsdb_season_for_eurobasket(now_dt.date())  # "2025"
    else:
        raise HTTPException(400, "league must be EuroLeague | EuroBasket | Israel Super League")

    # משוך אירועי עונה ובדוק מה נופל בחלון
    events = thesportsdb.events_season_by_league(league, season)
    filtered = []
    for ev in events:
        row = thesportsdb.map_event_to_row(ev, league)
        if row["match_date"] and now_dt <= row["match_date"] <= end_dt:
            filtered.append({
                "external_id": row["external_id"],
                "home": row["home_team"],
                "away": row["away_team"],
                "date": row["match_date"],
                "season": row["season"]
            })

    return {
        "league": league,
        "season": season,
        "events_in_season": len(events),
        "events_in_window": len(filtered),
        "sample": filtered[:5]
    }



@router.get("/live")
def live(
    league: Optional[str] = Query(None, description="Optional, filter by league"),
    db: Session = Depends(get_db),
):
    if league:
        meta = _resolve_league(league)
        if meta["source"] == "apisports":
            live_games = thesportsdb.get_live_games(league_id=meta["id"])
            for g in live_games:
                row = thesportsdb.map_game_to_row(g, league_name=league, league_id=meta["id"])
                _upsert_match(db, row)
            db.commit()
        else:
            today = dt.datetime.utcnow().date()
            for g in balldontlie.get_games_by_date(today):
                row = balldontlie.map_game_to_row(g)
                _upsert_match(db, row)
            db.commit()
    else:
        live_all = thesportsdb.get_live_games()
        for g in live_all:
            league_name = "EuroLeague" if g.get("league", {}).get("id") == 120 else \
                          "EuroBasket" if g.get("league", {}).get("id") == 197 else \
                          "Israel Super League" if g.get("league", {}).get("id") == 51 else "Unknown"
            league_id = g.get("league", {}).get("id")
            row = thesportsdb.map_game_to_row(g, league_name=league_name, league_id=league_id or 0)
            _upsert_match(db, row)
        for g in balldontlie.get_games_by_date(dt.datetime.utcnow().date()):
            row = balldontlie.map_game_to_row(g)
            _upsert_match(db, row)
        db.commit()

    q = db.query(models.Match).filter(models.Match.status.in_(["live", "Live", "In Progress", "inplay"]))
    if league:
        q = q.filter(models.Match.league_name == league)
    rows = q.order_by(models.Match.match_date.asc()).all()
    return [
        {
            "id": r.id,
            "league": r.league_name,
            "home": r.home_team,
            "away": r.away_team,
            "home_score": r.home_score,
            "away_score": r.away_score,
            "status": r.status,
            "date": r.match_date,
        }
        for r in rows
    ]

@router.post("/sync/fixtures")
def sync_fixtures(
    league: str = Query(...),
    days: int = 14,
    db: Session = Depends(get_db),
):
    return upcoming(league=league, days=days, db=db)

@router.get(
    "/next",
    response_model=List[NextGameOut],
    summary="Get the next X upcoming games from the DB",
    description="Returns upcoming games (match_date >= now or a provided start_from), sorted by date, with optional league/team filters and pagination."
)
def get_next_games(
    limit: int = Query(10, ge=1, le=200, description="How many games to return (default 10, max 200)"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    league: Optional[str] = Query(None, description="Filter by league name, e.g., NBA / EuroLeague / EuroBasket / Israel Super League"),
    team: Optional[str] = Query(None, description="Substring filter on team name (home/away)"),
    start_from: Optional[dt.datetime] = Query(None, description="Start datetime in ISO8601 (UTC). If omitted, uses current UTC time"),
    db: Session = Depends(get_db),
):

    now = dt.datetime.utcnow()
    base = start_from or now

    q = (db.query(models.Match)
        .filter(models.Match.match_date.isnot(None))
        .filter(models.Match.match_date >= base))

    if league:
        q = q.filter(models.Match.league_name == league)

    if team:
        ilike = f"%{team}%"
        q = q.filter(
            (models.Match.home_team.ilike(ilike)) |
            (models.Match.away_team.ilike(ilike))
        )

    rows = (q.order_by(models.Match.match_date.asc())
              .offset(offset)
              .limit(limit)
              .all())

    # Map DB rows to the schema shape (explicit keys)
    return [
        {
            "id": r.id,
            "external_id": r.external_id,
            "league": r.league_name,
            "home": r.home_team,
            "away": r.away_team,
            "date": r.match_date,
            "status": r.status,
            "source": r.source,
            "season": r.season,
        } for r in rows
    ]

@router.get("/_debug_counts")
def debug_counts(db: Session = Depends(get_db)):
    rows = db.execute(text("""
        SELECT COALESCE(league_name,'(NULL)') AS league,
               COUNT(*) AS cnt,
               MIN(match_date) AS min_date,
               MAX(match_date) AS max_date
        FROM matches
        GROUP BY league_name
        ORDER BY 1
    """)).fetchall()
    return [{"league": r[0], "count": r[1], "min_date": r[2], "max_date": r[3]} for r in rows]

@router.get("/_debug_sources")
def debug_sources(db: Session = Depends(get_db)):
    rows = db.execute(text("""
        SELECT COALESCE(league_name,'?') AS league,
               COALESCE(source,'?') AS source,
               COUNT(*) AS cnt,
               MIN(match_date) AS min_date,
               MAX(match_date) AS max_date
        FROM matches
        GROUP BY league, source
        ORDER BY league, source
    """)).fetchall()
    return [
        {"league": r[0], "source": r[1], "count": r[2], "min_date": r[3], "max_date": r[4]}
        for r in rows
    ]

@router.get("/_probe_euroleague")
def probe_euroleague(days: int = 60):
    now = dt.datetime.utcnow()
    end = now + dt.timedelta(days=days)
    season_code = f"E{now.year if now.month >= 7 else (now.year - 1)}"

    # Open API
    open_count, open_sample = 0, []
    try:
        raw_open = euroleague_open.get_games_range(now.date(), end.date(), season_code)
        open_count = len(raw_open)
        open_sample = raw_open[:3]
    except Exception as e:
        open_sample = [{"error": str(e)}]

    # TSDB
    tsdb_count, tsdb_sample = 0, []
    try:
        season_str = thesportsdb.tsdb_season_for_euroleague(now.date())
        events = thesportsdb.events_season_by_league("EuroLeague", season_str)
        filt = []
        for ev in events:
            row = thesportsdb.map_event_to_row(ev, "EuroLeague")
            if row["match_date"] and now <= row["match_date"] <= end:
                filt.append(row)
        tsdb_count = len(filt)
        tsdb_sample = filt[:3]
    except Exception as e:
        tsdb_sample = [{"error": str(e)}]

    return {
        "season_code": season_code,
        "open_api": {"count": open_count, "sample": open_sample},
        "tsdb": {"season": season_str, "count": tsdb_count, "sample": tsdb_sample},
    }