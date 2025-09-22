from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Literal
import datetime as dt
from sqlalchemy import text, bindparam
from ..db.models import Team
from ..db import models
from ..core import database
from ..services import balldontlie, euroleague_open, thesportsdb
from ..db.schemas import NextGameOut
router = APIRouter(prefix="/games", tags=["games"])
from sqlalchemy import text
from ..db.db_upsert import bulk_upsert_by_external_id
from ..core.constants import LeagueConstants, LEAGUE_RESOLVER, ErrorMessages, HTTPStatus, AppConstants
from ..services.match_service import MatchService
from ..db.schemas import StandingRow
from ..services.euroleague_open import fetchStandings, get_team_stats as el_get_team_stats, get_team_leaders as el_get_team_leaders
from collections import defaultdict
from sqlalchemy import func
import requests


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
SPONSOR_TOKENS = {
    "fc","bc","basket","basketball","mozzart","meridianbet","segafredo","emporio","armani","aktor","beko","playtika","rapyd","ibi","ldlc"
}

ALIASES = {
    "milan": "olimpia milano",
    "ea7 emporio armani milan": "olimpia milano",
    "fc barcelona": "barcelona",
    "bayern munich": "bayern munich",
    "asvel villeurbanne": "asvel",
    "ldlc asvel villeurbanne": "asvel",
    "partizan belgrade": "partizan",
    "crvena zvezda belgrade": "crvena zvezda",
    "fenerbahce istanbul": "fenerbahce",
    "panathinaikos athens": "panathinaikos",
    "anadolu efes istanbul": "anadolu efes",
    "olympiacos piraeus": "olympiacos",
    "baskonia vitoria gasteiz": "baskonia",
    "zalgiris kaunas": "zalgiris",
    "valencia basket": "valencia",
    "paris basketball": "paris",
    "hapoel tel aviv": "hapoel tel aviv",
    "maccabi tel aviv": "maccabi tel aviv",
    "dubai basketball": "dubai basketball",
    "virtus bologna": "virtus bologna",
    "as monaco": "as monaco",
    "real madrid": "real madrid"
}
def normalize_name(s: str) -> str:
    x = (s or "").lower()
    out = []
    cur = []
    for ch in x:
        if ch.isalnum():
            cur.append(ch)
        else:
            cur.append(" ")
    x = "".join(cur)
    parts = [p for p in x.split() if p and p not in SPONSOR_TOKENS]
    return " ".join(parts)

def build_team_index(db: Session, league_ids) -> Dict[int, Dict[str, Team]]:
    idx: Dict[int, Dict[str, Team]] = {}
    for lid in league_ids:
        rows = db.query(Team).filter(Team.league_id == lid).all()
        m: Dict[str, Team] = {}
        for t in rows:
            m[normalize_name(t.name or "")] = t
        for alias, canonical in ALIASES.items():
            if canonical in m and alias not in m:
                m[alias] = m[canonical]
        idx[lid] = m
    return idx

@router.get("/upcoming")
def upcoming(
    league: str,
    days: int = AppConstants.DEFAULT_DAYS_RANGE,
    limit: Optional[int] = Query(None, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    svc = MatchService(db)
    try:
        rows = svc.get_upcoming_matches_db(league=league, days=days, limit=limit)
        return rows
    except ValueError as e:
        if "Unknown league" in str(e):
            raise HTTPException(HTTPStatus.NOT_FOUND, str(e))
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(e))

    
    
@router.get("/_probe_tsdb")
def probe_tsdb(league: str, days: int = 30):

    now_dt = dt.datetime.utcnow()
    end_dt = now_dt + dt.timedelta(days=days)

    if league == "EuroLeague":
        season = thesportsdb.tsdb_season_for_euroleague(now_dt.date())  
    elif league == "Israel Super League":
        season = thesportsdb.tsdb_season_for_israel(now_dt.date())     
    elif league == "EuroBasket":
        season = thesportsdb.tsdb_season_for_eurobasket(now_dt.date())  
    else:
        raise HTTPException(HTTPStatus.BAD_REQUEST, ErrorMessages.LEAGUE_MUST_BE_SPECIFIC)

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

        team_pattern = f"%{team}%"
        q = q.filter(
            (models.Match.home_team.ilike(team_pattern)) |
            (models.Match.away_team.ilike(team_pattern))
        )

    rows = (q.order_by(models.Match.match_date.asc())
              .offset(offset)
              .limit(limit)
              .all())

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
    
    
    
    
@router.get("/ui_next", summary="UI-ready matches for the frontend")
def get_ui_next_games(
    limit: int = Query(1000, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    league_id: Optional[int] = Query(None),
    league: Optional[str] = Query(None),
    date_from: Optional[dt.datetime] = Query(None),
    date_to: Optional[dt.datetime] = Query(None),
    days_before: int = Query(120, ge=0, le=730),
    days_after: int = Query(365, ge=0, le=730),
    scope: Literal["window","season"] = Query("window"),
    season: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    now = dt.datetime.utcnow()
    if scope == "season" and season is not None:
        q = db.query(models.Match).filter(models.Match.season == season)
    else:
        start = date_from or (now - dt.timedelta(days=days_before))
        end = date_to or (now + dt.timedelta(days=days_after))
        q = db.query(models.Match).filter(models.Match.match_date.isnot(None)).filter(models.Match.match_date.between(start, end))
    if league_id is not None:
        q = q.filter(models.Match.league_id == league_id)
    if league is not None:
        q = q.filter(models.Match.league_name == league)
    rows = q.order_by(models.Match.match_date.asc()).offset(offset).limit(limit).all()
    leagues = {r.league_id for r in rows if r.league_id is not None}
    tindex = build_team_index(db, leagues)
    def map_row(r):
        h = tindex.get(r.league_id, {}).get(normalize_name(r.home_team or ""))
        a = tindex.get(r.league_id, {}).get(normalize_name(r.away_team or ""))
        return {
            "id": r.id,
            "leagueId": r.league_id,
            "leagueName": r.league_name,
            "date": r.match_date.isoformat(),
            "status": (r.status or "upcoming").lower(),
            "home": {"name": r.home_team},
            "away": {"name": r.away_team},
            "homeTeamId": h.id if h else None,
            "awayTeamId": a.id if a else None,
            "score": {"home": r.home_score, "away": r.away_score} if (r.home_score is not None or r.away_score is not None) else None,
            "season": r.season,
        }
    return [map_row(r) for r in rows]



@router.get("/standings", response_model=List[StandingRow])
def get_standings(league: str, season: int, db: Session = Depends(get_db), conference: str | None = Query(None, description="NBA only: East/West"),division: str | None = Query(None, description="NBA only: Atlantic/Central/..."),
):
    league = league.lower()
    if league == "euroleague":
        data = fetchStandings(season_code={"E" + str(season)})
        rows = [
            {
                "team": r["team"],
                "w":    r["wins"],
                "l":    r["losses"],
                "pf":   r["pf"],
                "pa":   r["pa"],
                "diff": r["pf"] - r["pa"],
                "rank": r["rank"]
            }
            for r in data
        ]
        return rows

    elif league == "nba":
        rows =  compute_nba_standings(season=season, db=db)
        if not rows:
            teams = list_teams_from_matches(db, league_name=league, league_id=0, season=season)
            teams = [t for t in teams
                         if t and NBA_TEAM_META.get((t))
                         and (conference is None or NBA_TEAM_META[(t)]["conference"].lower() == conference.lower())
                         and (division   is None or NBA_TEAM_META[(t)]["division"].lower()   == division.lower())]
            if teams:
                rows = ensure_all_teams(rows, teams)
                rows = filter_nba_rows_by_meta(rows, conference=conference, division=division)
                rows.sort(key=lambda r: (-r["w"], -r["diff"], -r["pf"]))
            for i, r in enumerate(rows, 1):
                r["rank"] = i
        return rows

    else:
        raise HTTPException(status_code=400, detail="Unsupported league")

def ensure_all_teams(rows: list[dict], teams: list[str]) -> list[dict]:
    have = {r["team"] for r in rows}
    out = rows[:]
    for t in teams:
        if t not in have:
            out.append({"team": t, "w": 0, "l": 0, "pf": 0, "pa": 0, "diff": 0})
    out.sort(key=lambda r: (-r["w"], -(r["pf"] - r["pa"]), -r["pf"]))
    for r in out:
        r["diff"] = r["pf"] - r["pa"]
    
    return out
def list_teams_from_matches(
    db: Session, *, league_name: str | None = None, league_id: int | None = None, season: int | None = None
) -> list[str]:
    q = db.query(models.Team)
    if league_id is not None:
        q = q.filter(models.Team.league_id == league_id)
    elif league_name:
        q = q.filter(func.lower(models.Team.league_name) == league_name.lower())
    names = set()
    for t in q.all():
        if t.name: names.add(t.name)
    return sorted(names)
def compute_nba_standings(season: int, db: Session):
    q = (
        db.query(models.Match)
        .filter(models.Match.season == season)
        .filter(models.Match.league_name == "NBA")    
        .filter(models.Match.status.in_(["finished","final","ended"]))
    )
    agg = defaultdict(lambda: {"w":0,"l":0,"pf":0,"pa":0})
    for m in q:
        a = agg[m.home_team]; a["pf"] += m.home_score or 0; a["pa"] += m.away_score or 0
        if (m.home_score or 0) > (m.away_score or 0): a["w"] += 1
        else: a["l"] += 1
        b = agg[m.away_team]; b["pf"] += m.away_score or 0; b["pa"] += m.home_score or 0
        if (m.away_score or 0) > (m.home_score or 0): b["w"] += 1
        else: b["l"] += 1

    rows = [
        {"team": team, "w": v["w"], "l": v["l"], "pf": v["pf"], "pa": v["pa"], "diff": v["pf"]-v["pa"]}
        for team, v in agg.items()
    ]
    rows.sort(key=lambda r: (-r["w"], -r["diff"], -r["pf"]))
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return rows
    
NBA_TEAM_META: dict[str, dict[str, str]] = {
    # East - Atlantic
    "Boston Celtics":               {"conference": "East", "division": "Atlantic"},
    "Brooklyn Nets":                {"conference": "East", "division": "Atlantic"},
    "New York Knicks":              {"conference": "East", "division": "Atlantic"},
    "Philadelphia 76ers":           {"conference": "East", "division": "Atlantic"},
    "Toronto Raptors":              {"conference": "East", "division": "Atlantic"},
    # East - Central
    "Chicago Bulls":                {"conference": "East", "division": "Central"},
    "Cleveland Cavaliers":          {"conference": "East", "division": "Central"},
    "Detroit Pistons":              {"conference": "East", "division": "Central"},
    "Indiana Pacers":               {"conference": "East", "division": "Central"},
    "Milwaukee Bucks":              {"conference": "East", "division": "Central"},
    # East - Southeast
    "Atlanta Hawks":                {"conference": "East", "division": "Southeast"},
    "Charlotte Hornets":            {"conference": "East", "division": "Southeast"},
    "Miami Heat":                   {"conference": "East", "division": "Southeast"},
    "Orlando Magic":                {"conference": "East", "division": "Southeast"},
    "Washington Wizards":           {"conference": "East", "division": "Southeast"},
    # West - Northwest
    "Denver Nuggets":               {"conference": "West", "division": "Northwest"},
    "Minnesota Timberwolves":       {"conference": "West", "division": "Northwest"},
    "Oklahoma City Thunder":        {"conference": "West", "division": "Northwest"},
    "Portland Trail Blazers":       {"conference": "West", "division": "Northwest"},
    "Utah Jazz":                    {"conference": "West", "division": "Northwest"},
    # West - Pacific
    "Golden State Warriors":        {"conference": "West", "division": "Pacific"},
    "LA Clippers":                  {"conference": "West", "division": "Pacific"},
    "Los Angeles Lakers":           {"conference": "West", "division": "Pacific"},
    "Phoenix Suns":                 {"conference": "West", "division": "Pacific"},
    "Sacramento Kings":             {"conference": "West", "division": "Pacific"},
    # West - Southwest
    "Dallas Mavericks":             {"conference": "West", "division": "Southwest"},
    "Houston Rockets":              {"conference": "West", "division": "Southwest"},
    "Memphis Grizzlies":            {"conference": "West", "division": "Southwest"},
    "New Orleans Pelicans":         {"conference": "West", "division": "Southwest"},
    "San Antonio Spurs":            {"conference": "West", "division": "Southwest"},
}

def filter_nba_rows_by_meta(rows: list[dict], *, conference: str | None, division: str | None) -> list[dict]:
    if not conference and not division:
        return rows
    out = []
    for r in rows:
        meta = NBA_TEAM_META.get((r["team"]))
        if not meta:
            continue 
        if conference and meta["conference"].lower() != conference.lower():
            continue
        if division and meta["division"].lower() != division.lower():
            continue
        out.append(r)
    return out



@router.get("/euroleague/team-stats")
def euroleague_team_stats(team_code: str, season: int, phase: str = "All"):
    try:
        return el_get_team_stats(team_code=team_code, season=season, phase=phase)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"EuroLeague team-stats failed: {e}")

@router.get("/euroleague/team-leaders")
def euroleague_team_leaders(season: int, phase: str = "All", subset: str = "All"):
    try:
        return el_get_team_leaders(season=season, phase=phase, subset=subset)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"EuroLeague team-leaders failed: {e}")