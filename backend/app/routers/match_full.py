from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from ..core import database
from ..db.models import Match, Team, Player,GameTeamStat, GamePlayerStat
from typing import Dict, Any, Tuple, List
import requests
from ..services.euroleague_open import  upsert_el_boxscore_to_db, _el_boxscore_from_db

router = APIRouter(prefix="/matches", tags=["matches"])
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
def _boxscore_from_db(db: Session, match_id: int, league_id: int):

    rows = (
        db.query(
            GamePlayerStat.player_id,
            Player.first_name, Player.last_name,
            Player.team_id,
            GamePlayerStat.minutes,
            GamePlayerStat.pts, GamePlayerStat.ast, GamePlayerStat.reb,
            GamePlayerStat.stl, GamePlayerStat.blk, GamePlayerStat.fg3m,
            GamePlayerStat.league_id,
            GamePlayerStat.match_id,
        )
        .join(Player, Player.id == GamePlayerStat.player_id)
        .filter(GamePlayerStat.match_id == match_id, GamePlayerStat.league_id == league_id)
        .all()
    )

    has_plus = hasattr(GamePlayerStat, "plus_minus")
    if has_plus:
        rows = (
            db.query(
                GamePlayerStat.player_id,
                Player.first_name, Player.last_name,
                Player.team_id,
                GamePlayerStat.minutes,
                GamePlayerStat.pts, GamePlayerStat.ast, GamePlayerStat.reb,
                GamePlayerStat.stl, GamePlayerStat.blk, GamePlayerStat.fg3m,
                GamePlayerStat.plus_minus,
            )
            .join(Player, Player.id == GamePlayerStat.player_id)
            .filter(GamePlayerStat.match_id == match_id, GamePlayerStat.league_id == league_id)
            .all()
        )

    players = []
    team_abbr = {t.id: t.abbreviation for t in db.query(Team).filter(Team.league_id == league_id).all()}
    for r in rows:
        d = {
            "player_id": r.player_id,
            "first_name": r.first_name, "last_name": r.last_name,
            "team_code": team_abbr.get(r.team_id),
            "minutes": getattr(r, "minutes", None),
            "pts": getattr(r, "pts", None),
            "ast": getattr(r, "ast", None),
            "reb": getattr(r, "reb", None),
            "stl": getattr(r, "stl", None),
            "blk": getattr(r, "blk", None),
            "fg3m": getattr(r, "fg3m", None),
        }
        if has_plus:
            d["plus_minus"] = getattr(r, "plus_minus", None)
        players.append(d)
    return {"players": players}
def _season_to_date_team_summary(db: Session, team_id: int, league_id: int, season: int, cutoff_dt):

    q = (
        db.query(
            func.sum(GamePlayerStat.pts).label("pts"),
            func.sum(GamePlayerStat.ast).label("ast"),
            func.sum(GamePlayerStat.reb).label("reb"),
            func.count(func.distinct(Match.id)).label("games"),
        )
        .join(Player, Player.id == GamePlayerStat.player_id)
        .join(Match, Match.id == GamePlayerStat.match_id)
        .filter(
            Player.team_id == team_id,
            GamePlayerStat.league_id == league_id,
            Match.season == season,
            Match.match_date < cutoff_dt, 
        )
    ).first()

    games = int((q.games or 0))
    def per_game(x): return round(float(x or 0) / games, 2) if games else 0.0
    return {"ppg": per_game(q.pts), "apg": per_game(q.ast), "rpg": per_game(q.reb), "games": games}
def _team_assets(db: Session, league_id: int, team_name: str):
    t = db.query(Team).filter(Team.league_id == league_id, Team.name == team_name).first()
    if not t:
        return None
    return {
        "id": t.id,
        "name": t.name,
        "abbreviation": t.abbreviation,
        "logo_url": t.logo_url,
        "primary_color": t.primary_color,
        "secondary_color": t.secondary_color
    }






def _team_for_against(db, match_id, team_id):
    from app.db.models import GameTeamStat
    me = db.query(GameTeamStat).filter_by(match_id=match_id, team_id=team_id).first()
    if not me: return None
    opp = db.query(GameTeamStat).filter_by(match_id=match_id, team_id=me.opponent_team_id).first()
    def pack(x):
        if not x: return None
        def pct(m,a): return round((float(m or 0)/(a or 1)), 3) if a else 0.0
        return {
            "PTS": x.pts, "AST": x.ast, "REB": x.reb, "ST": x.stl, "BLK": x.blk, "TO": x.tov,
            "FG%": pct(x.fgm, x.fga), "3P%": pct(x.fg3m, x.fg3a), "FT%": pct(x.ftm, x.fta),
            "3PTM": x.fg3m,
        }
    return {"for": pack(me), "against": pack(opp)}
def _leaders_to_date(db: Session, team_id: int, league_id: int, season: int, cutoff_dt):

    def top(col):
        row = (
            db.query(
                Player.id.label("player_id"),
                (func.coalesce(Player.first_name, "") + " " + func.coalesce(Player.last_name, "")).label("player"),
                func.sum(col).label("v"),
            )
            .join(GamePlayerStat, GamePlayerStat.player_id == Player.id)
            .join(Match, Match.id == GamePlayerStat.match_id)
            .filter(
                Player.team_id == team_id,
                GamePlayerStat.league_id == league_id,
                Match.season == season,
                Match.match_date < cutoff_dt,
            )
            .group_by(Player.id, "player")
            .order_by(func.sum(col).desc())
            .limit(1)
        ).first()
        if not row:
            return None
        return {"player_id": row.player_id, "player": row.player.strip(), "value": int(row.v or 0)}

    return {
        "pts": top(GamePlayerStat.pts),
        "ast": top(GamePlayerStat.ast),
        "reb": top(GamePlayerStat.reb),
    }
@router.get("/{match_id}/full")
def match_full(match_id: int = Path(..., ge=1), db: Session = Depends(get_db)):

    m = db.query(Match).filter(Match.id == match_id).first()
    if not m:
        raise HTTPException(404, "match not found")

    league_id = m.league_id
    season = m.season
    home_assets = _team_assets(db, league_id, m.home_team) if m.home_team else None
    away_assets = _team_assets(db, league_id, m.away_team) if m.away_team else None
    pregame = {"home": {"summary": {"ppg": 0.0, "apg": 0.0, "rpg": 0.0, "games": 0}, "leaders": {"pts": None, "ast": None, "reb": None}},
               "away": {"summary": {"ppg": 0.0, "apg": 0.0, "rpg": 0.0, "games": 0}, "leaders": {"pts": None, "ast": None, "reb": None}}}
    live_box = {"players": []}
    team_game = None

    started = (m.status and m.status.lower() not in ("scheduled", "postponed")) or \
              db.query(GameTeamStat.id).filter(GameTeamStat.match_id == m.id).first() is not None or \
              db.query(GamePlayerStat.id).filter(GamePlayerStat.match_id == m.id).first() is not None

    if not started:
        if league_id == 0:
            pregame = pregame
        else:
            if home_assets:
                pregame["home"]["summary"] = _season_to_date_team_summary(db, home_assets["id"], league_id, season, m.match_date)
                pregame["home"]["leaders"] = _leaders_to_date(db, home_assets["id"], league_id, season, m.match_date) if pregame["home"]["summary"]["games"] else {"pts": None, "ast": None, "reb": None}
            if away_assets:
                pregame["away"]["summary"] = _season_to_date_team_summary(db, away_assets["id"], league_id, season, m.match_date)
                pregame["away"]["leaders"] = _leaders_to_date(db, away_assets["id"], league_id, season, m.match_date) if pregame["away"]["summary"]["games"] else {"pts": None, "ast": None, "reb": None}
    else:
        live_box = _boxscore_from_db(db, m.id, league_id)
        if home_assets and away_assets:
            home_fg = _team_for_against(db, m.id, home_assets["id"])
            away_fg = _team_for_against(db, m.id, away_assets["id"])
            if home_fg and away_fg:
                team_game = {"home": home_fg, "away": away_fg}

    return {
        "match": {
            "id": m.id,
            "home_team": {
                "name": m.home_team,
                "logo_url": home_assets["logo_url"] if home_assets else None,
                "primary_color": home_assets["primary_color"] if home_assets else None,
                "secondary_color": home_assets["secondary_color"] if home_assets else None
            },
            "away_team": {
                "name": m.away_team,
                "logo_url": away_assets["logo_url"] if away_assets else None,
                "primary_color": away_assets["primary_color"] if away_assets else None,
                "secondary_color": away_assets["secondary_color"] if away_assets else None
            },
            "home_score": m.home_score,
            "away_score": m.away_score,
            "status": m.status,
            "season": m.season,
            "league_id": m.league_id,
            "match_date": m.match_date.isoformat() if m.match_date else None
        },
        "pregame": pregame if not started else None,
        "team_game": team_game if started else None,
        "boxscore": live_box if started else {"players": []},
        "assets": {
            "home": home_assets,
            "away": away_assets
        }
    }