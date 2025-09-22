from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from ..core import database
from ..db.models  import Team, Player, Match, GamePlayerStat, GameTeamStat
from fastapi import HTTPException


router = APIRouter(prefix="/stats", tags=["stats"])



def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def top_player(db: Session, team_id: int, league_id: int, season: int, col):
    q = (
        db.query(
            Player.id,
            Player.first_name,
            Player.last_name,
            func.sum(col).label("v")
        )
        .join(GamePlayerStat, GamePlayerStat.player_id == Player.id)
        .join(Match, Match.id == GamePlayerStat.match_id)
        .filter(
            Player.team_id == team_id,
            GamePlayerStat.league_id == league_id,
            Match.season == season
        )
        .group_by(Player.id)
        .order_by(func.sum(col).desc())
        .limit(1)
    ).first()
    if not q:
        return None
    pid, fn, ln, v = q
    return {"player_id": pid, "player": f"{fn or ''} {ln or ''}".strip(), "value": int(v or 0)}

@router.get("/team-season")
def team_season_summary(league_id: int = Query(...), season: int = Query(...), db: Session = Depends(get_db)):
    agg = (
        db.query(
            Team.id.label("team_id"),
            Team.name.label("team"),
            func.sum(GamePlayerStat.pts).label("total_pts"),
            func.sum(GamePlayerStat.ast).label("total_ast"),
            func.sum(GamePlayerStat.reb).label("total_reb"),
            func.count(distinct(Match.id)).label("games")
        )
        .join(Player, Player.team_id == Team.id)
        .join(GamePlayerStat, GamePlayerStat.player_id == Player.id)
        .join(Match, Match.id == GamePlayerStat.match_id)
        .filter(GamePlayerStat.league_id == league_id, Match.season == season)
        .group_by(Team.id, Team.name)
        .all()
    )

    out = []
    for row in agg:
        games = int(row.games or 0)
        ppg = float(row.total_pts or 0) / games if games else 0.0
        apg = float(row.total_ast or 0) / games if games else 0.0
        rpg = float(row.total_reb or 0) / games if games else 0.0
        leaders = {
            "pts": top_player(db, row.team_id, league_id, season, GamePlayerStat.pts),
            "ast": top_player(db, row.team_id, league_id, season, GamePlayerStat.ast),
            "reb": top_player(db, row.team_id, league_id, season, GamePlayerStat.reb)
        }
        out.append({
            "team_id": row.team_id,
            "team": row.team,
            "ppg": round(ppg, 2),
            "apg": round(apg, 2),
            "rpg": round(rpg, 2),
            "leaders": leaders
        })
    return {"league_id": league_id, "season": season, "teams": out}


@router.get("/team-game")
def team_game_stats(match_id: int, team_id: int, db: Session = Depends(get_db)):
    me = db.query(GameTeamStat).filter_by(match_id=match_id, team_id=team_id).first()
    opp = db.query(GameTeamStat).filter_by(match_id=match_id, team_id=me.opponent_team_id).first()
    def pack(x):
        FGp = round((x.fgm or 0)/float(x.fga or 1), 3)
        TPp = round((x.fg3m or 0)/float(x.fg3a or 1), 3)
        FTp = round((x.ftm or 0)/float(x.fta or 1), 3)
        return {
            "PTS": x.pts, "AST": x.ast, "REB": x.reb, "ST": x.stl, "BLK": x.blk, "TO": x.tov,
            "FG%": FGp, "3P%": TPp, "FT%": FTp, "3PTM": x.fg3m
        }
    return {"for": pack(me), "against": pack(opp)}


VALID_PLAYER_METRICS = {
    "pts": ("pts", GamePlayerStat.pts),
    "ast": ("ast", GamePlayerStat.ast),
    "reb": ("reb", GamePlayerStat.reb),
    "stl": ("stl", GamePlayerStat.stl),
    "blk": ("blk", GamePlayerStat.blk),
    "fg3m": ("fg3m", GamePlayerStat.fg3m),
}
@router.get("/top-players")
def top_players(
    league_id: int = Query(...),
    season: int = Query(...),
    metric: str = Query(..., description="one of: pts, ast, reb, stl, blk, fg3m"),
    limit: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
):
    if metric not in VALID_PLAYER_METRICS:
        raise HTTPException(400, f"invalid metric: {metric}")
    key, col = VALID_PLAYER_METRICS[metric]

    q = (
        db.query(
            Player.id.label("player_id"),
            Player.first_name,
            Player.last_name,
            Team.id.label("team_id"),
            Team.name.label("team"),
            func.sum(col).label("v"),
        )
        .join(GamePlayerStat, GamePlayerStat.player_id == Player.id)
        .join(Match, Match.id == GamePlayerStat.match_id)
        .outerjoin(Team, Team.id == Player.team_id)
        .filter(GamePlayerStat.league_id == league_id, Match.season == season)
        .group_by(Player.id, Team.id, Team.name, Player.first_name, Player.last_name)
        .order_by(func.sum(col).desc())
        .limit(limit)
    ).all()

    out = []
    for row in q:
        out.append({
            "player_id": row.player_id,
            "player": f"{row.first_name or ''} {row.last_name or ''}".strip(),
            "team_id": row.team_id,
            "team": row.team,
            key: int(row.v or 0),
        })
    return {"league_id": league_id, "season": season, "metric": metric, "players": out}


@router.get("/top-teams")
def top_teams(
    league_id: int = Query(...),
    season: int = Query(...),
    metric: str = Query(..., description="one of: pts, ast, reb, stl, blk, fg3m"),
    limit: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
):
    if metric not in VALID_PLAYER_METRICS:
        raise HTTPException(400, f"invalid metric: {metric}")
    key, col = VALID_PLAYER_METRICS[metric]

    q = (
        db.query(
            Team.id.label("team_id"),
            Team.name.label("team"),
            func.sum(col).label("v"),
        )
        .join(Player, Player.team_id == Team.id)
        .join(GamePlayerStat, GamePlayerStat.player_id == Player.id)
        .join(Match, Match.id == GamePlayerStat.match_id)
        .filter(GamePlayerStat.league_id == league_id, Match.season == season)
        .group_by(Team.id, Team.name)
        .order_by(func.sum(col).desc())
        .limit(limit)
    ).all()

    out = []
    for row in q:
        out.append({
            "team_id": row.team_id,
            "team": row.team,
            key: int(row.v or 0),
        })
    return {"league_id": league_id, "season": season, "metric": metric, "teams": out}