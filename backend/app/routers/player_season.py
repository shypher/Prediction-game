from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..core import database
from ..db.models import Player, GamePlayerStat, Team

router = APIRouter(prefix="/stats", tags=["stats"])

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/player-season")
def player_season(league_id: int = Query(...), season: int = Query(...),
                  team_id: int | None = None,
                  per: str = Query("game", pattern="^(game|total)$"),
                  db: Session = Depends(get_db)):
    q = (db.query(
            Player.id.label("player_id"),
            (Player.first_name + ' ' + Player.last_name).label("player"),
            func.sum(GamePlayerStat.pts).label("PTS"),
            func.sum(GamePlayerStat.ast).label("AST"),
            func.sum(GamePlayerStat.reb).label("REB"),
            func.sum(GamePlayerStat.stl).label("ST"),
            func.sum(GamePlayerStat.blk).label("BLK"),
            func.sum(GamePlayerStat.tov).label("TO"),
            func.sum(GamePlayerStat.fgm).label("FGM"),
            func.sum(GamePlayerStat.fga).label("FGA"),
            func.sum(GamePlayerStat.fg3m).label("3PM"),
            func.sum(GamePlayerStat.fg3a).label("3PA"),
            func.sum(GamePlayerStat.ftm).label("FTM"),
            func.sum(GamePlayerStat.fta).label("FTA"),
            func.sum(GamePlayerStat.plus_minus).label("Plusminus"),
            func.count(GamePlayerStat.match_id.distinct()).label("GP"),
        )
        .join(Team, Player.team_id == Team.id, isouter=True)
        .join(GamePlayerStat, GamePlayerStat.player_id == Player.id)
        .filter(GamePlayerStat.league_id == league_id)
    )
    if team_id:
        q = q.filter(Player.team_id == team_id)

    q = q.group_by(Player.id)
    rows = q.all()

    out = []
    for r in rows:
        gp = int(r.GP or 0) or 1
        def per_game(x): return round(float(x or 0)/gp, 2)
        FGp  = round(float(r.FGM or 0)/float(r.FGA or 1), 3)
        FTp  = round(float(r.FTM or 0)/float(r.FTA or 1), 3)
        TPp  = round(float(r._3PM or 0)/float(r._3PA or 1), 3) if hasattr(r,'_3PM') else round(float(r[10] or 0)/float(r[11] or 1),3)
        item = {
            "player_id": r.player_id,
            "player": r.player,
            "FG%": FGp, "FT%": FTp, "3P%": TPp,
            "3PTM": int(r[10] or 0),  # 3PM
            "AST": per_game(r.AST) if per=="game" else int(r.AST or 0),
            "REB": per_game(r.REB) if per=="game" else int(r.REB or 0),
            "PTS": per_game(r.PTS) if per=="game" else int(r.PTS or 0),
            "ST":  per_game(r.ST)  if per=="game" else int(r.ST or 0),
            "BLK": per_game(r.BLK) if per=="game" else int(r.BLK or 0),
            "TO":  per_game(r.TO)  if per=="game" else int(r.TO or 0),
            "GP":  gp
        }
        out.append(item)
    return {"league_id": league_id, "season": season, "players": out}
