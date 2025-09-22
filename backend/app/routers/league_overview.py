from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from ..core import database
from ..db.models import Team, Player, Match, GamePlayerStat
from sqlalchemy import func
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
router = APIRouter(prefix="/stats", tags=["stats"])

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
    return {"player_id": pid, "player": f"{(fn or '').strip()} {(ln or '').strip()}".strip(), "value": int(v or 0)}

@router.get("/league_overview")
def league_overview(
    league_id: int = Query(...),
    season: int = Query(...),
    include_empty: bool = Query(True),
    db: Session = Depends(get_db),
):
    teams_q = db.query(Team).filter(Team.league_id == league_id).order_by(Team.name).all()

    agg_q = (
        db.query(
            Player.team_id.label("team_id"),
            func.sum(GamePlayerStat.pts).label("total_pts"),
            func.sum(GamePlayerStat.ast).label("total_ast"),
            func.sum(GamePlayerStat.reb).label("total_reb"),
            func.count(func.distinct(Match.id)).label("games")
        )
        .join(GamePlayerStat, GamePlayerStat.player_id == Player.id)
        .join(Match, Match.id == GamePlayerStat.match_id)
        .filter(GamePlayerStat.league_id == league_id, Match.season == season)
        .group_by(Player.team_id)
        .all()
    )
    agg_map = {row.team_id: row for row in agg_q}

    out = []
    for t in teams_q:
        row = agg_map.get(t.id)
        if not row and not include_empty:
            continue
        games = int(getattr(row, "games", 0) or 0)
        pts = float(getattr(row, "total_pts", 0) or 0)
        ast = float(getattr(row, "total_ast", 0) or 0)
        reb = float(getattr(row, "total_reb", 0) or 0)
        ppg = pts / games if games else 0.0
        apg = ast / games if games else 0.0
        rpg = reb / games if games else 0.0
        leaders = {
            "pts": top_player(db, t.id, league_id, season, GamePlayerStat.pts) if games else None,
            "ast": top_player(db, t.id, league_id, season, GamePlayerStat.ast) if games else None,
            "reb": top_player(db, t.id, league_id, season, GamePlayerStat.reb) if games else None
        }
        out.append({
            "team_id": t.id,
            "name": t.name,
            "abbreviation": t.abbreviation,
            "logo_url": t.logo_url,
            "primary_color": t.primary_color,
            "secondary_color": t.secondary_color,
            "ppg": round(ppg, 2),
            "apg": round(apg, 2),
            "rpg": round(rpg, 2),
            "leaders": leaders
        })
    return {"league_id": league_id, "season": season, "teams": out}


STAT_MAP = {
    "pts": GamePlayerStat.pts,
    "ast": GamePlayerStat.ast,
    "reb": GamePlayerStat.reb,
    "st":  GamePlayerStat.stl,
    "blk": GamePlayerStat.blk,
    "3ptm": GamePlayerStat.fg3m,
    "to": GamePlayerStat.to,
    "pm": GamePlayerStat.to,
}
@router.get("/leaders/players")
def leaders_players(
    league_id: int = Query(...),
    season:   int = Query(...),
    team_id:  int = Query(...),
    stat:     str = Query(..., pattern="^(pts|ast|reb|st|blk|3ptm|to)$"),
    top:      int = 3,
    db: Session = Depends(get_db)
):
    col = STAT_MAP.get(stat)
    if not col:
        raise HTTPException(400, "unsupported stat")
    q = (
        db.query(
            Player.id.label("player_id"),
            (func.coalesce(Player.first_name, "") + " " + func.coalesce(Player.last_name, "")).label("player"),
            func.sum(col).label("val"),
        )
        .join(GamePlayerStat, GamePlayerStat.player_id == Player.id)
        .join(Match, Match.id == GamePlayerStat.match_id)
        .filter(Player.team_id == team_id,
                GamePlayerStat.league_id == league_id,
                Match.season == season)
        .group_by(Player.id, "player")
        .order_by(func.sum(col).desc())
        .limit(top)
    )
    rows = q.all()
    return {"team_id": team_id, "stat": stat, "leaders": [{"player_id": r.player_id, "player": r.player.strip(), "value": int(r.val or 0)} for r in rows]}



@router.get("/leaders/teams")
def leaders_teams(
    league_id: int = Query(...),
    season:   int = Query(...),
    stat:     str = Query(..., pattern="^(pts|ast|reb|st|blk|3ptm|ppg|apg|rpg)$"),
    top:      int = 10,
    per:      str = Query("game", pattern="^(game|total)$"),
    db: Session = Depends(get_db)
):
    base = (
        db.query(
            GamePlayerStat.league_id,
            Match.season,
            GamePlayerStat.match_id,
            Player.team_id,
            func.sum(GamePlayerStat.pts).label("PTS"),
            func.sum(GamePlayerStat.ast).label("AST"),
            func.sum(GamePlayerStat.reb).label("REB"),
            func.sum(GamePlayerStat.stl).label("ST"),
            func.sum(GamePlayerStat.blk).label("BLK"),
            func.sum(GamePlayerStat.fg3m).label("TPM"),
        )
        .join(Player, Player.id == GamePlayerStat.player_id)
        .join(Match, Match.id == GamePlayerStat.match_id)
        .filter(GamePlayerStat.league_id == league_id, Match.season == season)
        .group_by(GamePlayerStat.league_id, Match.season, GamePlayerStat.match_id, Player.team_id)
        .subquery()
    )
    q = (
        db.query(
            base.c.team_id,
            func.count(base.c.match_id.distinct()).label("GP"),
            func.sum(base.c.PTS).label("PTS"),
            func.sum(base.c.AST).label("AST"),
            func.sum(base.c.REB).label("REB"),
            func.sum(base.c.ST).label("ST"),
            func.sum(base.c.BLK).label("BLK"),
            func.sum(base.c.TPM).label("TPM"),
        )
        .group_by(base.c.team_id)
    )

    rows = q.all()
    def pick(row, key):
        val = getattr(row, key)
        if per == "game":
            gp = int(row.GP or 0) or 1
            return round(float(val or 0)/gp, 2)
        return int(val or 0)

    key = {
        "pts":"PTS","ppg":"PTS",
        "ast":"AST","apg":"AST",
        "reb":"REB","rpg":"REB",
        "st":"ST","blk":"BLK","3ptm":"TPM"
    }[stat]

    ranked = sorted(
        [{"team_id": r.team_id, "value": pick(r, key)} for r in rows],
        key=lambda x: x["value"], reverse=True
    )[:top]

    return {"stat": stat, "per": per, "leaders": ranked}