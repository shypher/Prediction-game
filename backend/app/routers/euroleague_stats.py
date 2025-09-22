from fastapi import APIRouter, HTTPException, Depends, Path
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from ..core import database
from ..db.models import Match

router = APIRouter(prefix="/euroleague", tags=["euroleague"])
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/boxscore/{match_id}")
def euroleague_boxscore_raw(match_id: int, db: Session = Depends(get_db)):
    m = db.query(Match).filter(Match.id==match_id, Match.league_id==120).first()
    if not m or not m.external_id:
        raise HTTPException(404, "match not found or external_id missing")
    seasoncode, gamecode = parse_el_external_id(m.external_id)
    data = get_boxscore(seasoncode, gamecode)
    return data

@router.get("/boxscore_simple/{match_id}")
def euroleague_boxscore_simple(match_id: int, db: Session = Depends(get_db)):
    m = db.query(Match).filter(Match.id==match_id, Match.league_id==120).first()
    if not m or not m.external_id:
        raise HTTPException(404, "match not found or external_id missing")
    seasoncode, gamecode = parse_el_external_id(m.external_id)
    data = get_boxscore(seasoncode, gamecode)
    players = []
    for side in ["HomeTeam","AwayTeam","homeTeam","awayTeam","home","away"]:
        team = data.get(side) if isinstance(data, dict) else None
        if team and isinstance(team, dict):
            plist = team.get("Players") or team.get("players") or []
            tname = team.get("TeamName") or team.get("teamName") or team.get("Name") or team.get("name")
            for s in plist:
                first = s.get("FirstName") or s.get("firstName") or s.get("First_Name") or ""
                last = s.get("LastName") or s.get("lastName") or s.get("Surname") or ""
                pts = s.get("Points") or s.get("PTS") or s.get("points") or 0
                ast = s.get("Assists") or s.get("AST") or s.get("assists") or 0
                reb = s.get("ReboundsTotal") or s.get("REB") or (s.get("DefRebounds",0)+s.get("OffRebounds",0))
                minutes = s.get("Minutes") or s.get("MIN") or s.get("minutes")
                players.append({
                    "team": tname,
                    "player": f"{first} {last}".strip(),
                    "pts": pts,
                    "ast": ast,
                    "reb": reb,
                    "minutes": minutes
                })
    return {"match_id": match_id, "players": players}
