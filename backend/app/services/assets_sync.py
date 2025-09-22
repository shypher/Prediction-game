import json
from pathlib import Path
from sqlalchemy.orm import Session
from app.db.models import Team

def _load(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def sync_assets_from_json(db: Session, json_path: Path):
    payload = _load(json_path)
    league_id = payload.get("league_id")
    for t in payload.get("teams", []):
        name = t.get("name")
        q = db.query(Team).filter(Team.league_id==league_id, Team.name==name).first()
        if not q:
            q = Team(league_id=league_id, name=name)
        q.abbreviation = t.get("abbreviation")
        q.logo_url = t.get("logo_path")
        q.primary_color = t.get("primary_color") or None
        q.secondary_color = t.get("secondary_color") or None
        db.add(q)
    db.commit()