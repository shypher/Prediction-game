
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from ..core import database
from ..db.models import Team
from urllib.parse import urljoin

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

router = APIRouter(prefix="/teams", tags=["teams"])


def absolutize_logo(logo_url: str | None, base_url) -> str | None:
  if not logo_url:
      return None
  u = logo_url.strip()
  if u.startswith("http://") or u.startswith("https://"):
      return u
  if u.startswith("/"):
      u = u[1:]
  return urljoin(str(base_url), u)

@router.get("")
def list_teams(league_id: int = Query(...), request: Request = None, db: Session = Depends(get_db)):
    rows = db.query(Team).filter(Team.league_id == league_id).order_by(Team.name).all()
    out = []
    for r in rows:
        out.append({
            "id": r.id,
            "name": r.name,
            "abbreviation": r.abbreviation,
            "logo_url": absolutize_logo(r.logo_url, request.base_url),
            "primary_color": r.primary_color,
            "secondary_color": r.secondary_color
        })
    return out