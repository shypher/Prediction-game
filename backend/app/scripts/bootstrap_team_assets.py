from pathlib import Path
from ..core.database import SessionLocal 
from app.services.assets_sync import sync_assets_from_json

def main():
    base = Path(__file__).resolve().parents[1] / "services" / "assets"
    with SessionLocal() as db:
        sync_assets_from_json(db, base / "nba_teams.json")
        sync_assets_from_json(db, base / "euroleague_teams.json")

if __name__ == "__main__":
    main()