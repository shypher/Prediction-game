from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import text
import datetime as dt
import os

from ..db.models import Match
from ..core.interfaces import IMatchService
from ..core.constants import AppConstants, LeagueConstants, LEAGUE_RESOLVER, ErrorMessages
from ..services import balldontlie, euroleague_open, thesportsdb
from ..db.db_upsert import bulk_upsert_by_external_id

class MatchService(IMatchService):
    def __init__(self, db: Session):
        self.db = db
        
    def get_match_by_id(self, match_id: int) -> Optional[Dict[str, Any]]:
        """Get match by ID"""
        match = self.db.get(Match, match_id)
        if not match:
            return None
        
        return {
            "id": match.id,
            "home_team": match.home_team,
            "away_team": match.away_team,
            "match_date": match.match_date,
            "home_score": match.home_score,
            "away_score": match.away_score,
            "league_name": match.league_name,
            "status": match.status
        }
    
    def _resolve_league(self, league: str) -> dict:
        """Resolve league configuration"""
        if league not in LEAGUE_RESOLVER:
            raise ValueError(f"{ErrorMessages.UNKNOWN_LEAGUE} '{league}'. Use one of: {', '.join(LEAGUE_RESOLVER.keys())}")
        return LEAGUE_RESOLVER[league]
    
    def _get_euroleague_season_code(self, date: dt.datetime) -> str:
        """Get EuroLeague season code"""
        return f"E{date.year if date.month >= 7 else date.year - 1}"
    
    def _upsert_match(self, row: dict) -> Match:
        """Upsert match data"""
        q = None
        if row.get("external_id"):
            q = self.db.query(Match).filter(Match.external_id == row["external_id"]).first()
        if not q:
            q = (self.db.query(Match)
                   .filter(Match.match_date == row.get("match_date"))
                   .filter(Match.home_team == row.get("home_team"))
                   .filter(Match.away_team == row.get("away_team"))
                   .first())
        if q:
            for k, v in row.items():
                setattr(q, k, v)
            return q
        m = Match(**row)
        self.db.add(m)
        return m
    
    def get_upcoming_matches(self, league: str, days: int = AppConstants.DEFAULT_DAYS_RANGE) -> List[Dict[str, Any]]:
        now = dt.datetime.utcnow()
        end = now + dt.timedelta(days=days)

        handler = self._handlers.get(league)
        if not handler:
            raise ValueError(f"{ErrorMessages.UNKNOWN_LEAGUE} '{league}'")

        rows = handler(now, end)

        for row in rows:
            self._upsert_match(row)
        self.db.commit()

        return rows
    
    def update_match_scores(self, match_id: int, home_score: int, away_score: int) -> bool:
        """Update match scores"""
        match = self.db.get(Match, match_id)
        if not match:
            return False
        
        match.home_score = home_score
        match.away_score = away_score
        match.status = "finished"
        match.last_update = dt.datetime.utcnow()
        
        self.db.commit()
        return True
    
    def is_match_locked(self, match_id: int) -> bool:
        """Check if match is locked for predictions"""
        match = self.db.get(Match, match_id)
        if not match or not match.match_date:
            return False
        
        now = dt.datetime.utcnow()
        lock_time = match.match_date - dt.timedelta(minutes=AppConstants.LOCK_MINUTES)
        return now >= lock_time
    
    def get_matches_by_league(self, league: str) -> List[Dict[str, Any]]:
        """Get matches by league using raw SQL for consistency"""
        rows = self.db.execute(text("""
            SELECT id, home_team, away_team, match_date, home_score, away_score, 
                   league_name, status, external_id
            FROM matches 
            WHERE league_name = :league
            ORDER BY match_date DESC
        """), {"league": league})
        
        return [dict(row) for row in rows]
    
    def get_finished_matches(self) -> List[Dict[str, Any]]:
        """Get finished matches using raw SQL for consistency"""
        rows = self.db.execute(text("""
            SELECT id, home_team, away_team, match_date, home_score, away_score, 
                   league_name, status
            FROM matches 
            WHERE status = 'finished' AND home_score IS NOT NULL AND away_score IS NOT NULL
            ORDER BY match_date DESC
        """))
        
        return [dict(row) for row in rows]
    
    
    def get_upcoming_matches_db(
        self,
        league: str,
        days: int = AppConstants.DEFAULT_DAYS_RANGE,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:

        now = dt.datetime.utcnow()
        end = now + dt.timedelta(days=days)
        cfg = self._resolve_league(league)
        league_name = cfg.get("name", league)

        q = (
            self.db.query(Match)
            .filter(Match.league_name == league_name)
            .filter(Match.match_date >= now, Match.match_date <= end)
            .order_by(Match.match_date.asc())
        )
        if limit:
            q = q.limit(limit)

        matches = q.all()
        out = []
        for m in matches:
            out.append({
                "id": m.id,
                "external_id": m.external_id,
                "league": m.league_name,
                "home": m.home_team,
                "away": m.away_team,
                "date": m.match_date,
                "status": m.status,
                "source": m.source,
                "season": m.season,
            })
        return out