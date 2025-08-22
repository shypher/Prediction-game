# app/services/balldontlie.py
import os, datetime as dt, requests
from typing import Any, Dict, List, Optional

BASE = os.getenv("BALLDONTLIE_BASE", "https://api.balldontlie.io/v1")
API_KEY = os.getenv("BALLDONTLIE_API_KEY", "")
HEADERS = {"Authorization": API_KEY} if API_KEY else {}

def _get(path: str, params: Dict[str, Any]) -> Dict[str, Any]:
    r = requests.get(f"{BASE}{path}", params=params, headers=HEADERS, timeout=25)
    r.raise_for_status()
    return r.json()

def _to_utc_naive(dt_str: Optional[str]) -> Optional[dt.datetime]:
    if not dt_str:
        return None
    try:
        d = dt.datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None
    if d.tzinfo:
        d = d.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return d

def get_games_range(start: dt.date, end: dt.date, per_page: int = 100, max_pages: int = 3) -> List[Dict[str, Any]]:
    params = {"start_date": start.isoformat(), "end_date": end.isoformat(), "per_page": per_page}
    data = _get("/games", params)
    out = data.get("data", []) or []
    cursor = (data.get("meta") or {}).get("next_cursor")
    pages = 1
    while cursor and pages < max_pages:
        params["cursor"] = cursor
        data = _get("/games", params)
        out.extend(data.get("data", []) or [])
        cursor = (data.get("meta") or {}).get("next_cursor")
        pages += 1
    return out

def get_games_by_date(date: dt.date) -> List[Dict[str, Any]]:
    return get_games_range(date, date)

def map_game_to_row(g: Dict[str, Any]) -> Dict[str, Any]:
    when = _to_utc_naive(g.get("datetime") or g.get("date"))
    home = (g.get("home_team") or {}).get("full_name") or (g.get("home_team") or {}).get("name")
    away = (g.get("visitor_team") or {}).get("full_name") or (g.get("visitor_team") or {}).get("name")

    raw_status = g.get("status") or "scheduled"
    if isinstance(raw_status, str) and len(raw_status) >= 10 and raw_status[4] == "-":
        raw_status = "scheduled"

    return {
        "external_id": f"nba_{g.get('id')}",
        "home_team": home,
        "away_team": away,
        "match_date": when,     # UTC naive
        "home_score": g.get("home_team_score"),
        "away_score": g.get("visitor_team_score"),
        "status": raw_status,   # "Final", "In Progress", "Scheduled"
        "league_id": 0,
        "league_name": "NBA",
        "country": "USA",
        "timezone": "UTC",
        "source": "balldontlie",
        "season": g.get("season"),
    }
