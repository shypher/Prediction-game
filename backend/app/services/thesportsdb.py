import os, datetime as dt, requests
from typing import Any, Dict, List, Optional
from urllib.parse import quote

API_KEY = os.getenv("THESPORTSDB_API_KEY", "123")
BASE = os.getenv("THESPORTSDB_BASE", "https://www.thesportsdb.com/api/v1/json")

LEAGUE_IDS = {
    "EuroLeague": 4546,             # https://www.thesportsdb.com/league/4546-euroleague-basketball
    "Israel Super League": 4474,    # Israeli BSL
    "EuroBasket": 4831,             # https://www.thesportsdb.com/league/4831-fiba-eurobasket
}

def _get(path: str, params: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{BASE}/{API_KEY}/{path}"
    r = requests.get(url, params=params, timeout=25)
    r.raise_for_status()
    return r.json()

def next_events_by_league(league_name: str, limit: int = 20) -> List[Dict[str, Any]]:
    lid = LEAGUE_IDS.get(league_name)
    if not lid:
        return []
    data = _get("eventsnextleague.php", {"id": lid})
    events = data.get("events") or []
    return events[:limit]

def events_season_by_league(league_name: str, season: str) -> List[Dict[str, Any]]:
    lid = LEAGUE_IDS.get(league_name)
    if not lid:
        return []
    data = _get("eventsseason.php", {"id": lid, "s": season})
    return data.get("events") or []

def tsdb_season_for_euroleague(d: dt.date) -> str:
    y = d.year if d.month >= 7 else d.year - 1
    return f"{y}-{y+1}"

def tsdb_season_for_israel(d: dt.date) -> str:
    y = d.year if d.month >= 7 else d.year - 1
    return f"{y}-{y+1}"

def tsdb_season_for_eurobasket(_: dt.date) -> str:
    return "2025"

def _to_utc_naive(ts: Optional[str], date_local: Optional[str], time_local: Optional[str]) -> Optional[dt.datetime]:
    if ts:
        try:
            d = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return d.astimezone(dt.timezone.utc).replace(tzinfo=None)
        except Exception:
            pass
    if date_local:
        try:
            t = time_local or "00:00:00"
            return dt.datetime.fromisoformat(f"{date_local}T{t}")
        except Exception:
            return None
    return None


EUROBASKET_UTC_OFFSET = int(os.getenv("EUROBASKET_UTC_OFFSET", "+3")) 
def map_event_to_row(ev: Dict[str, Any], league_name: str) -> Dict[str, Any]:
    when = _to_utc_naive(ev.get("strTimestamp"), ev.get("dateEvent"), ev.get("strTime"))+dt.timedelta(hours=EUROBASKET_UTC_OFFSET)
    ext = ev.get("idEvent")
    external_id = f"tsdb_{ext}" if ext else None
    status_raw = (ev.get("strStatus") or "").strip().lower()
    if status_raw in ["ft", "full time", "finished", "match finished"]:
        status = "finished"
    elif status_raw in ["in progress", "live", "playing"]:
        status = "in_progress"
    else:
        status = "scheduled"
    home_score = None
    away_score = None
    try:
        if ev.get("intHomeScore") is not None:
            home_score = int(ev.get("intHomeScore"))
        if ev.get("intAwayScore") is not None:
            away_score = int(ev.get("intAwayScore"))
    except (ValueError, TypeError):
        pass
    return {
        "external_id": external_id,
        "home_team": ev.get("strHomeTeam"),
        "away_team": ev.get("strAwayTeam"),
        "match_date": when,
        "home_score": home_score,
        "away_score": away_score,
        "status": status,
        "league_id": 0,
        "league_name": league_name,
        "country": ev.get("strCountry"),
        "timezone": "UTC",
        "source": "thesportsdb",
        "season": ev.get("strSeason"),
    }

def events_day(when: dt.date, league_name: str | None = None):

    d = when.isoformat()
    url = f"{BASE}/{API_KEY}/eventsday.php?d={d}"
    if league_name:
        url += f"&l={quote(league_name)}"
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    data = r.json()
    return data.get("events") or []