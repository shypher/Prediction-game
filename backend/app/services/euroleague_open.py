import os
import datetime as dt
from typing import Any, Dict, List, Optional
import requests
import xml.etree.ElementTree as ET

BASE = os.getenv("EUROLEAGUE_OPEN_BASE", "https://api-live.euroleague.net")
HEADERS = {
    "User-Agent": os.getenv("EUROLEAGUE_UA", "PredictionGame/1.0 (+fastapi)"),
    "Accept": "application/xml,text/xml,*/*",
    "Connection": "close",
}
EUROLEAGUE_UTC_OFFSET = int(os.getenv("EUROLEAGUE_UTC_OFFSET", "1")) 


def _get_xml(path: str, params: Dict[str, Any]) -> ET.Element:
    url = f"{BASE}{path}"
    r = requests.get(url, params=params, headers=HEADERS, timeout=25)
    r.raise_for_status()
    return ET.fromstring(r.text)

def _parse_date_time(date_str: Optional[str], time_str: Optional[str]) -> Optional[dt.datetime]:

    if not date_str:
        return None
    try:
        d = dt.datetime.strptime(date_str.strip(), "%b %d, %Y")
    except Exception:
        try:
            d = dt.datetime.strptime(date_str.strip(), "%B %d, %Y")
        except Exception:
            return None
    if time_str:
        try:
            t = dt.datetime.strptime(time_str.strip(), "%H:%M").time()
            return dt.datetime.combine(d.date(), t)
        except Exception:
            pass
    return dt.datetime.combine(d.date(), dt.time(0, 0))

def _text(node: Optional[ET.Element]) -> Optional[str]:
    return node.text.strip() if (node is not None and node.text) else None

def _item_to_row(item: ET.Element) -> Dict[str, Any]:
    date_str   = _text(item.find("date"))
    time_str   = _text(item.find("startime"))
    when       = _parse_date_time(date_str, time_str)
    when = when + dt.timedelta(hours=EUROLEAGUE_UTC_OFFSET)
    home_team  = _text(item.find("hometeam"))
    away_team  = _text(item.find("awayteam"))
    gamecode   = _text(item.find("gamecode"))  
    played     = (_text(item.find("played")) or "").lower() == "true"

    external_id = f"el_{gamecode}" if gamecode else None

    status = "finished" if played else "scheduled"

    season = None
    if gamecode and len(gamecode) >= 6 and gamecode[1:5].isdigit():
        season = int(gamecode[1:5])

    return {
        "external_id": external_id,
        "home_team": home_team,
        "away_team": away_team,
        "match_date": when,            
        "home_score": None,
        "away_score": None,
        "status": status,
        "league_id": 120,
        "league_name": "EuroLeague",
        "country": "International",
        "timezone": "UTC",
        "source": "euroleague_open_xml",
        "season": season,
    }

def get_schedule(season_code: Optional[str] = None) -> List[Dict[str, Any]]:

    params: Dict[str, Any] = {}
    if season_code:
        params["seasoncode"] = season_code
    root = _get_xml("/v1/schedules", params)
    items = root.findall(".//item")
    return [_item_to_row(it) for it in items]

def get_games_range(start: dt.date, end: dt.date, season_code: Optional[str] = None) -> List[Dict[str, Any]]:
    rows = get_schedule(season_code=season_code)
    if not rows:
        return []
    sdt = dt.datetime.combine(start, dt.time.min)
    edt = dt.datetime.combine(end, dt.time.max)
    return [r for r in rows if r.get("match_date") and sdt <= r["match_date"] <= edt]

