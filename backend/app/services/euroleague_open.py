import os
import datetime as dt
from typing import Any, Dict, List, Optional
import requests
import xml.etree.ElementTree as ET
from app.db.models import Player, Team, GamePlayerStat, GameTeamStat, Match
from sqlalchemy.orm import Session
from sqlalchemy import func

BASE = os.getenv("EUROLEAGUE_OPEN_BASE", "https://api-live.euroleague.net")
HEADERS = {
    "User-Agent": os.getenv("EUROLEAGUE_UA", "PredictionGame/1.0 (+fastapi)"),
    "Accept": "application/xml,text/xml,*/*",
    "Connection": "close",
}
EUROLEAGUE_UTC_OFFSET = int(os.getenv("EUROLEAGUE_UTC_OFFSET", "1")) 

EL_TO_GPS = {
  "Points": ("pts", int),
  "Assistances": ("ast", int),
  "TotalRebounds": ("reb", int),
  "Steals": ("stl", int),
  "BlocksFavour": ("blk", int),
  "FieldGoalsMade3": ("fg3m", int),
  "Minutes": ("minutes", str),
  "Plusminus": ("plus_minus", int),
  "FieldGoalsMade2": ("fgm",int),
  "FieldGoalsAttempted2":("fga",int),
  "FieldGoalsAttempted3":("fga3",int),
  "Turnovers": ("to",int),
  "FreeThrowsMade": ("ftm",int),
  "FreeThrowsAttempted": ("fta",int)
}
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

def fetchStandings(season_code: Optional[str] = None) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {}
    if season_code:
        params["seasoncode"] = season_code
    timeout_sec = 25
    resp = requests.get("https://api-live.euroleague.net/v1/standings", timeout=timeout_sec)
    root =ET.fromstring(resp.content)
    team_el = root.findall(".//item")
    rows: list[dict] = []    
    for team_el in root.findall(".//team"):
        team_name = team_el.find("name")
        wins_el = team_el.find("wins")
        loss_el = team_el.find("losses")
        rank_el = team_el.find("ranking")
        pf_el = team_el.find("ptsfavour")
        pa_el = team_el.find("ptsagainst")
        name = (team_name.text if team_name is not None else "").strip()
        try:
            w  = int(wins_el.text) if wins_el is not None and wins_el.text else 0
            l  = int(loss_el.text) if loss_el is not None and loss_el.text else 0
            pf = int(pf_el.text)   if pf_el is not None and pf_el.text else 0
            pa = int(pa_el.text)   if pa_el is not None and pa_el.text else 0
            rank = int(rank_el.text) if rank_el is not None and rank_el.text else 0
        except ValueError:
            w = l = pf = pa = 0
        rows.append({"team": name, "wins": w, "losses": l, "pf": pf, "pa": pa, "diff": pf - pa, "rank": rank})
    return rows
  

def _get_json(url: str, params: Dict[str, Any], timeout_sec: int = 12) -> Dict[str, Any]:
    r = requests.get(url, params=params, timeout=timeout_sec)
    r.raise_for_status()
    return r.json()


def _get_num(row: Dict[str, Any], *keys: str) -> float:
    for k in keys:
        if k in row and row[k] is not None:
            try:
                return float(row[k])
            except Exception:
                pass
    return 0.0


def get_team_stats(team_code: str, season: int, phase: str = "All") -> Dict[str, Any]:

    url = f"{BASE}/v1/teamstats"
    params = {"seasoncode": f"E{season}", "teamcode": team_code, "phasetype": phase}
    data = _get_json(url, params)

    row = data.get("TeamStats") if isinstance(data, dict) else None
    if isinstance(row, list) and row:
        row = row[0]
    if not row or not isinstance(row, dict):
        row = data if isinstance(data, dict) else {}

    two_m = _get_num(row, "2PM", "TwoPointsMade", "twoPointsMade")
    two_a = _get_num(row, "2PA", "TwoPointsAttempted", "twoPointsAttempted")
    tre_m = _get_num(row, "3PM", "ThreePointsMade", "threePointsMade")
    tre_a = _get_num(row, "3PA", "ThreePointsAttempted", "threePointsAttempted")

    fg_pct = round(100.0 * (two_m + tre_m) / max(1.0, (two_a + tre_a)), 1)

    out = {
        "team_code": team_code,
        "season": season,
        "phase": phase,
        "fg_pct": fg_pct,
        "ft_pct": _get_num(row, "FT%", "FTPerc", "freeThrowsPercentage"),
        "three_pm": _get_num(row, "3PM", "ThreePointsMade", "threePointsMade"),
        "ast": _get_num(row, "AST", "Assists", "assists"),
        "reb": _get_num(row, "TREB", "ReboundsTotal", "totalRebounds"),
        "stl": _get_num(row, "STL", "Steals", "steals"),
        "blk": _get_num(row, "BLK", "Blocks", "blocks", "BlocksFavour"),
        "to":  _get_num(row, "TO", "Turnovers", "turnovers"),
        "pts_for": _get_num(row, "PTS", "Points", "points"),
    }
    return out

def get_team_leaders(season: int, phase: str = "All", subset: str = "All") -> Dict[str, Any]:

    url = f"{BASE}/v1/teamlead"
    params = {"seasoncode": f"E{season}", "phasetype": phase, "subset": subset}
    data = _get_json(url, params)

    acc = data.get("TeamAccumulated") if isinstance(data, dict) else None
    avg = data.get("TeamAveragePerGame") if isinstance(data, dict) else None
    if acc is None:
        acc = data.get("accumulated") if isinstance(data, dict) else []
    if avg is None:
        avg = data.get("per_game") if isinstance(data, dict) else []

    if not isinstance(acc, list): acc = []
    if not isinstance(avg, list): avg = []

    return {
        "season": season,
        "phase": phase,
        "accumulated": acc,
        "per_game": avg,
    }
    
BASE_LIVE = "https://live.euroleague.net/api"

def fetch_boxscore(gamecode: int, seasoncode: str = "E2025"):
    url = f"{BASE_LIVE}/Boxscore?gamecode={gamecode}&seasoncode={seasoncode}"
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    return r.json()

def _resolve_team_id(db: Session, team_code: str, league_id: int) -> Optional[int]:
    team = db.query(Team).filter_by(external_id=team_code, league_id=league_id).first()
    return team.id if team else None

def _resolve_opponent(db: Session, match_id: int, team_id: int) -> Optional[int]:
    match = db.query(Match).filter_by(id=match_id).first()
    if not match:
        return None
    if match.home_team_id == team_id:
        return match.away_team_id
    elif match.away_team_id == team_id:
        return match.home_team_id
    return None

def upsert_boxscore(db: Session, match_id: int, league_id: int, box):
    team_totals = {}
    for t in box["Stats"]["Teams"]:
        team_id = _resolve_team_id(db, t["TeamCode"], league_id)
        opp_id  = _resolve_opponent(db, match_id, team_id)
        gts = GameTeamStat(
            match_id=match_id, league_id=league_id,
            team_id=team_id, opponent_team_id=opp_id,
            pts=t["Points"], ast=t["Assists"], reb=t["Rebounds"],
            stl=t["Steals"], blk=t["Blocks"], tov=t["Turnovers"],
            fgm=t["FieldGoalsMade"], fga=t["FieldGoalsAttempted"],
            fg3m=t["ThreePointersMade"], fg3a=t["ThreePointersAttempted"],
            ftm=t["FreeThrowsMade"], fta=t["FreeThrowsAttempted"]
        )
        db.merge(gts)
        team_totals[team_id] = gts

        for p in box["Stats"]["Players"]:
            player_id = _resolve_player_id(db, p)
            gps = GamePlayerStat(match_id=match_id, player_id=player_id, league_id=league_id)
            for el_key, (db_field, typ) in EL_TO_GPS.items():
                setattr(gps, db_field, typ(p.get(el_key) or ("" if typ is str else 0)))
            db.merge(gps)
    
    def _resolve_player_id(db: Session, player_data: dict) -> Optional[int]:
        """
        Resolves a player's ID from the database using available player data.
        """
        external_id = player_data.get("PlayerCode") or player_data.get("PlayerId")
        player = db.query(Player).filter_by(external_id=external_id).first()
        return player.id if player else None

    db.commit()
    
def _resolve_team_by_code(db: Session, league_id: int, code: str):
    t = db.query(Team).filter(Team.league_id == league_id, Team.abbreviation == code).first()
    if not t:
        t = db.query(Team).filter(Team.league_id == league_id, Team.name == code).first()
    return t

def _resolve_player(db: Session, league_id: int, team_id: int | None,
                    external_id: str | None, first_name: str | None, last_name: str | None):
    external_id = (external_id or "").strip() or None
    q = None
    if external_id:
        q = db.query(Player).filter(Player.league_id == league_id, Player.external_id == external_id).first()
        if q:
            if team_id and q.team_id != team_id:
                q.team_id = team_id
            return q
    q = (db.query(Player)
           .filter(Player.league_id == league_id,
                   func.trim(Player.first_name) == (first_name or "").strip(),
                   func.trim(Player.last_name) == (last_name or "").strip())
           .first())
    if q:
        if team_id and q.team_id != team_id:
            q.team_id = team_id
        return q
    p = Player(external_id=external_id, league_id=league_id,
               first_name=(first_name or "").strip() or None,
               last_name=(last_name or "").strip() or None,
               team_id=team_id)
    db.add(p); db.flush()
    return p
def _el_boxscore_from_db(db: Session, match_id: int, league_id: int):
    rows = (
        db.query(
            GamePlayerStat.player_id,
            Player.first_name, Player.last_name,
            Team.abbreviation.label("team_code"),
            GamePlayerStat.minutes,
            GamePlayerStat.pts, GamePlayerStat.ast, GamePlayerStat.reb,
            GamePlayerStat.stl, GamePlayerStat.blk, GamePlayerStat.fg3m,
            GamePlayerStat.plus_minus
        )
        .join(Player, Player.id == GamePlayerStat.player_id)
        .join(Team, Team.id == Player.team_id, isouter=True)
        .filter(GamePlayerStat.match_id == match_id,
                GamePlayerStat.league_id == league_id)
        .all()
    )
    players = []
    for r in rows:
        players.append({
            "player_id": r.player_id,
            "first_name": r.first_name, "last_name": r.last_name,
            "team_code": r.team_code,
            "minutes": r.minutes,
            "pts": r.pts, "ast": r.ast, "reb": r.reb,
            "stl": r.stl, "blk": r.blk, "fg3m": r.fg3m,
            "plus_minus": r.plus_minus,
        })
    return {"players": players}
def upsert_el_boxscore_to_db(db: Session, match_id: int, league_id: int, raw: dict):
    players = raw.get("Stats", {}).get("Players", []) or raw.get("players", [])

    team_codes = sorted({p.get("Team") for p in players if p.get("Team")})
    code_to_team_id = {c: (_resolve_team_by_code(db, league_id, c) or {}).id
                       for c in team_codes if _resolve_team_by_code(db, league_id, c)}

    team_totals = {} 
    for p in players:
        code = p.get("Team")
        if not code:
            continue
        T = team_totals.setdefault(code, {"pts":0,"ast":0,"reb":0,"stl":0,"blk":0,"fg3m":0,"fg3a":0,"tov":0,"fgm":0,"fga":0,"ftm":0,"fta":0})
        T["pts"]  += int(p.get("Points") or 0)
        T["ast"]  += int(p.get("Assistances") or 0)
        T["reb"]  += int(p.get("TotalRebounds") or 0)
        T["stl"]  += int(p.get("Steals") or 0)
        T["blk"]  += int(p.get("BlocksFavour") or 0)
        T["fg3m"] += int(p.get("FieldGoalsMade3") or 0)
        T["fg3a"] += int(p.get("FieldGoalsAttempted3") or 0)
        T["tov"]  += int(p.get("Turnovers") or 0)
        fgm2 = int(p.get("FieldGoalsMade2") or 0);  fga2 = int(p.get("FieldGoalsAttempted2") or 0)
        fgm3 = int(p.get("FieldGoalsMade3") or 0);  fga3 = int(p.get("FieldGoalsAttempted3") or 0)
        T["fgm"] += fgm2 + fgm3;  T["fga"] += fga2 + fga3
        T["ftm"] += int(p.get("FreeThrowsMade") or 0)
        T["fta"] += int(p.get("FreeThrowsAttempted") or 0)

        full_name = (p.get("Player") or "").strip()
        if "," in full_name:
            last_name, first_name = [s.strip() for s in full_name.split(",", 1)]
        else:
            parts = full_name.split()
            first_name = parts[0] if parts else None
            last_name = " ".join(parts[1:]) if len(parts) > 1 else None

        team_id = code_to_team_id.get(code)
        player = _resolve_player(db, league_id, team_id, p.get("Player_ID"), first_name, last_name)

        gps = (db.query(GamePlayerStat)
                 .filter(GamePlayerStat.match_id == match_id,
                         GamePlayerStat.player_id == player.id,
                         GamePlayerStat.league_id == league_id)
                 .first())
        if not gps:
            gps = GamePlayerStat(match_id=match_id, player_id=player.id, league_id=league_id)
            db.add(gps)

            # הקצאה דינמית לפי EL_TO_GPS
            for el_key, (db_field, typ) in EL_TO_GPS.items():
                setattr(gps, db_field, typ(p.get(el_key) or ("" if typ is str else 0)))

    if len(team_totals) >= 2:
        codes = list(team_totals.keys())
        for my_code, opp_code in [(codes[0], codes[1]), (codes[1], codes[0])]:
            my_team_id  = code_to_team_id.get(my_code)
            opp_team_id = code_to_team_id.get(opp_code)
            if not my_team_id or not opp_team_id:
                continue
            Tm = team_totals[my_code]
            gts = (db.query(GameTeamStat)
                     .filter(GameTeamStat.match_id == match_id,
                             GameTeamStat.league_id == league_id,
                             GameTeamStat.team_id == my_team_id)
                     .first())
            if not gts:
                gts = GameTeamStat(match_id=match_id, league_id=league_id,
                                   team_id=my_team_id, opponent_team_id=opp_team_id)
                db.add(gts)
            gts.opponent_team_id = opp_team_id
            gts.pts, gts.ast, gts.reb = Tm["pts"], Tm["ast"], Tm["reb"]
            gts.stl, gts.blk, gts.tov = Tm["stl"], Tm["blk"], Tm["tov"]
            gts.fgm, gts.fga = Tm["fgm"], Tm["fga"]
            gts.fg3m, gts.fg3a = Tm["fg3m"], Tm["fg3a"]
            gts.ftm, gts.fta = Tm["ftm"], Tm["fta"]

    db.commit()