import { getJSON } from "./client";

export type LeagueOverviewTeam = {
  team_id: number;
  name: string;
  abbreviation: string | null;
  logo_url: string | null;
  primary_color: string | null;
  secondary_color: string | null;
  ppg: number;
  apg: number;
  rpg: number;
  leaders: {
    pts: { player_id: number; player: string; value: number } | null;
    ast: { player_id: number; player: string; value: number } | null;
    reb: { player_id: number; player: string; value: number } | null;
  } | null;
};

export type LeagueOverview = {
  league_id: number;
  season: number;
  teams: LeagueOverviewTeam[];
};

export async function fetchLeagueOverview(leagueId: number, season: number, includeEmpty = true, signal?: AbortSignal): Promise<LeagueOverview> {
  return getJSON<LeagueOverview>(`/stats/league_overview?league_id=${leagueId}&season=${season}&include_empty=${includeEmpty}`, signal);
}

export type SimpleBoxscore = {
  match_id: number;
  players: { team: string; player: string; pts: number; ast: number; reb: number; minutes: string | number | null }[];
};

export async function fetchEuroleagueBoxscoreSimple(matchId: number, signal?: AbortSignal): Promise<SimpleBoxscore> {
  return getJSON<SimpleBoxscore>(`/euroleague/boxscore_simple/${matchId}`, signal);
}

export type MatchExtended = {
  match: {
    id: number;
    home_team: { name: string; logo_url: string | null; primary_color: string | null; secondary_color: string | null; leaders?: any } | null;
    away_team: { name: string; logo_url: string | null; primary_color: string | null; secondary_color: string | null; leaders?: any } | null;
    home_score: number | null;
    away_score: number | null;
    status: string;
    season: number;
    league_id: number;
  };
  boxscore: { player: string; team_id: number | null; pts: number | null; ast: number | null; reb: number | null; stl: number | null; blk: number | null; fg3m: number | null; minutes: string | null }[];
};

export async function fetchMatchExtended(matchId: number, signal?: AbortSignal): Promise<MatchExtended> {
  return getJSON<MatchExtended>(`/api/matches/${matchId}/extended`, signal);
}
