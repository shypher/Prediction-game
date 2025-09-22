import { getJSON } from "./client";

export type TeamSummary = { ppg: number; apg: number; rpg: number; games: number };
export type LeaderRow = { player_id: number; player: string; value: number };
export type Leaders = {
  pts: LeaderRow | null;
  ast: LeaderRow | null;
  reb: LeaderRow | null;
  st?: LeaderRow | null;    
  blk?: LeaderRow | null;   
  fg3m?: LeaderRow | null;  
};
export type TeamGameLine = {
  PTS?: number; AST?: number; REB?: number; ST?: number; BLK?: number; TO?: number;
  "FG%"?: number; "3P%"?: number; "FT%"?: number; "3PTM"?: number;
};

export type BoxPlayer = {
  player_id?: number | string;
  first_name?: string;
  last_name?: string;
  player?: string; 
  team_code?: string;
  team?: string;   
  minutes?: string | number | null;
  pts?: number | null;
  ast?: number | null;
  reb?: number | null;
  stl?: number | null;
  blk?: number | null;
  fg3m?: number | null;
  plus_minus?: number | null;
};
export type MatchFull = {
  match?: {
    id?: number;
    home_team?: { name?: string; logo_url?: string | null; primary_color?: string | null; secondary_color?: string | null };
    away_team?: { name?: string; logo_url?: string | null; primary_color?: string | null; secondary_color?: string | null };
    home_score?: number | null;
    away_score?: number | null;
    status?: string;
    season?: number;
    league_id?: number;
    match_date?: string;
  };
  assets?: { home?: any; away?: any };

  pregame?: {
    home?: { summary?: TeamSummary; leaders?: Leaders };
    away?: { summary?: TeamSummary; leaders?: Leaders };
  } | null;

  season?: {
    home?: { summary?: TeamSummary; leaders?: Leaders };
    away?: { summary?: TeamSummary; leaders?: Leaders };
  } | null;

  team_game?: {
    home?: { for?: TeamGameLine; against?: TeamGameLine };
    away?: { for?: TeamGameLine; against?: TeamGameLine };
  } | null;

  boxscore?: {
    players?: BoxPlayer[];
  } | null;
};

export async function fetchMatchFull(matchId: number, signal?: AbortSignal): Promise<MatchFull> {
  return getJSON<MatchFull>(`/matches/${matchId}/full`, signal);
}