export interface MatchDTO {
  id: number;
  home_team: string;
  away_team: string;
  match_date: string;      
  home_score: number | null;
  away_score: number | null;
  round: number | null;
  league_id: number;
  season: number;
  external_id: string | null;
  status: string;          
  league_name: string | null;
  country: string | null;
  timezone: string | null;
  last_update: string | null;
  source: string | null;
}

export type UIMatchStatus = "upcoming" | "live" | "final";

export interface TeamRef {
  id?: number;
  name: string;
  emoji?: string; 
}

export interface UIMatch {
  id: number;
  leagueId: number;
  leagueName?: string | null;
  season: number;
  round?: number | null;
  date: string;       
  status: UIMatchStatus;
  timezone?: string | null;
  home: TeamRef;
  away: TeamRef;
  score?: { home: number; away: number }; 
}

function mapStatus(s: string): UIMatchStatus {
  const x = s.toLowerCase();
  if (x.includes("live")) return "live";
  if (x.includes("finish") || x === "final" || x === "ended") return "final";
  return "upcoming"; 
}

export function mapMatchDTOToUIMatch(dto: MatchDTO): UIMatch {
  return {
    id: dto.id,
    leagueId: dto.league_id,
    leagueName: dto.league_name,
    season: dto.season,
    round: dto.round ?? undefined,
    date: new Date(dto.match_date).toISOString(),
    status: mapStatus(dto.status || "scheduled"),
    timezone: dto.timezone,
    home: { name: dto.home_team, emoji: "🔷" }, 
    away: { name: dto.away_team, emoji: "🔶" },
    score:
      dto.home_score != null && dto.away_score != null
        ? { home: dto.home_score, away: dto.away_score }
        : undefined,
  };
}
