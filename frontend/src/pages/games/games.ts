import { api } from "../../client";

export type Game = {
  id: number;
  homeTeam: string;
  awayTeam: string;
  matchDate: string; 
  homeScore?: number | null;
  awayScore?: number | null;
  round?: number | null;
  leagueId: number;
  season: number;
  status?: string | null;
  leagueName?: string | null;
  country?: string | null;
  timezone?: string | null;
  source?: string | null;
};
export async function getGames(params?: {
  leagueId?: number;
  season?: number;
  status?: string;
  limit?: number;
  offset?: number;
}): Promise<Game[]> {
  const res = await api.get<Game[]>("/games", { params });
  return res.data;
}
