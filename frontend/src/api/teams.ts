import { getJSON } from "./client";

export type TeamAsset = {
  id: number;
  name: string;
  abbreviation: string | null;
  logo_url: string | null;
  primary_color: string | null;
  secondary_color: string | null;
};

export async function fetchTeamsAssets(leagueId: number, signal?: AbortSignal): Promise<TeamAsset[]> {
  return getJSON<TeamAsset[]>(`/teams?league_id=${leagueId}`, signal);
}
