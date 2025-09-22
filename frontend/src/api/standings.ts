const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

export type StandingRowDTO = {
  team: string;
  w: number;
  l: number;
  pf: number;
  pa: number;
  diff: number;
  rank: number
};

export async function fetchStandings(
  params: { league: string; season?: number; conference?: string; division?: string },
  signal?: AbortSignal
) {
  const qs = new URLSearchParams();
  if (params.league) qs.set("league", params.league);
  if (params.season != null) qs.set("season", String(params.season));
  if (params.conference) qs.set("conference", params.conference);
  if (params.division) qs.set("division", params.division);
  const res = await fetch(`${BASE_URL}/games/standings?${qs.toString()}`, {
    signal, credentials: "include",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as StandingRowDTO[];
}