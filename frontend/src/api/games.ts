import { getJSON } from "./client";
import type { MatchDTO, UIMatch } from "../pages/games/types";
import { mapMatchDTOToUIMatch } from "../pages/games/types";

export async function fetchMatches(
  params: { leagueId?: number; leagueName?: string; date?: string },
  signal?: AbortSignal
): Promise<UIMatch[]> {
  const qs = new URLSearchParams();
  if (params.leagueId != null) qs.set("league_id", String(params.leagueId));
  if (params.leagueName)       qs.set("league", params.leagueName);
  if (params.date)             qs.set("date", params.date);
  const url = "/matches" + (qs.toString() ? `?${qs.toString()}` : "");
  const data = await getJSON<MatchDTO[]>(url, signal);
  return data.map(mapMatchDTOToUIMatch);
}

// Interface for the /ui_next endpoint response

export type FetchUINextOptions = {
  limit?: number;
  daysAfter?: number;
  daysBefore?: number;
  scope?: "window" | "season";
  season?: number;
  leagueId?: number;
};

export async function fetchUINextMatches(opts: FetchUINextOptions = {}, signal?: AbortSignal) {
  const p = new URLSearchParams();
  p.set("limit", String(opts.limit ?? 2000));
  if (opts.daysAfter != null) p.set("days_after", String(opts.daysAfter));
  if (opts.daysBefore != null) p.set("days_before", String(opts.daysBefore));
  if (opts.scope) p.set("scope", opts.scope);
  if (opts.season != null) p.set("season", String(opts.season));
  if (opts.leagueId != null) p.set("league_id", String(opts.leagueId));
  return getJSON(`/games/ui_next?${p.toString()}`, signal);
}

