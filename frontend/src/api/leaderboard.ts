import { getJSON } from "../api/client";

export type LeaderboardEntry = {
  user_id: number;
  total_points: number;
  bets: number;
  rank: number;
};

export function fetchLeaderboard(params: {
  group_id?: number;
  league?: string;
  season?: number;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}, signal?: AbortSignal) {
  const url = new URL("/leaderboard", window.location.origin);
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  });
  return getJSON<LeaderboardEntry[]>(url.pathname + "?" + url.searchParams.toString(), signal);
}
