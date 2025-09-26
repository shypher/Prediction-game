import { getJSON, postJSON, buildQuery } from "../api/client";

export type PickSide = "home" | "away" | null;

export type PredictionOut = {
  id: number;
  user_id: number;
  match_id: number;
  pick: PickSide;
  margin: number;          
  points_awarded?: number | null;
  is_final: boolean;
  created_at: string;
  updated_at: string;
};

export type CreatePrediction = {
  match_id: number;
  pick: PickSide;            
  margin: number;            
};

export type UpdatePrediction = {
  pick?: PickSide;
  margin?: number;
};

export function createOrUpdatePrediction(payload: CreatePrediction, signal?: AbortSignal) {
  return postJSON<PredictionOut>("/predictions", payload, signal);
}

export function fetchMyPrediction(matchId: number, signal?: AbortSignal) {
  return getJSON<PredictionOut>(`/predictions/me/${matchId}`, signal);
}

export type MatchPredictionStats = {
  match_id: number;
  total: number;
  home_pick?: number;
  away_pick?: number;
  favorite: "home" | "away" | null;
  confidence_pct: number | null;          
  avg_signed_margin: number | null;       
  median_signed_margin: number | null;
  margin_histogram: { range: string; count: number }[];
};

export function fetchMatchPredictionStats(matchId: number, signal?: AbortSignal) {
  return getJSON<MatchPredictionStats>(`/predictions/by-match/${matchId}`, signal);
}

export function fetchPreviewPoints(matchId: number, signal?: AbortSignal) {
  return getJSON<{ match_id: number; preview_points: number | null; reason?: string }>(
    `/predictions/preview/${matchId}`, signal
  );
}
