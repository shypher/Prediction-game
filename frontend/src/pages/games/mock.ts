export type TeamRef = { id: string; name: string; logo?: string; emoji?: string };
export type MatchStatus = "upcoming" | "live" | "final";

export type Match = {
  id: string;
  league: string;            // e.g., "EuroLeague"
  date: string;              // ISO string
  status: MatchStatus;
  home: TeamRef;
  away: TeamRef;
  score?: { home: number; away: number }; // when live/final
};

export type TeamLeaders = {
  points: { name: string; value: number };
  rebounds: { name: string; value: number };
  assists: { name: string; value: number };
};

export type MatchStats = {
  homeTeamStats: { ppg: number; rpg: number; apg: number };
  awayTeamStats: { ppg: number; rpg: number; apg: number };
  homeLeaders: TeamLeaders;
  awayLeaders: TeamLeaders;
homeRecord?: string;
  awayRecord?: string;
};

// ---- Mock data ----
export const MOCK_MATCHES: Match[] = [
  {
    id: "m1",
    league: "EuroLeague",
    date: "2025-10-01T19:30:00Z",
    status: "upcoming",
    home: { id: "mac", name: "Maccabi", emoji: "🟡" },
    away: { id: "rmd", name: "Real Madrid", emoji:"⬜️"  },
  },
  {
    id: "m2",
    league: "EuroLeague",
    date: "2025-10-02T21:00:00Z",
    status: "upcoming",
    home: { id: "bar", name: "Barcelona", emoji: "🔵" },
    away: { id: "fen", name: "Fenerbahçe", emoji: "🟨" },
  },
  {
    id: "m3",
    league: "EuroCup",
    date: "2025-10-02T18:00:00Z",
    status: "final",
    home: { id: "par", name: "Paris", emoji: "🟪" },
    away: { id: "val", name: "Valencia", emoji: "🟧" },
    score: { home: 78, away: 80 },
  },
];

export const MOCK_STATS: Record<string, MatchStats> = {
  m1: {
    homeTeamStats: { ppg: 85.2, rpg: 35.1, apg: 18.4 },
    awayTeamStats: { ppg: 83.0, rpg: 34.6, apg: 19.2 },
    homeLeaders: {
      points: { name: "Cohen", value: 19 },
      rebounds: { name: "Blayzer", value: 9 },
      assists: { name: "Brown", value: 7 },
    },
    awayLeaders: {
      points: { name: "Llull", value: 17 },
      rebounds: { name: "Tavares", value: 11 },
      assists: { name: "Campazzo", value: 8 },
    },
    homeRecord: "7-0",
    awayRecord: "6-1",
  },
  m2: {
    homeTeamStats: { ppg: 84.0, rpg: 34.0, apg: 20.0 },
    awayTeamStats: { ppg: 82.5, rpg: 33.5, apg: 18.8 },
    homeLeaders: {
      points: { name: "Laprovittola", value: 18 },
      rebounds: { name: "Vesely", value: 8 },
      assists: { name: "Satoransky", value: 7 },
    },
    awayLeaders: {
      points: { name: "Wilbekin", value: 20 },
      rebounds: { name: "Motley", value: 10 },
      assists: { name: "Calathes", value: 9 },
    },
    homeRecord: "5-2",
    awayRecord: "6-1",
  },
  m3: {
    homeTeamStats: { ppg: 80.0, rpg: 32.0, apg: 16.0 },
    awayTeamStats: { ppg: 81.0, rpg: 33.0, apg: 17.0 },
    homeLeaders: {
      points: { name: "James", value: 21 },
      rebounds: { name: "Diallo", value: 9 },
      assists: { name: "Smith", value: 6 },
    },
    awayLeaders: {
      points: { name: "Lopez", value: 18 },
      rebounds: { name: "Garcia", value: 12 },
      assists: { name: "Mendez", value: 7 },
    },
    homeRecord: "5-2",
    awayRecord: "2-5",
  },
};
