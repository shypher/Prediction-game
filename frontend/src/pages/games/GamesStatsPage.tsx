import { useEffect, useMemo, useState } from "react";
import "./Results.css";
import { fetchTeamsAssets, type TeamAsset } from "../../api/teams";

type TopPlayerRow = {
  player_id: number;
  player: string;
  team_id?: number;
  team?: string;
} & Record<string, number>;
type TopTeamRow = { team_id: number; team: string } & Record<string, number>;
async function jsonOrThrow(res: Response) {
  const ct = res.headers.get("content-type") || "";
  if (!res.ok || !ct.includes("application/json")) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status} - ${text.slice(0, 200)}`);
  }
  return res.json();
}

async function fetchTopPlayers(
  league_id: number,
  season: number,
  metric: string,
  signal?: AbortSignal
) {
  const res = await fetch(
    `/stats/top-players?league_id=${league_id}&season=${season}&metric=${metric}`,
    { signal }
  );
  return (await jsonOrThrow(res)) as { players: TopPlayerRow[] };
}

async function fetchTopTeams(
  league_id: number,
  season: number,
  metric: string,
  signal?: AbortSignal
) {
  const res = await fetch(
    `/stats/top-teams?league_id=${league_id}&season=${season}&metric=${metric}`,
    { signal }
  );
  return (await jsonOrThrow(res)) as { teams: TopTeamRow[] };
}
const METRICS = [
  { key: "pts", label: "Points" },
  { key: "ast", label: "Assists" },
  { key: "reb", label: "Rebounds" },
  { key: "stl", label: "Steals" },
  { key: "blk", label: "Blocks" },
  { key: "fg3m", label: "3PT Made" },
];

export default function GamesStatsPage({
  leagueId = 120,
  season,
}: {
  leagueId?: number;
  season: number;
}) {
  const [tab, setTab] = useState<"players" | "teams">("players");
  const [assets, setAssets] = useState<Record<number, TeamAsset>>({});
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [players, setPlayers] = useState<Record<string, TopPlayerRow[]>>({});
  const [teams, setTeams] = useState<Record<string, TopTeamRow[]>>({});

  useEffect(() => {
    const ac = new AbortController();
    fetchTeamsAssets(leagueId, ac.signal)
      .then((list) => {
        const byId: Record<number, TeamAsset> = {};
        for (const a of list) if (a.id != null) byId[a.id] = a as any;
        setAssets(byId);
      })
      .catch(() => {});
    return () => ac.abort();
  }, [leagueId]);

  useEffect(() => {
    const ac = new AbortController();
    (async () => {
      try {
        setLoading(true);
        setErr(null);
        const pCalls = METRICS.map((m) =>
          fetchTopPlayers(leagueId, season, m.key, ac.signal).then(
            (r) => [m.key, r.players] as const
          )
        );
        const tCalls = METRICS.map((m) =>
          fetchTopTeams(leagueId, season, m.key, ac.signal).then(
            (r) => [m.key, r.teams] as const
          )
        );
        const p = await Promise.all(pCalls);
        const t = await Promise.all(tCalls);
        setPlayers(Object.fromEntries(p));
        setTeams(Object.fromEntries(t));
      } catch (e: any) {
        if (e?.name !== "AbortError")
          setErr(e?.message || "Failed to load stats");
      } finally {
        setLoading(false);
      }
    })();
    return () => ac.abort();
  }, [leagueId, season]);
  const hasAnyData =
    Object.values(players).some((arr) => (arr?.length || 0) > 0) ||
    Object.values(teams).some((arr) => (arr?.length || 0) > 0);
  return (
    <div className="results-root">
      <div className="card" style={{ display: "flex", gap: 8 }}>
        <button
          className={`chip ${tab === "players" ? "active" : ""}`}
          onClick={() => setTab("players")}
        >
          Players
        </button>
        <button
          className={`chip ${tab === "teams" ? "active" : ""}`}
          onClick={() => setTab("teams")}
        >
          Teams
        </button>
      </div>

      {loading && <div className="card">Loading…</div>}
      {err && !loading && <div className="card">Error: {err}</div>}
      {!loading && !err && !hasAnyData && (
        <div className="card">
          <strong>Stats are coming soon</strong>
          <div className="subtle" style={{ marginTop: 6 }}>
            We don’t have season stats yet for league {leagueId}, season{" "}
            {season}.
          </div>
        </div>
      )}
      {!loading && !err && (
        <div className="stats-grid">
          {(tab === "players" ? METRICS : METRICS).map((m) => (
            <div key={m.key} className="card">
              <strong>
                Top 5 {tab === "players" ? "Players" : "Teams"} — {m.label}
              </strong>
              <ol style={{ marginTop: 8 }}>
                {(tab === "players" ? players[m.key] || [] : teams[m.key] || [])
                  .slice(0, 5)
                  .map((row, idx) => (
                    <li
                      key={idx}
                      style={{ display: "flex", alignItems: "center", gap: 8 }}
                    >
                      {tab === "teams" ? (
                        <>
                          {"team_id" in row && assets[(row as any).team_id] && (
                            <img
                              src={assets[(row as any).team_id].logo_url || ""}
                              alt=""
                              style={{
                                width: 20,
                                height: 20,
                                objectFit: "contain",
                              }}
                            />
                          )}
                          <span style={{ flex: 1 }}>{(row as any).team}</span>
                          <b>{row[m.key as keyof typeof row] as any}</b>
                        </>
                      ) : (
                        <>
                          <span style={{ flex: 1 }}>
                            {(row as any).player}
                            {(row as any).team ? ` — ${(row as any).team}` : ""}
                          </span>
                          <b>{row[m.key as keyof typeof row] as any}</b>
                        </>
                      )}
                    </li>
                  ))}
              </ol>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
