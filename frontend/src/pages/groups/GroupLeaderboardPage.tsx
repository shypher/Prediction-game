import { useEffect, useMemo, useState } from "react";
import "./../games/Results.css";
import { fetchLeaderboard, type LeaderboardEntry } from "../../api/leaderboard";
import { useParams } from "react-router-dom";

export default function GroupLeaderboardPage() {
  const params = useParams<{ id: string }>();
  const groupId = Number(params.id);
  const [season, setSeason] = useState<number | "">("");
  const [league, setLeague] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string|null>(null);
  const [rows, setRows] = useState<LeaderboardEntry[]>([]);

  useEffect(() => {
    if (!groupId) return;
    const ac = new AbortController();
    (async () => {
      try {
        setLoading(true); setErr(null);
        const data = await fetchLeaderboard({
          group_id: groupId,
          season: season === "" ? undefined : Number(season),
          league: league || undefined,
          limit: 100,
          offset: 0,
        }, ac.signal);
        setRows(data);
      } catch (e: any) {
        if (e?.name !== "AbortError") setErr(e?.message || "Failed to load leaderboard");
      } finally { setLoading(false); }
    })();
    return () => ac.abort();
  }, [groupId, season, league]);

  return (
    <div className="results-root">
      <div className="card" style={{display:"flex", gap:8, flexWrap:"wrap", alignItems:"center"}}>
        <strong>Leaderboard</strong>
        <label>Season</label>
        <input type="number" placeholder="(all)" value={season as any} onChange={e => setSeason((e.target.value === "" ? "" : Number(e.target.value)) as any)} style={{width:100}} />
        <label>League</label>
        <input placeholder="(all)" value={league} onChange={e=>setLeague(e.target.value)} style={{width:140}} />
      </div>

      {loading && <div className="card">Loading…</div>}
      {err && !loading && <div className="card">Error: {err}</div>}

      {!loading && !err && (
        <div className="card">
          <table className="table">
            <thead>
              <tr>
                <th style={{width:60, textAlign:"right"}}>#</th>
                <th>User</th>
                <th style={{width:120, textAlign:"right"}}>Points</th>
                <th style={{width:120, textAlign:"right"}}>Bets</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr><td colSpan={4} className="subtle">No entries yet.</td></tr>
              )}
              {rows.map((r, idx) => (
                <tr key={r.user_id}>
                  <td style={{textAlign:"right"}}>{r.rank}</td>
                  <td>User #{r.user_id}</td>
                  <td style={{textAlign:"right"}}>{r.total_points}</td>
                  <td style={{textAlign:"right"}}>{r.bets}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
