import { useEffect, useMemo, useState } from "react";
import "./Table.css";
import { fetchStandings, type StandingRowDTO } from "../../api/standings";
import { fetchTeamsAssets, type TeamAsset } from "../../api/teams";
function normalizeName(s: string): string {
  const x = s
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
  const tokens = x
    .replace(/[^a-z0-9]+/g, " ")
    .split(" ")
    .filter(Boolean);
  const skip = new Set([
    "fc",
    "bc",
    "basket",
    "basketball",
    "mozzart",
    "meridianbet",
    "segafredo",
    "emporio",
    "armani",
    "aktor",
    "beko",
    "playtika",
    "rapyd",
    "ibi",
    "ldlc",
  ]);
  const kept = tokens.filter((t) => !skip.has(t));
  return kept.join(" ");
}
type LeagueKey = "EuroLeague" | "NBA";
const LEAGUE_IDS: Record<LeagueKey, number> = {
  EuroLeague: 120,
  NBA: 0,
};
export type StandingRow = {
  pos: number;
  team: string;
  w: number;
  l: number;
  pf: number;
  pa: number;
  rank: number;
};
type TeamsMap = Record<string, TeamAsset>;
type SortKey = keyof StandingRow | "diff" | "rank";
type SortDir = "asc" | "desc";

export default function TablePage() {
  const [league, setLeague] = useState<LeagueKey>("EuroLeague");
  const [season, setSeason] = useState<number>(2025);
  const [conference, setConference] = useState<string>("");
  const [division, setDivision] = useState<string>("");
  const [rows, setRows] = useState<StandingRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<SortKey>("pos");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [teamsMap, setTeamsMap] = useState<TeamsMap>({});

  useEffect(() => {
    const ac = new AbortController();
    const leagueId = LEAGUE_IDS[league];
    setTeamsMap({});
    fetchTeamsAssets(leagueId, ac.signal)
      .then((list) => {
        const map: TeamsMap = {};
        for (const t of list) {
          map[normalizeName(t.name || "")] = t; 
        }
        setTeamsMap(map);
      })
      .catch(() => setTeamsMap({}));
    return () => ac.abort();
  }, [league]);
  useEffect(() => {
    if (league !== "NBA") {
      setConference("");
      setDivision("");
    }
  }, [league]);
  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    setError(null);
    fetchStandings({ league, season }, ac.signal)
      .then((data) => {
        const mapped: StandingRow[] = data.map((r) => ({
          pos: 0,
          team: r.team,
          w: r.w,
          l: r.l,
          pf: r.pf,
          pa: r.pa,
          rank: r.rank,
        }));
        setRows(mapped);
      })
      .catch((e: any) => setError(e?.message || "Failed to load standings"))
      .finally(() => setLoading(false));
    return () => ac.abort();
  }, [league, season]);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    setError(null);
    fetchStandings(
      {
        league,
        season,
        conference: league === "NBA" ? conference || undefined : undefined,
        division: league === "NBA" ? division || undefined : undefined,
      },
      ac.signal
    )
      .then((data) => {
        const mapped: StandingRow[] = data.map((r) => ({
          pos: 0,
          team: r.team,
          w: r.w,
          l: r.l,
          pf: r.pf,
          pa: r.pa,
          rank: r.rank,
        }));
        setRows(mapped);
      })
      .catch((e) => setError(e?.message || "Failed to load standings"))
      .finally(() => setLoading(false));
    return () => ac.abort();
  }, [league, season, conference, division]);
  const sorted = useMemo(() => {
    const base = rows.map((r) => ({ ...r, diff: r.pf - r.pa }));
    const out = [...base].sort((a, b) => {
      const va = (sortBy === "diff" ? a.pf - a.pa : (a as any)[sortBy]) as any;
      const vb = (sortBy === "diff" ? b.pf - b.pa : (b as any)[sortBy]) as any;

      if (typeof va === "string" && typeof vb === "string") {
        const cmp = va.localeCompare(vb);
        return sortDir === "asc" ? cmp : -cmp;
      } else {
        const na = Number(va);
        const nb = Number(vb);
        const cmp = na - nb;
        return sortDir === "asc" ? cmp : -cmp;
      }
    });
    return out.map((r, i) => ({ ...r, pos: i + 1 }));
  }, [rows, sortBy, sortDir]);

  function toggleSort(col: SortKey) {
    if (sortBy !== col) {
      setSortBy(col);
      setSortDir(col === "pos" ? "asc" : "desc");
    } else {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    }
  }

  const arrow = (col: SortKey) =>
    sortBy === col ? (sortDir === "asc" ? "▲" : "▼") : " ";

  return (
    <div className="card table-card">
      <div className="table-toolbar">
        <div className="toolbar-left">
          <label className="sr-only" htmlFor="league">
            League
          </label>
          <select
            id="league"
            value={league}
            onChange={(e) => setLeague(e.target.value as LeagueKey)}
          >
            <option value="EuroLeague">EuroLeague</option>
            <option value="NBA">NBA</option>
          </select>

          <label className="sr-only" htmlFor="season">
            Season
          </label>
          <select
            id="season"
            value={season}
            onChange={(e) => setSeason(Number(e.target.value))}
            style={{ marginInlineStart: 8 }}
          >
            <option value={2025}>2025</option>
            <option value={2024}>2024</option>
            <option value={2023}>2023</option>
          </select>

          {league === "NBA" && (
            <>
              <select
                aria-label="Conference"
                value={conference}
                onChange={(e) => {
                  setConference(e.target.value);
                  setDivision("");
                }}
                style={{ marginInlineStart: 8 }}
              >
                <option value="">All Conferences</option>
                <option value="East">East</option>
                <option value="West">West</option>
              </select>

              <select
                aria-label="Division"
                value={division}
                onChange={(e) => setDivision(e.target.value)}
                style={{ marginInlineStart: 8 }}
              >
                <option value="">All Divisions</option>
                {conference === "" || conference === "East" ? (
                  <>
                    <option value="Atlantic">Atlantic</option>
                    <option value="Central">Central</option>
                    <option value="Southeast">Southeast</option>
                  </>
                ) : null}
                {conference === "" || conference === "West" ? (
                  <>
                    <option value="Northwest">Northwest</option>
                    <option value="Pacific">Pacific</option>
                    <option value="Southwest">Southwest</option>
                  </>
                ) : null}
              </select>
            </>
          )}
        </div>
      </div>

      {loading && <div className="card">Loading…</div>}
      {error && !loading && <div className="card">Error: {error}</div>}

      {!loading && !error && (
        <div className="table-wrap">
          <table className="standings" role="table">
            <caption className="sr-only">{league} standings</caption>
            <thead>
              <tr>
                <Th
                  onClick={() => toggleSort("rank")}
                  align="start"
                  className="col-pos"
                >
                  # {arrow("rank")}
                </Th>
                <Th
                  onClick={() => toggleSort("pos")}
                  align="end"
                  className="col-pos"
                >
                  # {arrow("pos")}
                </Th>
                <Th
                  onClick={() => toggleSort("team")}
                  align="end"
                  className="col-team"
                >
                  Team {arrow("team")}
                </Th>
                <Th
                  onClick={() => toggleSort("w")}
                  align="end"
                  className="col-w"
                >
                  W {arrow("w")}
                </Th>
                <Th
                  onClick={() => toggleSort("l")}
                  align="end"
                  className="col-l"
                >
                  L {arrow("l")}
                </Th>
                <Th
                  onClick={() => toggleSort("pf")}
                  align="end"
                  className="col-pf"
                >
                  PF {arrow("pf")}
                </Th>
                <Th
                  onClick={() => toggleSort("pa")}
                  align="end"
                  className="col-pa"
                >
                  PA {arrow("pa")}
                </Th>
                <Th
                  onClick={() => toggleSort("diff")}
                  align="end"
                  className="col-diff"
                >
                  +/- {arrow("diff")}
                </Th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((r) => (
                <tr key={r.team}>
                  <Td align="end" className="col-rank" label="#">
                    {r.rank}
                  </Td>
                  <Td align="end" className="col-pos" label="#">
                    {r.pos}
                  </Td>
                  <Td align="start" className="col-team" label="Team">
                    <span className="team-cell">
                      {(() => {
                        const t = teamsMap[normalizeName(r.team)];
                        if (t?.logo_url) {
                          return (
                            <img
                              className="team-logo-sm"
                              src={t.logo_url}
                              alt=""
                              aria-hidden
                            />
                          );
                        }
                        if (t?.primary_color) {
                          return (
                            <span
                              className="team-dot"
                              style={{ background: t.primary_color }}
                            />
                          );
                        }
                        return <span className="team-dot" />;
                      })()}
                      <span className="team-name">{r.team}</span>
                    </span>
                  </Td>
                  <Td align="end" className="col-w" label="W">
                    {r.w}
                  </Td>
                  <Td align="end" className="col-l" label="L">
                    {r.l}
                  </Td>
                  <Td align="end" className="col-pf" label="PF">
                    {r.pf}
                  </Td>
                  <Td align="end" className="col-pa" label="PA">
                    {r.pa}
                  </Td>
                  <Td align="end" className="col-diff" label="+/-">
                    {r.pf - r.pa}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Th(props: {
  children: React.ReactNode;
  onClick: () => void;
  align?: "start" | "end";
  className?: string;
}) {
  return (
    <th
      scope="col"
      onClick={props.onClick}
      className={props.className}
      style={{ textAlign: props.align ?? "start", cursor: "pointer" }}
    >
      {props.children}
    </th>
  );
}
function Td(props: {
  children: React.ReactNode;
  align?: "start" | "end";
  label?: string;
  className?: string;
}) {
  return (
    <td
      className={props.className}
      style={{ textAlign: props.align ?? "start" }}
      data-label={props.label ?? ""}
    >
      {props.children}
    </td>
  );
}
