import { useMemo, useRef, useEffect } from "react";
import type { UIMatch } from "./types";
import "./Results.css";

export type ResultsFilters = { league: string; date: string };

type Prediction = { winner: "home" | "away" | null; spread: number };
function normalizeName(s: string): string {
  const x = s.normalize("NFD").toLowerCase();
  const tokens = x
    .replace(/[^a-z0-9]+/g, " ")
    .split(" ")
    .filter(Boolean);
  const skip = new Set([
    "fc",
    "bc",
    "mozzart",
    "meridianbet",
    "segafredo",
    "emporio",
    "armani",
    "aktor",
    "rapyd",
    "ibi",
    "ldlc",
    "istanbul",
    "belgrade",
    "athens",
    "gasteiz",
    "piraeus",
  ]);
  const kept = tokens.filter((t) => !skip.has(t));
  return kept.join(" ").toUpperCase();
}
type TeamAsset = {
  logo_url: string | null;
  primary_color: string | null;
  secondary_color: string | null;
};

type LeagueAssets = {
  byName: Record<string, TeamAsset>;
  byId: Record<number, TeamAsset>;
};

type Props = {
  allMatches: UIMatch[];
  filters: ResultsFilters;
  onChangeFilters: (next: ResultsFilters) => void;
  visibleMatches: UIMatch[];
  selectedMatchId: number | null;
  onSelectMatch: (id: number) => void;
  predictions: Record<number, Prediction>;
  teamAssets?: Record<number, LeagueAssets>;
};

function uniqSorted<T>(arr: T[]) {
  return Array.from(new Set(arr)).sort() as T[];
}
function firstOrNextDateForLeague(
  allMatches: UIMatch[],
  leagueId: number,
  base?: string
) {
  const days = uniqSorted(
    allMatches
      .filter((m) => m.leagueId === leagueId)
      .map((m) => dateKeyFromISO(m.date))
  );
  if (!days.length) return "";
  if (!base) return days[0];
  const i = days.findIndex((d) => d >= base);
  return i >= 0 ? days[i] : days[0];
}
function dateKeyFromISO(s: string): string {
  const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  const d = new Date(s);
  const y = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${y}-${mm}-${dd}`;
}
export default function ResultsHeader({
  allMatches,
  filters,
  onChangeFilters,
  visibleMatches,
  selectedMatchId,
  onSelectMatch,
  predictions,
  teamAssets,
}: Props) {
  const leagues = useMemo(() => {
    const map = new Map<number, string>();
    for (const m of allMatches) {
      if (m.leagueId != null) {
        const name = m.leagueName ?? String(m.leagueId);
        if (!map.has(m.leagueId)) map.set(m.leagueId, name);
      }
    }
    return Array.from(map.entries()).map(([id, name]) => ({ id, name }));
  }, [allMatches]);

  const scrollerRef = useRef<HTMLDivElement>(null);
  const scrollBy = (px: number) =>
    scrollerRef.current?.scrollBy({ left: px, behavior: "smooth" });
  const scrollPrev = () => scrollBy(-360);
  const scrollNext = () => scrollBy(+360);
  const leagueMatches = useMemo(() => {
    if (!filters.league) return allMatches;
    return allMatches.filter((m) => m.leagueName === filters.league);
  }, [allMatches, filters.league]);
  const todayKey = useMemo(() => {
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    return `${y}-${m}-${dd}`;
  }, []);
  const selectedLeagueId = filters.league ? Number(filters.league) : null;
  const dateOptions = useMemo(() => {
    const pool = selectedLeagueId
      ? allMatches.filter(m => m.leagueId === selectedLeagueId)
      : allMatches;
    return uniqSorted(pool.map(m => dateKeyFromISO(m.date)));
  }, [allMatches, selectedLeagueId]);
    const dateValue = useMemo(() => {
    if (!filters.date) return ""; 
    if (dateOptions.includes(filters.date)) return filters.date;
    return dateOptions[0] || ""; 
  }, [filters.date, dateOptions]);
  return (
    <div className="results-header">
      <div className="results-header-grid">
        <div className="filters">
          <div>
            <label>League</label>
            <select
              value={filters.league}
              onChange={(e) => {
                const league = e.target.value;
                if (!league) {
                  onChangeFilters({ ...filters, league });
                  return;
                }
                const lid = Number(league);
                const curDay = filters.date || "";
                const dayHasLeague =
                  !curDay ||
                  allMatches.some(
                    (m) => m.leagueId === lid && dateKeyFromISO(m.date) === curDay
                  );
                const nextDate = dayHasLeague
                  ? curDay
                  : firstOrNextDateForLeague(
                      allMatches,
                      lid,
                      curDay || dateKeyFromISO(new Date().toISOString())
                    );
                onChangeFilters({ ...filters, league, date: nextDate });
              }}
            >
              <option value="">All</option>
              {leagues.map((l) => (
                <option key={l.id} value={String(l.id)}>
                  {l.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label>Date</label>
            <select
              value={dateValue}
              onChange={(e) => onChangeFilters({ ...filters, date: e.target.value })}

            >
               <option value="">All dates</option>
        {dateOptions.map((d) => (
          <option key={d} value={d}>{d}</option>
        ))}
            </select>
          </div>
        </div>
        <button
          className="scroll-btn"
          onClick={scrollPrev}
          title="Previous games"
        >
          ◀
        </button>
        <div className="match-scroller" ref={scrollerRef}>
          {visibleMatches.map((m) => {
            const when = new Date(m.date);
            const time = when.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            });
            const day = when.toLocaleDateString();
            const active = selectedMatchId === m.id;
            const pred = predictions[m.id];
            const isHomePicked = pred?.winner === "home";
            const isAwayPicked = pred?.winner === "away";
            const statusLabel =
              m.status === "live"
                ? "LIVE"
                : m.status === "final"
                ? "FINAL"
                : "UPCOMING";
            const mAny = m as any;
            const hid = mAny.homeTeamId as number | undefined;
            const aid = mAny.awayTeamId as number | undefined;
            const ha =
              hid != null
                ? teamAssets?.[m.leagueId]?.byId[hid]
                : teamAssets?.[m.leagueId]?.byName[m.home.name];
            const aa =
              aid != null
                ? teamAssets?.[m.leagueId]?.byId[aid]
                : teamAssets?.[m.leagueId]?.byName[m.away.name];
            const chipStyle: React.CSSProperties = ha?.primary_color
              ? { borderColor: ha.primary_color }
              : {};

            return (
              <button
                key={m.id}
                className={"match-chip " + (active ? "active" : "")}
                onClick={() => onSelectMatch(m.id)}
                title={`${m.home.name} vs ${m.away.name}`}
              >
                <div className="chip-top">
                  <span className={`chip-status ${m.status}`}>
                    {statusLabel}
                  </span>
                  <span className="chip-datetime">
                    {day} • {time}
                  </span>
                </div>
                <div
                  className={"chip-teamrow " + (isHomePicked ? "picked" : "")}
                >
                  {ha?.logo_url && (
                    <img src={ha.logo_url} alt="" className="team-logo chip" />
                  )}
                  <span className="team-name">
                    {normalizeName(m.home.name)}
                  </span>
                  {isHomePicked && pred?.spread != null && (
                    <span className="spread">+{pred.spread}</span>
                  )}
                  <span className="team-score">
                    {m.score ? m.score.home : ""}
                  </span>
                </div>
                <div
                  className={"chip-teamrow " + (isAwayPicked ? "picked" : "")}
                >
                  {aa?.logo_url && (
                    <img src={aa.logo_url} alt="" className="team-logo chip" />
                  )}
                  <span className="team-name">
                    {normalizeName(m.away.name)}
                  </span>
                  {isAwayPicked && pred?.spread != null && (
                    <span className="spread">+{pred.spread}</span>
                  )}
                  <span className="team-score">
                    {m.score ? m.score.away : ""}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
        <button className="scroll-btn" onClick={scrollNext} title="More games">
          ▶
        </button>
      </div>
    </div>
  );
}
