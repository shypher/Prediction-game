import { useMemo, useRef, useEffect } from "react";
import type { UIMatch } from "./types";
import "./Results.css";

export type ResultsFilters = { league: string; date: string };

type Prediction = { winner: "home" | "away" | null; spread: number };
function normalizeName(s: string): string {
  const x = s
    .normalize("NFD")
    .toLowerCase();
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
    "athens","gasteiz", "piraeus"
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
    return allMatches.filter(m => m.leagueName === filters.league);

  }, [allMatches, filters.league]);
  const todayKey = useMemo(() => {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${dd}`;
}, []);
  const dateOptions = useMemo(() => {
  const set = new Set<string>();
  for (const m of leagueMatches) {
    const d = new Date(m.date);
    const y = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    set.add(`${y}-${mm}-${dd}`);
  }
  const values = Array.from(set).sort(); // עולה
  return values.map(v => {
    const [yy, mm, dd] = v.split("-").map(Number);
    const label = new Date(yy, mm - 1, dd).toLocaleDateString("he-IL", {
      weekday: "short", month: "numeric", day: "numeric"
    });
    return { value: v, label };
  });
}, [leagueMatches]);
  useEffect(() => {
  if (!filters.league) return;           
  if (!dateOptions.length) return;       
  const hasCurrent = !!dateOptions.find(o => o.value === filters.date);
  if (hasCurrent) return;           

  const next =
    dateOptions.find(o => o.value >= todayKey)?.value
    ?? dateOptions[dateOptions.length - 1].value;

  if (next !== filters.date) {
    onChangeFilters({ ...filters, date: next });
  }
}, [filters.league, dateOptions, todayKey]);
  useEffect(() => {
  if (filters.date) return;
  if (!dateOptions.length) return;
  const today = new Date();
  const todayKey = dateKeyFromISO(today.toISOString());
  const next = dateOptions.find(o => o.value >= todayKey)?.value ?? dateOptions[0].value;
  onChangeFilters({ ...filters, date: next });
}, [dateOptions]);
  return (
    <div className="results-header">
      <div className="results-header-grid">
        <div className="filters">
          <div>
            <label>League</label>
            <select
              value={filters.league}
              onChange={(e) =>
                onChangeFilters({ ...filters, league: e.target.value })
              }
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
              value={filters.date}
              onChange={(e) =>
                onChangeFilters({ ...filters, date: e.target.value })
              }
            >
              <option value="">All dates</option>
              {dateOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
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
                  <span className="team-name">{normalizeName(m.home.name)}</span>
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
                  <span className="team-name">{normalizeName(m.away.name)}</span>
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
