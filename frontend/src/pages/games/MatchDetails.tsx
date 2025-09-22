import { useEffect, useMemo, useRef, useState } from "react";
import "./Results.css";
import type { UIMatch } from "./types";
import { LANG } from "../../i18n";
import type { MatchFull } from "../../api/match";

type Bet = { winner: "home" | "away" | null; spread: number };
const HOME_ON_LEFT = true;

type PlayerRow = {
  player_id?: number | string;
  first_name?: string;
  last_name?: string;
  player?: string; 
  team_code?: string;
  team?: string;   
  minutes?: string | number | null; 
  pts?: number | null;
  ast?: number | null;
  reb?: number | null;
  stl?: number | null;
  blk?: number | null;
  fg3m?: number | null;
  plus_minus?: number | null;
};
function normalizeBoxPlayers(raw: any[] | undefined): PlayerRow[] {
  if (!raw) return [];
  return raw.map((p) => {
    let first = p.first_name, last = p.last_name;
    if (!first && !last && typeof p.player === "string") {
      const t = p.player.trim().split(/\s+/);
      first = t[0] || "";
      last = t.slice(1).join(" ") || "";
    }
    const team_code = p.team_code ?? p.team ?? undefined;
    return {
      player_id: p.player_id,
      first_name: first,
      last_name: last,
      team_code,
      minutes: p.minutes ?? null,
      pts: p.pts ?? null,
      ast: p.ast ?? null,
      reb: p.reb ?? null,
      stl: p.stl ?? null,
      blk: p.blk ?? null,
      fg3m: p.fg3m ?? null,
      plus_minus: p.plus_minus ?? null,
    };
  });
}
type TeamLeaders = {
  pts?: { name: string; value: number } | null;
  reb?: { name: string; value: number } | null;
  ast?: { name: string; value: number } | null;
  stl?: { name: string; value: number } | null;
  blk?: { name: string; value: number } | null;
  fg3m?: { name: string; value: number } | null;
};

function computeGameLeaders(
  players: PlayerRow[],
  homeCode?: string,
  awayCode?: string
): { home: TeamLeaders; away: TeamLeaders } {
  // קבץ לפי קוד קבוצה
  const byTeam = new Map<string, PlayerRow[]>();
  for (const p of players) {
    const k = (p.team_code || "UNK").toUpperCase();
    if (!byTeam.has(k)) byTeam.set(k, []);
    byTeam.get(k)!.push(p);
  }
  // אם אין קודים מה־assets, נבחר שני קודים הנפוצים ביותר
  const codes = Array.from(byTeam.keys());
  if (!homeCode || !awayCode) {
    const sorted = codes.sort((a, b) => (byTeam.get(b)!.length - byTeam.get(a)!.length));
    homeCode = homeCode || sorted[0];
    awayCode = awayCode || sorted[1];
  }

  function topOf(team: string | undefined, key: keyof PlayerRow) {
    if (!team) return null;
    const arr = byTeam.get(team.toUpperCase()) || [];
    let best: PlayerRow | null = null;
    for (const p of arr) {
      const val = (p[key] as number | null) ?? -Infinity;
      const bestVal = best ? ((best[key] as number | null) ?? -Infinity) : -Infinity;
      if (val > bestVal) best = p;
    }
    if (!best) return null;
    const value = (best[key] as number | null) ?? 0;
    const name = `${best.first_name ?? ""} ${best.last_name ?? ""}`.trim() || (best.player as string) || "";
    return { name, value };
  }

  const home = {
    pts: topOf(homeCode, "pts"),
    reb: topOf(homeCode, "reb"),
    ast: topOf(homeCode, "ast"),
    stl: topOf(homeCode, "stl"),
    blk: topOf(homeCode, "blk"),
    fg3m: topOf(homeCode, "fg3m"),
  };
  const away = {
    pts: topOf(awayCode, "pts"),
    reb: topOf(awayCode, "reb"),
    ast: topOf(awayCode, "ast"),
    stl: topOf(awayCode, "stl"),
    blk: topOf(awayCode, "blk"),
    fg3m: topOf(awayCode, "fg3m"),
  };
  return { home, away };
}

function StatLine({
  title,
  s,
}: {
  title: string;
  s?: Record<string, number | string | undefined>;
}) {
  if (!s) return null;
  const item = (k: string, label = k) =>
    s[k] != null ? (
      <li key={k}>
        {label}: {s[k] as any}
      </li>
    ) : null;
  return (
    <div className="card">
      <strong>{title}</strong>
      <ul>
        {item("PPG")}
        {item("RPG")}
        {item("APG")}
        {item("PTS")}
        {item("REB")}
        {item("AST")}
        {item("ST")}
        {item("BLK")}
        {item("TO")}
        {item("FG%", "FG%")}
        {item("3P%", "3P%")}
        {item("FT%", "FT%")}
        {item("3PTM")}
        {item("PPG".toLowerCase())}
        {item("RPG".toLowerCase())}
        {item("APG".toLowerCase())}
      </ul>
    </div>
  );
}
export default function MatchDetails({
  match,
  stats,
  prediction,
  onChange,
  matchFull,
  homeLogoUrl, awayLogoUrl,
}: {
  match: UIMatch;
  stats?: any;
  prediction?: Bet;
  onChange?: (next: Bet) => void;
  matchFull?: MatchFull;
  homeLogoUrl?: string;
  awayLogoUrl?: string;
}) {
  const [bet, setBet] = useState<Bet>(prediction ?? { winner: null, spread: 0 });
  const [pickerOpen, setPickerOpen] = useState(false);

  useEffect(() => {
    setBet(prediction ?? { winner: null, spread: 0 });
    setPickerOpen(false);
  }, [prediction, match.id]);

  function setAndNotify(next: Bet) {
    setBet(next);
    onChange?.(next);
  }

  const effectiveStatus = (matchFull?.match?.status || match.status || "scheduled").toLowerCase();
  const isStarted = effectiveStatus !== "scheduled" && effectiveStatus !== "postponed";
  const statusLabel =
    effectiveStatus === "live" ? "LIVE" :
    effectiveStatus === "final" ? "FINAL" : "UPCOMING";

  const centerWhen = useMemo(() => {
    const d = new Date(match.date);
    const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const day = d.toLocaleDateString(LANG === "he" ? "he-IL" : undefined);
    return `${day} • ${time}`;
  }, [match.date]);

  const liveScoreText = match.score ? `${match.score.home} : ${match.score.away}` : "";
  const homeLogoRight = HOME_ON_LEFT;
  const awayLogoRight = !HOME_ON_LEFT;
  const homeLogo = homeLogoUrl || "";
  const awayLogo = awayLogoUrl || "";
  const preOrSeason = matchFull?.pregame ?? matchFull?.season ?? undefined;
  const hs = preOrSeason?.home?.summary;
  const as = preOrSeason?.away?.summary;
  const hl = preOrSeason?.home?.leaders;
  const al = preOrSeason?.away?.leaders;
  const homeSummary = preOrSeason?.home?.summary;
  const awaySummary = preOrSeason?.away?.summary;
  const homeLeadersPre = preOrSeason?.home?.leaders;
  const awayLeadersPre = preOrSeason?.away?.leaders;
  const rawPlayers = matchFull?.boxscore?.players || [];
  const homeCode = matchFull?.assets?.home?.abbreviation as string | undefined;
  const awayCode = matchFull?.assets?.away?.abbreviation as string | undefined;
  const boxPlayers = normalizeBoxPlayers(rawPlayers);

  const gameLeaders = useMemo(
    () => (isStarted ? computeGameLeaders(boxPlayers, homeCode, awayCode) : null),
    [isStarted, boxPlayers, homeCode, awayCode]
    );  
  const mergedStats = useMemo(() => {
    const base = stats || {};
    const mapLeaders = (l: any) =>
      l ? {
        points:  l.pts ? { name: l.pts.player, value: l.pts.value } : null,
        rebounds:l.reb ? { name: l.reb.player, value: l.reb.value } : null,
        assists: l.ast ? { name: l.ast.player, value: l.ast.value } : null,
      } : undefined;

    return {
      ...base,
      homeTeamStats: hs ? { ppg: hs.ppg, rpg: hs.rpg, apg: hs.apg } : base.homeTeamStats,
      awayTeamStats: as ? { ppg: as.ppg, rpg: as.rpg, apg: as.apg } : base.awayTeamStats,
      homeLeaders: hl ? mapLeaders(hl) : base.homeLeaders,
      awayLeaders: al ? mapLeaders(al) : base.awayLeaders,
    };
  }, [stats, hs, as, hl, al]);

  const hasTeamStats = Boolean(mergedStats?.homeTeamStats && mergedStats?.awayTeamStats);
  const hasLeaders   = Boolean(mergedStats?.homeLeaders && mergedStats?.awayLeaders);

  const teamGame = matchFull?.team_game || null;


    return (
    <div className="match-details">
      <div className="details-main">
        <div className="details-meta">
          <span className={`chip-status ${effectiveStatus}`}>{statusLabel}</span>
          <span className="chip-datetime">{centerWhen}</span>
        </div>

        <div className="details-rows">
          <TeamCard
            side="home"
            name={match.home.name}
            logoUrl={homeLogo}
            record={stats?.homeRecord ?? "-"}
            selected={bet.winner === "home"}
            onPick={() => setAndNotify({ ...bet, winner: bet.winner === "home" ? null : "home" })}
            logoRight={homeLogoRight}
          />

          <div className="details-center">
            <button
              className="pick-pill"
              onClick={() => setPickerOpen((v) => !v)}
              aria-expanded={pickerOpen}
              title="Set spread"
            >
              {bet.winner ? `My pick: ${bet.winner.toUpperCase()} +${bet.spread}` : "Pick winner & spread"}
            </button>

            {pickerOpen && (
              <SpreadPicker
                value={bet.spread}
                onChange={(v) => setAndNotify({ ...bet, spread: v })}
                onClose={() => setPickerOpen(false)}
              />
            )}

            {liveScoreText && <div className="live-score">{liveScoreText}</div>}
          </div>

          <TeamCard
            side="away"
            name={match.away.name}
            logoUrl={awayLogo}
            record={stats?.awayRecord ?? "-"}
            selected={bet.winner === "away"}
            onPick={() => setAndNotify({ ...bet, winner: bet.winner === "away" ? null : "away" })}
            logoRight={awayLogoRight}
          />
        </div>

        {/* --- PRE-GAME: סטטיסטיקות קבוצה עשירות + מובילים עד עכשיו --- */}
        {!isStarted && (
          <>
            <div className="stats-grid" style={{ marginTop: 12 }}>
              <StatLine title={`${match.home.name} — Team stats to date`} s={homeSummary as any} />
              <StatLine title={`${match.away.name} — Team stats to date`} s={awaySummary as any} />
            </div>

            {(homeLeadersPre || awayLeadersPre) && (
              <div className="leaders-grid" style={{ marginTop: 12 }}>
                <div className="card">
                  <strong>{match.home.name} — Leaders to date</strong>
                  <ul>
                    {homeLeadersPre?.pts && <li>PTS: {homeLeadersPre.pts.player} ({homeLeadersPre.pts.value})</li>}
                    {homeLeadersPre?.reb && <li>REB: {homeLeadersPre.reb.player} ({homeLeadersPre.reb.value})</li>}
                    {homeLeadersPre?.ast && <li>AST: {homeLeadersPre.ast.player} ({homeLeadersPre.ast.value})</li>}
                    {homeLeadersPre?.st  && <li>ST:  {homeLeadersPre.st.player}  ({homeLeadersPre.st.value})</li>}
                    {homeLeadersPre?.blk && <li>BLK: {homeLeadersPre.blk.player} ({homeLeadersPre.blk.value})</li>}
                    {homeLeadersPre?.fg3m && <li>3PTM: {homeLeadersPre.fg3m.player} ({homeLeadersPre.fg3m.value})</li>}
                  </ul>
                </div>
                <div className="card">
                  <strong>{match.away.name} — Leaders to date</strong>
                  <ul>
                    {awayLeadersPre?.pts && <li>PTS: {awayLeadersPre.pts.player} ({awayLeadersPre.pts.value})</li>}
                    {awayLeadersPre?.reb && <li>REB: {awayLeadersPre.reb.player} ({awayLeadersPre.reb.value})</li>}
                    {awayLeadersPre?.ast && <li>AST: {awayLeadersPre.ast.player} ({awayLeadersPre.ast.value})</li>}
                    {awayLeadersPre?.st  && <li>ST:  {awayLeadersPre.st.player}  ({awayLeadersPre.st.value})</li>}
                    {awayLeadersPre?.blk && <li>BLK: {awayLeadersPre.blk.player} ({awayLeadersPre.blk.value})</li>}
                    {awayLeadersPre?.fg3m && <li>3PTM: {awayLeadersPre.fg3m.player} ({awayLeadersPre.fg3m.value})</li>}
                  </ul>
                </div>
              </div>
            )}
          </>
        )}

        {/* --- IN/POST-GAME: For/Against, מובילי משחק בפועל, בוקס-סקור --- */}
        {isStarted && (
          <>
            {teamGame && (
              <div className="stats-grid" style={{ marginTop: 12 }}>
                <StatLine title={`${match.home.name} — Game stats (For)`} s={teamGame.home?.for as any} />
                <StatLine title={`${match.away.name} — Game stats (For)`} s={teamGame.away?.for as any} />
              </div>
            )}

            {gameLeaders && (
              <div className="leaders-grid" style={{ marginTop: 12 }}>
                <div className="card">
                  <strong>{match.home.name} — Game leaders</strong>
                  <ul>
                    {gameLeaders.home.pts && <li>PTS: {gameLeaders.home.pts.name} ({gameLeaders.home.pts.value})</li>}
                    {gameLeaders.home.reb && <li>REB: {gameLeaders.home.reb.name} ({gameLeaders.home.reb.value})</li>}
                    {gameLeaders.home.ast && <li>AST: {gameLeaders.home.ast.name} ({gameLeaders.home.ast.value})</li>}
                    {gameLeaders.home.stl && <li>ST:  {gameLeaders.home.stl.name} ({gameLeaders.home.stl.value})</li>}
                    {gameLeaders.home.blk && <li>BLK: {gameLeaders.home.blk.name} ({gameLeaders.home.blk.value})</li>}
                    {gameLeaders.home.fg3m && <li>3PTM: {gameLeaders.home.fg3m.name} ({gameLeaders.home.fg3m.value})</li>}
                  </ul>
                </div>
                <div className="card">
                  <strong>{match.away.name} — Game leaders</strong>
                  <ul>
                    {gameLeaders.away.pts && <li>PTS: {gameLeaders.away.pts.name} ({gameLeaders.away.pts.value})</li>}
                    {gameLeaders.away.reb && <li>REB: {gameLeaders.away.reb.name} ({gameLeaders.away.reb.value})</li>}
                    {gameLeaders.away.ast && <li>AST: {gameLeaders.away.ast.name} ({gameLeaders.away.ast.value})</li>}
                    {gameLeaders.away.stl && <li>ST:  {gameLeaders.away.stl.name} ({gameLeaders.away.stl.value})</li>}
                    {gameLeaders.away.blk && <li>BLK: {gameLeaders.away.blk.name} ({gameLeaders.away.blk.value})</li>}
                    {gameLeaders.away.fg3m && <li>3PTM: {gameLeaders.away.fg3m.name} ({gameLeaders.away.fg3m.value})</li>}
                  </ul>
                </div>
              </div>
            )}

            {boxPlayers.length > 0 && (
              <div className="card" style={{ marginTop: 12, overflowX: "auto" }}>
                <strong>Box Score</strong>
                <table className="table compact" style={{ width: "100%", marginTop: 8 }}>
                  <thead>
                    <tr>
                      <th style={{ textAlign: "left" }}>Player</th>
                      <th>Team</th>
                      <th>Min</th>
                      <th>PTS</th>
                      <th>REB</th>
                      <th>AST</th>
                      <th>STL</th>
                      <th>BLK</th>
                      <th>3PM</th>
                      <th>+/-</th>
                    </tr>
                  </thead>
                  <tbody>
                    {boxPlayers.map((p, idx) => (
                      <tr key={`${p.player_id ?? idx}`}>
                        <td style={{ textAlign: "left" }}>
                          {[(p.first_name || ""), (p.last_name || "")].join(" ").trim() || (p.player || "")}
                        </td>
                        <td>{p.team_code ?? "-"}</td>
                        <td>{p.minutes ?? "-"}</td>
                        <td>{p.pts ?? "-"}</td>
                        <td>{p.reb ?? "-"}</td>
                        <td>{p.ast ?? "-"}</td>
                        <td>{p.stl ?? "-"}</td>
                        <td>{p.blk ?? "-"}</td>
                        <td>{p.fg3m ?? "-"}</td>
                        <td>{p.plus_minus ?? "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function TeamCard({
  side, name, logoUrl, record, selected, onPick, logoRight,
}: {
  side: "home" | "away";
  name: string;
  logoUrl?: string;
  record?: string;
  selected: boolean;
  onPick: () => void;
  logoRight: boolean;
}) {
  return (
    <button
      className={
        "team-card " +
        (selected ? "selected " : "") +
        (logoRight ? "logo-right " : "")
      }
      onClick={onPick}
      aria-pressed={selected}
      title={`Pick ${name}`}
    >
      <img className="team-logo" src={logoUrl} alt="" />
      <div className="team-text">
        <div className="team-name-lg">{name}</div>
        {record && <div className="team-record subtle">{record}</div>}
      </div>
    </button>
  );
}

function SpreadPicker({
  value, onChange, onClose,
}: {
  value: number;
  onChange: (v: number) => void;
  onClose: () => void;
}) {
  const [local, setLocal] = useState(value);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => setLocal(value), [value]);

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLButtonElement>(".picker-item.active");
    el?.scrollIntoView({ block: "center" });
  }, []);

  const clamp = (n: number) => Math.max(0, Math.min(99, n));
  const commit = (n: number) => { onChange(clamp(n)); onClose(); };

  function onKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "ArrowUp")   { e.preventDefault(); setLocal((v) => clamp(v + 1)); }
    if (e.key === "ArrowDown") { e.preventDefault(); setLocal((v) => clamp(v - 1)); }
    if (e.key === "Enter")     { e.preventDefault(); commit(local); }
    if (e.key === "Escape")    { e.preventDefault(); onClose(); }
  }

  const items = Array.from({ length: 100 }, (_, i) => i);

  return (
    <div className="picker-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="picker" onClick={(e) => e.stopPropagation()}>
        <div className="picker-controls">
          <input
            className="picker-input"
            type="number"
            min={0}
            max={99}
            value={local}
            onChange={(e) => setLocal(clamp(Number(e.target.value) || 0))}
            onKeyDown={onKey}
            aria-label="Spread"
          />
          <div className="picker-actions">
            <button className="itembtn" onClick={() => setLocal((v) => clamp(v - 1))}>−</button>
            <button className="itembtn" onClick={() => setLocal((v) => clamp(v + 1))}>+</button>
            <button className="itembtn" onClick={() => commit(local)}>Set</button>
          </div>
        </div>

        <div className="picker-window" />
        <div className="picker-list" ref={listRef} tabIndex={0}>
          {items.map((n) => (
            <button
              key={n}
              className={"picker-item " + (n === local ? "active" : "")}
              onClick={() => commit(n)}
            >
              {n}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
