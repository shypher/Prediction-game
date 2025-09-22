import { useEffect, useMemo, useState } from "react";
import ResultsHeader, { type ResultsFilters } from "./ResultsHeader";
import MatchDetails from "./MatchDetails";
import "./Results.css";
import MobileMatchList from "./MobileMatchList";
import type { UIMatch } from "./types";
import { fetchUINextMatches } from "../../api/games";
import { fetchTeamsAssets, type TeamAsset } from "../../api/teams";
import { fetchMatchFull, type MatchFull } from "../../api/match";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";

type Prediction = { winner: "home" | "away" | null; spread: number };

type LeagueAssets = {
  byName: Record<string, TeamAsset>;
  byId: Record<number, TeamAsset>;
};

type AssetsMap = Record<number, LeagueAssets>;

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

const EL_ALIASES: Record<string, string> = {
  "milan": "olimpia milano",
  "ea7 emporio armani milan": "olimpia milano",
  "fc barcelona": "barcelona",
  "bayern munich": "bayern munich",
  "asvel villeurbanne": "asvel",
  "ldlc asvel villeurbanne": "asvel",
  "partizan belgrade": "partizan",
  "crvena zvezda belgrade": "crvena zvezda belgrade",
  "fenerbahce istanbul": "fenerbahce",
  "panathinaikos athens": "panathinaikos athens",
  "anadolu efes ": "anadolu efes",
  "olympiacos piraeus": "olympiacos",
  "baskonia vitoria": "baskonia vitoria",
  "zalgiris kaunas": "zalgiris",
  "valencia basket": "valencia",
  "paris basketball": "paris",
  "hapoel tel aviv": "hapoel tel aviv",
  "maccabi tel aviv": "maccabi tel aviv",
  "dubai basketball": "dubai basketball",
  "virtus bologna": "virtus bologna",
  "as monaco": "as monaco",
  "real madrid": "real madrid",
};

function applyAlias(k: string): string {
  if (!k) return k;
  const low = k.toLowerCase();
  return EL_ALIASES[low] ?? k;
}

function sameDayISO(matchISO: string, day: string) {
  if (!day) return true;
  const m = matchISO.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}` === day;
  const a = new Date(matchISO);
  const y = a.getFullYear();
  const mm = String(a.getMonth() + 1).padStart(2, "0");
  const dd = String(a.getDate()).padStart(2, "0");
  return `${y}-${mm}-${dd}` === day;
}

export default function ResultsPage() {
  const [filters, setFilters] = useState<ResultsFilters>({
    league: "",
    date: "",
  });
  const [allMatches, setAllMatches] = useState<UIMatch[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const visibleMatches = useMemo(() => {
    if (!allMatches) return [];
    return allMatches.filter((m) => {
      const byLeague = !filters.league || m.leagueId === Number(filters.league);
      const byDate = sameDayISO(m.date, filters.date);
      return byLeague && byDate;
    });
  }, [allMatches, filters]);

  const isMobile = useIsMobile();
  const [selectedMatchId, setSelectedMatchId] = useState<number | null>(null);

  useEffect(() => {
    const ac = new AbortController();
    (async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await fetchUINextMatches(
          { limit: 2000, daysAfter: 365, daysBefore: 120 },
          ac.signal
        );
        setAllMatches(data as UIMatch[]);
      } catch (e: any) {
        if (e?.name !== "AbortError") setError(e?.message || "Failed to load");
      } finally {
        setLoading(false);
      }
    })();
    return () => ac.abort();
  }, []);

  const [predictions, setPredictions] = useState<Record<number, Prediction>>(
    {}
  );
  function upsertPrediction(matchId: number, next: Prediction) {
    setPredictions((prev) => ({ ...prev, [matchId]: next }));
  }

  const [viewMode, setViewMode] = useState<"list" | "details">(
    isMobile ? "list" : "details"
  );
  useEffect(() => {
    setViewMode(isMobile ? "list" : "details");
  }, [isMobile]);

  function handleSelectMatch(id: number) {
    setSelectedMatchId(id);
    if (isMobile) setViewMode("details");
  }

  const selectedMatch =
    visibleMatches.find((m) => m.id === selectedMatchId) ??
    visibleMatches[0] ??
    null;

  const [assets, setAssets] = useState<AssetsMap>({});
  useEffect(() => {
    if (!allMatches) return;
    const leagues = Array.from(new Set(allMatches.map((m) => m.leagueId)));
    if (!leagues.length) return;
    const ctrl = new AbortController();
    Promise.all(
      leagues.map((lid) =>
        fetchTeamsAssets(lid, ctrl.signal).then((list) => [lid, list] as const)
      )
    )
      .then((pairs) => {
        const next: AssetsMap = {};
        for (const [lid, list] of pairs) {
          const byName: Record<string, TeamAsset> = {};
          const byId: Record<number, TeamAsset> = {};
          for (const a of list) {
            const key = normalizeName(applyAlias(a.name));
            byName[key] = a;
            if (a.id != null) byId[a.id] = a as any;
          }
          if (lid === 120) {
            for (const [alias, canonical] of Object.entries(EL_ALIASES)) {
              const ckey = normalizeName(canonical);
              if (byName[ckey] && !byName[alias]) byName[alias] = byName[ckey];
            }
          }
          next[lid] = { byName, byId };
        }
        setAssets(next);
      })
      .catch(() => {});
    return () => ctrl.abort();
  }, [allMatches]);

  const [matchFull, setMatchFull] = useState<Record<number, MatchFull>>({});
  useEffect(() => {
    if (!selectedMatchId) return;
    const ctrl = new AbortController();
    fetchMatchFull(selectedMatchId, ctrl.signal)
      .then((data) =>
        setMatchFull((prev) => ({ ...prev, [selectedMatchId]: data }))
      )
      .catch(() => {});
    return () => ctrl.abort();
  }, [selectedMatchId]);

  useEffect(() => {
    if (!visibleMatches.length) {
      setSelectedMatchId(null);
      return;
    }
    if (
      selectedMatchId == null ||
      !visibleMatches.some((m) => m.id === selectedMatchId)
    ) {
      setSelectedMatchId(visibleMatches[0].id);
    }
  }, [visibleMatches, selectedMatchId]);

  const norm = (s: string) => normalizeName(applyAlias(s));
  const leagueAssets = selectedMatch ? assets[selectedMatch.leagueId] : undefined;
  const homeLogoUrl =
    selectedMatch && leagueAssets
      ? leagueAssets.byName[norm(selectedMatch.home.name)]?.logo_url || ""
      : "";
  const awayLogoUrl =
    selectedMatch && leagueAssets
      ? leagueAssets.byName[norm(selectedMatch.away.name)]?.logo_url || ""
      : "";

  return (
    <>
      {(!isMobile || viewMode === "list") && (
        <ResultsHeader
          allMatches={allMatches ?? []}
          filters={filters}
          onChangeFilters={setFilters}
          visibleMatches={visibleMatches}
          predictions={predictions}
          selectedMatchId={selectedMatchId ?? null}
          onSelectMatch={handleSelectMatch}
          teamAssets={assets}
        />
      )}

      {loading && <div className="card">Loading games…</div>}
      {error && !loading && <div className="card">Error: {error}</div>}

      {selectedMatch && !(isMobile && viewMode === "list") && (
        <MatchDetails
          key={selectedMatch.id}   
          match={selectedMatch}
          prediction={predictions[selectedMatch.id]}
          onChange={(next) => upsertPrediction(selectedMatch.id, next)}
          stats={{ homeRecord: null, awayRecord: null }}
          matchFull={matchFull[selectedMatch.id]}
          homeLogoUrl={homeLogoUrl}
          awayLogoUrl={awayLogoUrl}
        />
      )}

      {!selectedMatch && !loading && !error && (
        <div className="card">No matches for the selected filters.</div>
      )}
    </>
  );
}

function useIsMobile(breakpoint = 900) {
  const [isMobile, setIsMobile] = useState<boolean>(
    () => window.innerWidth <= breakpoint
  );
  useEffect(() => {
    const mql = window.matchMedia(`(max-width:${breakpoint}px)`);
    const onChange = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    if (mql.addEventListener) mql.addEventListener("change", onChange);
    else mql.addListener(onChange);
    setIsMobile(mql.matches);
    return () => {
      if (mql.removeEventListener) mql.removeEventListener("change", onChange);
      else mql.removeListener(onChange);
    };
  }, [breakpoint]);
  return isMobile;
}
