import "./Results.css";
import type { Match } from "./mock";

type Prediction = { winner: "home" | "away" | null; spread: number };

export default function MobileMatchList({
  matches,
  predictions,
  onSelect,
}: {
  matches: Match[];
  predictions: Record<string, Prediction>;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="results-list">
      {matches.map((m) => {
        const pred = predictions[m.id];
        const homeSel = pred?.winner === "home";
        const awaySel = pred?.winner === "away";
        const d = new Date(m.date);
        const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        const day = d.toLocaleDateString("he-IL");
        const status = m.status === "live" ? "LIVE" : m.status === "final" ? "FINAL" : "UPCOMING";

        return (
          <button key={m.id} className="mobile-match-card" onClick={() => onSelect(m.id)}>
            <div className="chip-top">
              <span className={`chip-status ${m.status}`}>{status}</span>
              <span className="chip-datetime">{day} • {time}</span>
            </div>

            <div className="details-rows">
              <div className={"team-card " + (homeSel ? "selected " : "") + "logo-right"}>
                <div className="team-logo">{m.home.emoji ?? "🔷"}</div>
                <div className="team-text">
                  <div className="team-name-lg">{m.home.name}</div>
                </div>
              </div>

              <div className="details-center">
                {m.score && <div className="live-score">{m.score.home} : {m.score.away}</div>}
              </div>

              <div className={"team-card " + (awaySel ? "selected " : "")}>
                <div className="team-logo">{m.away.emoji ?? "🔶"}</div>
                <div className="team-text">
                  <div className="team-name-lg">{m.away.name}</div>
                </div>
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}
