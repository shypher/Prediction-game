import type { Group } from "../../types";

export default function GroupOverview({ group, onBack }: { group: Group; onBack: () => void }) {
  return (
    <>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <h2 style={{ margin: 0 }}>{group.name} — Overview</h2>
        <div style={{ display:"flex", gap: 8 }}>
          <button className="itembtn" onClick={() => alert("Settings (later)")}>Settings</button>
          <button className="itembtn" onClick={onBack}>Back to my groups</button>
        </div>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <strong>Players</strong>
        <ul>{group.members.map(m => <li key={m}>{m}</li>)}</ul>
      </div>
    </>
  );
}
