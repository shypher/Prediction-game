import { MOCK_GROUPS } from "./MockGroups";

export default function MyGroupsList({ onOpenGroup }: { onOpenGroup: (id: string) => void }) {
  return (
    <>
      <h2>My groups</h2>
      <div className="grid">
        {MOCK_GROUPS.map(g => (
          <div className="card" key={g.id}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom: 8 }}>
              <strong>{g.name}</strong>
              <span className="subtle">{g.members.length} members</span>
            </div>
            <button className="itembtn" onClick={() => onOpenGroup(g.id)}>Open overview</button>
          </div>
        ))}
      </div>
    </>
  );
}
