export default function CreateGroup() {
  return (
    <>
      <h2>Create group</h2>
      <div className="card" style={{ maxWidth: 420 }}>
        <label>Group name</label>
        <input placeholder="e.g., Friends League" />
        <label>Description (optional)</label>
        <input placeholder="Short description..." />
        <div style={{ display:"flex", gap: 8, marginTop: 8 }}>
          <button className="itembtn">Create</button>
          <span className="subtle">* UI only for now.</span>
        </div>
      </div>
    </>
  );
}
