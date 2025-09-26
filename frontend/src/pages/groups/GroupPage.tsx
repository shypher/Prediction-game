// src/pages/GroupsPage.tsx
import { useEffect, useState } from "react";
import "./Results.css";
import {
  createGroup, joinGroup, regenInvite, leaveGroup,
  type GroupOut,
  fetchMyGroups,         
  type MyGroupOut,        
} from "../../api/groups";
import { useNavigate } from "react-router-dom";

export default function GroupsPage() {
  const nav = useNavigate();

  const [groups, setGroups] = useState<MyGroupOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // --- טען את הקבוצות של המשתמש ---
  useEffect(() => {
    const ac = new AbortController();
    (async () => {
      try {
        setLoading(true); setErr(null);
        const data = await fetchMyGroups(ac.signal);
        setGroups(data);
      } catch (e: any) {
        // אם לא מחובר/פג תוקף → 401
        if (e?.status === 401) {
          // נווט למסך התחברות (או הצג הודעה)
          nav("/login?next=/groups");
          return;
        }
        setErr(e?.message || "Failed to load your groups");
      } finally {
        setLoading(false);
      }
    })();
    return () => ac.abort();
  }, [nav]);

  // --- יצירת קבוצה / הצטרפות נשארים כמו קודם ---
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [isPrivate, setIsPrivate] = useState(true);

  async function onCreate() {
    if (!name.trim()) return;
    setCreating(true); setErr(null);
    try {
      const g = await createGroup({ name: name.trim(), is_private: isPrivate });
      // רענון רשימה:
      setGroups(prev => [{ ...g, role: "owner" } as any, ...prev]);
      setName(""); setIsPrivate(true);
    } catch (e: any) {
      setErr(e?.message || "Failed to create group");
    } finally {
      setCreating(false);
    }
  }

  const [joinId, setJoinId] = useState<number | "">("");
  const [invite, setInvite] = useState("");
  async function onJoin() {
    if (!joinId) return;
    setErr(null);
    try {
      const g = await joinGroup(Number(joinId), invite || undefined);
      // רענון (אפשר גם לקרוא שוב fetchMyGroups)
      setGroups(prev => {
        const exists = prev.some(x => x.id === g.id);
        return exists ? prev : [...prev, { ...g, role: "member" } as any];
      });
      setInvite(""); setJoinId("");
    } catch (e: any) {
      setErr(e?.message || "Failed to join group");
    }
  }

  async function onRegenInvite(id: number) {
    try {
      const r = await regenInvite(id);
      alert(`New invite code: ${r.invite_code}`);
    } catch (e: any) {
      alert(e?.message || "Failed to regenerate invite");
    }
  }

  async function onLeave(id: number) {
    if (!confirm("Leave this group?")) return;
    try {
      await leaveGroup(id);
      setGroups(prev => prev.filter(g => g.id !== id));
    } catch (e: any) {
      alert(e?.message || "Failed to leave group");
    }
  }

  return (
    <div className="results-root">
      <div className="card" style={{display:"grid", gap:8}}>
        <strong>Create a new group</strong>
        <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
          <input placeholder="Group name" value={name} onChange={e=>setName(e.target.value)} />
          <label style={{display:"flex", alignItems:"center", gap:6}}>
            <input type="checkbox" checked={isPrivate} onChange={e=>setIsPrivate(e.target.checked)} />
            Private (invite code)
          </label>
          <button className="chip" onClick={onCreate} disabled={creating}>Create</button>
        </div>
        {err && <div className="subtle">Error: {err}</div>}
      </div>

      <div className="card" style={{display:"grid", gap:8}}>
        <strong>Join by group id</strong>
        <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
          <input placeholder="Group ID" value={joinId} onChange={e=>setJoinId((e.target.value as any))} />
          <input placeholder="Invite code (if required)" value={invite} onChange={e=>setInvite(e.target.value)} />
          <button className="chip" onClick={onJoin}>Join</button>
        </div>
      </div>

      <div className="card">
        <strong>Your groups</strong>
        {loading && <div className="subtle" style={{marginTop:6}}>Loading…</div>}
        {!loading && groups.length === 0 && (
          <div className="subtle" style={{marginTop:6}}>No groups yet.</div>
        )}
        <div style={{marginTop:8, display:"grid", gap:8}}>
          {groups.map(g => (
            <div key={g.id} className="row" style={{display:"flex", alignItems:"center", gap:8}}>
              <div style={{flex:1}}>
                <a className="link" href={`/groups/${g.id}`}>{g.name}</a>
                <div className="subtle">Role: {g.role} {g.is_private ? "• Private" : "• Public"}</div>
              </div>
              {g.role === "owner" && (
                <button className="chip" onClick={()=>onRegenInvite(g.id)}>Regen invite</button>
              )}
              <button className="chip" onClick={()=>onLeave(g.id)}>Leave</button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
