import { Routes, Route, Navigate, useNavigate, useParams } from "react-router-dom";
import MyGroupsList from "./groups/MyGroupsList";
import GroupOverview from "./groups/GroupOverview";
import CreateGroup from "./groups/CreateGroup";
import { MOCK_GROUPS } from "./groups/MockGroups";
import ResultsPage from "./games/ResultsPage";
import TablePage from "./games/TablePage";
import GamesStatsPage from "./games/GamesStatsPage";
import GroupsPage from "./groups/CreateGroup";
import GroupLeaderboardPage from "./groups/GroupLeaderboardPage";
function Placeholder({ title, note }: { title: string; note?: string }) {
  return (
    <>
      <h2>{title}</h2>
      <div className="card">
        <p className="subtle">{note || "Placeholder screen"}</p>
      </div>
    </>
  );
}

function GroupsIndexRoute() {
  const navigate = useNavigate();
  return <MyGroupsList onOpenGroup={(id) => navigate(`/groups/${id}`)} />;
}
function GroupOverviewRoute() {
  const navigate = useNavigate();
  const { groupId } = useParams();
  const g = MOCK_GROUPS.find((x) => x.id === groupId);
  if (!g) return <div className="card">Group not found.</div>;
  return <GroupOverview group={g} onBack={() => navigate("/groups")} />;
}

export default function Content() {

  return (
    <Routes>
      {/* Home / Overview & Updates */}
      <Route path="/" element={<Navigate to="/overview" replace />} />
      <Route path="/overview" element={<Placeholder title="Home overview" note="Today’s games & your status" />} />
      <Route path="/updates" element={<Placeholder title="Updates" note="Changelog / messages" />} />

      {/* Games */}
      <Route path="/games/results" element={<ResultsPage />} />
      <Route path="/games/results/:matchId" element={<ResultsPage />} />
      <Route path="/games/table" element={<TablePage />} />
      <Route path="/games/stats" element={<GamesStatsPage leagueId={120} season={2025} />} />

      {/* Groups */}
      <Route path="/groups" element={<GroupsPage />} />
      <Route path="/groups/:groupId" element={<GroupLeaderboardPage />} />
      <Route path="/groups/new" element={<CreateGroup />} />

      {/* Admin (ניהול) */}
      <Route path="/admin/users" element={<Placeholder title="Admin: Users" note="Manage users (later)" />} />
      <Route path="/admin/matches-admin" element={<Placeholder title="Admin: Matches" note="Create/edit matches (later)" />} />
      <Route path="/admin/sources" element={<Placeholder title="Admin: Sources" note="Jobs/logs (later)" />} />

      {/* Account */}
      <Route path="/account/profile" element={<Placeholder title="Profile" note="User info & preferences" />} />
      <Route path="/account/security" element={<Placeholder title="Security" note="Password / 2FA" />} />
      <Route path="/account/notifications" element={<Placeholder title="Notifications" note="Email / push settings" />} />

      {/* Fallback */}
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}