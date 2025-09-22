import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Shell from "./Shell";
import App from "../App"; 
import ResultsPage from "../pages/games/ResultsPage";
import TablePage from "../pages/games/TablePage";
const StatsPage = () => <div className="card">Stats — coming soon</div>;

const GroupsIndex = () => <div className="card">My Groups</div>;
const GroupNew = () => <div className="card">Create Group</div>;
const GroupOverview = () => <div className="card">Group Overview</div>;
const GroupPlayers = () => <div className="card">Group Players</div>;
const GroupSettings = () => <div className="card">Group Settings</div>;

const LeaderboardPage = () => <div className="card">Leaderboard</div>;

const AccountOverview = () => <div className="card">Account Overview</div>;
const AccountSettings = () => <div className="card">Account Settings</div>;
const SignIn = () => <div className="card">Sign in</div>;
const SignUp = () => <div className="card">Sign up</div>;

export default function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<Navigate to="/games/results" replace />} />

          {/* Games */}
          <Route path="games">
            <Route index element={<Navigate to="results" replace />} />
            <Route path="results">
              <Route index element={<ResultsPage />} />
              <Route path=":matchId" element={<ResultsPage />} />
            </Route>
            <Route path="table" element={<TablePage />} />
            <Route path="stats" element={<StatsPage />} />
          </Route>

          {/* Groups */}
          <Route path="groups">
            <Route index element={<GroupsIndex />} />
            <Route path="new" element={<GroupNew />} />
            <Route path=":groupId">
              <Route index element={<GroupOverview />} />
              <Route path="players" element={<GroupPlayers />} />
              <Route path="settings" element={<GroupSettings />} />
            </Route>
          </Route>

          {/* Leaderboard */}
          <Route path="leaderboard" element={<LeaderboardPage />} />

          {/* Account */}
          <Route path="account">
            <Route index element={<AccountOverview />} />
            <Route path="settings" element={<AccountSettings />} />
            <Route path="signin" element={<SignIn />} />
            <Route path="signup" element={<SignUp />} />
          </Route>

          {/* fallback */}
          <Route path="*" element={<Navigate to="/games/results" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
