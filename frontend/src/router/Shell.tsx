import { NavLink, Outlet, useLocation } from "react-router-dom";

const primary = [
  { to: "/games/results", label: "Games" },
  { to: "/groups",        label: "Groups" },
  { to: "/leaderboard",   label: "Leaderboard" },
  { to: "/account",       label: "Account" },
];

function SecondaryNav() {
  const { pathname } = useLocation();
  const isGames  = pathname.startsWith("/games");
  const isGroups = pathname.startsWith("/groups");
  const isAcct   = pathname.startsWith("/account");

  const items = isGames
    ? [
        { to: "/games/results", label: "Results" },
        { to: "/games/table",   label: "Table" },
        { to: "/games/stats",   label: "Stats" },
      ]
    : isGroups
    ? [
        { to: "/groups/new",    label: "Create Group" },
        { to: "/groups",        label: "My Groups" },
      ]
    : isAcct
    ? [
        { to: "/account",        label: "Overview" },
        { to: "/account/settings", label: "Settings" },
        { to: "/account/signin",   label: "Sign in" },
        { to: "/account/signup",   label: "Sign up" },
      ]
    : [];

  return (
    <nav className="sidenav secondary">
      {items.map(i => (
        <NavLink key={i.to} to={i.to} className={({isActive}) => "navitem" + (isActive ? " active" : "")}>
          {i.label}
        </NavLink>
      ))}
    </nav>
  );
}

export default function Shell() {
  return (
    <div className="app-layout">
      <nav className="sidenav primary">
        {primary.map(i => (
          <NavLink key={i.to} to={i.to} className={({isActive}) => "navitem" + (isActive ? " active" : "")}>
            {i.label}
          </NavLink>
        ))}
      </nav>

      <SecondaryNav />

      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
