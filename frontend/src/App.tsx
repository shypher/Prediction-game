import { useMemo, useState } from "react";
import "./App.css";
import { LANG, dirFor } from "./i18n";
import { SECONDARY, defaultSecondaryOf } from "./menu";
import type { PrimaryKey, SecondaryKey } from "./types";
import { useNavigate } from "react-router-dom";

import PrimaryNav from "./layout/PrimaryNav";
import SecondaryNav from "./layout/SecondaryNav";
import Content from "./pages/Content";

export default function App() {
  const navigate = useNavigate();

  // ⬇️ Keep your existing state to preserve styling/hover behavior
  const [activePrimary, setActivePrimary] = useState<PrimaryKey>("home");
  const [secondaryPrimary, setSecondaryPrimary] = useState<PrimaryKey>("home");
  const [activeSecondary, setActiveSecondary] = useState<SecondaryKey>(defaultSecondaryOf("home"));
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  const secondaryItems = useMemo(() => SECONDARY[secondaryPrimary], [secondaryPrimary]);
  const dir = dirFor(LANG);

  // map your primary/secondary to URL paths — minimal and explicit
  function pathFor(p: PrimaryKey, s?: SecondaryKey, groupId?: string | null): string {
    if (p === "home") {
      if (s === "updates") return "/updates";
      return "/overview"; // default
    }
    if (p === "games") {
      if (s === "table") return "/games/table";
      if (s === "stats") return "/games/stats";
      return "/games/results"; // default
    }
    if (p === "groups") {
      if (s === "create-group") return "/groups/new";
      if (groupId) return `/groups/${groupId}`;
      return "/groups"; // default list
    }
    if (p === "admin") {
      if (s === "matches-admin") return "/admin/matches-admin";
      if (s === "sources") return "/admin/sources";
      return "/admin/users"; // default
    }
    if (p === "account") {
      if (s === "security") return "/account/security";
      if (s === "notifications") return "/account/notifications";
      return "/account/profile"; // default
    }
    return "/overview";
  }

  function handlePrimaryClick(p: PrimaryKey) {
    const s = defaultSecondaryOf(p);
    setActivePrimary(p);
    setSecondaryPrimary(p);
    setActiveSecondary(s);
    setSelectedGroupId(null);
    navigate(pathFor(p, s));
  }

  function handlePrimaryHover(p: PrimaryKey) {
    setSecondaryPrimary(p);
  }

  function handleSecondaryClick(s: SecondaryKey) {
    if (activePrimary !== secondaryPrimary) setActivePrimary(secondaryPrimary);
    setActiveSecondary(s);
    navigate(pathFor(secondaryPrimary, s, selectedGroupId));
  }

  return (
    <div className="layout" dir={dir}>
      <PrimaryNav
        activePrimary={activePrimary}
        onPrimaryClick={handlePrimaryClick}
        onPrimaryHover={handlePrimaryHover}
      />

      <SecondaryNav
        secondaryPrimary={secondaryPrimary}
        activePrimary={activePrimary}
        items={secondaryItems}
        activeSecondary={activeSecondary}
        onSecondaryClick={handleSecondaryClick}
      />

      <main className="content">
        {/* Now Content renders based on the URL, not on these props.
            We keep props for compatibility but they are no longer required. */}
        <Content />
      </main>
    </div>
  );
}