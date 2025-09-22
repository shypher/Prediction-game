import type { PrimaryItem, SecondaryItem, PrimaryKey, SecondaryKey } from "./types";

export const PRIMARY_ITEMS: PrimaryItem[] = [
  { key: "home",   icon: "🏠", label: { en: "Home",   he: "בית" }, showInPrimary: true },
  { key: "games",  icon: "🏀", label: { en: "Games",  he: "משחקים" }, showInPrimary: true },
  { key: "groups", icon: "👥", label: { en: "Groups", he: "קבוצות" }, showInPrimary: true },
  { key: "admin",  icon: "🛠️", label: { en: "Admin", he: "ניהול" }, showInPrimary: true },
  { key: "account",icon: "👤", label: { en: "Account", he: "חשבון" }, showInPrimary: false },
];

export const SECONDARY: Record<PrimaryKey, SecondaryItem[]> = {
  home: [
    { key: "overview", label: { en: "Overview", he: "סקירה" } },
    { key: "updates",  label: { en: "Updates",  he: "עדכונים" } },
  ],
  games: [
    { key: "results", label: { en: "Results", he: "תוצאות" } },
    { key: "table",   label: { en: "Table",   he: "טבלה" } },
    { key: "stats",   label: { en: "Stats",   he: "סטטיסטיקה" } },
  ],
  groups: [
    { key: "create-group", label: { en: "Create group", he: "צור קבוצה" } },
    { key: "my-groups",    label: { en: "My groups",    he: "הקבוצות שלי" } },
  ],
  admin: [
    { key: "users",         label: { en: "Users", he: "משתמשים" } },
    { key: "matches-admin", label: { en: "Matches (admin)", he: "משחקים (ניהול)" } },
    { key: "sources",       label: { en: "Sources/Jobs", he: "מקורות/Jobs" } },
  ],
  account: [
    { key: "profile",       label: { en: "Profile", he: "פרופיל" } },
    { key: "security",      label: { en: "Security", he: "אבטחה" } },
    { key: "notifications", label: { en: "Notifications", he: "התראות" } },
  ],
};

export function defaultSecondaryOf(p: PrimaryKey): SecondaryKey {
  switch (p) {
    case "home": return "overview";
    case "games": return "results";
    case "groups": return "my-groups";
    case "admin": return "users";
    case "account": return "profile";
  }
}