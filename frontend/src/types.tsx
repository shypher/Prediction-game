import type { Label } from "./i18n";

export type PrimaryKey = "home" | "games" | "groups" | "admin" | "account";

export type SecondaryKey =
  | "overview" | "updates"                // home
  | "results" | "table" | "stats"        // games
  | "create-group" | "my-groups"         // groups
  | "users" | "matches-admin" | "sources"// admin
  | "profile" | "security" | "notifications"; // account

export type PrimaryItem = {
  key: PrimaryKey;
  icon: string;
  label: Label;
  showInPrimary?: boolean;
};

export type SecondaryItem = { key: SecondaryKey; label: Label };

// demo data types
export type Group = { id: string; name: string; members: string[] };