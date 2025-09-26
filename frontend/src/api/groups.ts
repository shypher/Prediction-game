// src/api/groups.ts
import { getJSON, postJSON } from "../api/client"; // הנתיב לפי הפרויקט שלך

export type GroupOut = {
  id: number;
  name: string;
  owner_id: number;
  invite_code?: string | null;
  is_private: boolean;
  member_count?: number;
};

export type MyGroupOut = {
  id: number;
  name: string;
  role: string;        // "owner" | "member" | ...
  owner_id: number;
  is_private: boolean;
  invite_code?: string | null;
  created_at?: string | null;
  member_count?: number;
};

export function fetchMyGroups(signal?: AbortSignal) {
  return getJSON<MyGroupOut[]>("/groups/my", signal);
}

export function createGroup(payload: { name: string; is_private: boolean }, signal?: AbortSignal) {
  return postJSON<GroupOut>("/groups", payload, signal);
}

export function joinGroup(groupId: number, invite_code?: string, signal?: AbortSignal) {
  const qs = invite_code ? `?invite_code=${encodeURIComponent(invite_code)}` : "";
  return postJSON<GroupOut>(`/groups/${groupId}/join${qs}`, undefined, signal);
}

export function leaveGroup(groupId: number, signal?: AbortSignal) {
  return postJSON<{ ok: boolean }>(`/groups/${groupId}/leave`, undefined, signal);
}

export function regenInvite(groupId: number, signal?: AbortSignal) {
  return postJSON<{ invite_code: string }>(`/groups/${groupId}/regen-invite`, undefined, signal);
}
