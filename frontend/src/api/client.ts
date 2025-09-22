const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export class HttpError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}

export async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(BASE_URL + path, { signal, credentials: "include" });
  if (!res.ok) {
    const text = await res.text().catch(()=> "");
    throw new HttpError(text || `HTTP ${res.status}`, res.status);
  }
  return res.json() as Promise<T>;
}
