const BASE = "";

export async function invoke<T = any>(command: string, args: any = {}): Promise<T> {
  const res = await fetch(`${BASE}/api/invoke/${encodeURIComponent(command)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(args ?? {})
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `API ${res.status}`);
  return data as T;
}

export type UnlistenFn = () => void;
export async function listen<T = any>(_event: string, _handler: (event: { payload: T }) => void): Promise<UnlistenFn> {
  return () => {};
}
