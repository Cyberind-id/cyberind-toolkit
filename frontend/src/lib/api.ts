const BASE = "";

const DEFAULT_TIMEOUT_MS = 60000;

export async function invoke<T = any>(command: string, args: any = {}, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${BASE}/api/invoke/${encodeURIComponent(command)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(args ?? {}),
      signal: controller.signal
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = typeof data?.error === "string" ? data.error : JSON.stringify(data);
      throw new Error(detail ? `API ${res.status}: ${detail}` : `API ${res.status}`);
    }
    return data as T;
  } catch (e: any) {
    if (e?.name === "AbortError") {
      throw new Error(`Request timeout setelah ${Math.round(timeoutMs / 1000)} detik. Periksa target/parameter lalu coba lagi.`);
    }
    throw e;
  } finally {
    window.clearTimeout(timer);
  }
}

export type UnlistenFn = () => void;
export async function listen<T = any>(_event: string, _handler: (event: { payload: T }) => void): Promise<UnlistenFn> {
  return () => {};
}
