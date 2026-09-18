import { ref } from "vue";

export type LogLevel = "info" | "hit" | "ok" | "valid" | "warn" | "err" | "dim";

export interface LogLine {
  ts: string;
  level: LogLevel;
  text: string;
}

export function useTerminal(max = 500) {
  const lines = ref<LogLine[]>([]);

  function now() {
    const d = new Date();
    return d.toTimeString().slice(0, 8);
  }

  function push(level: LogLevel, text: string) {
    lines.value.push({ ts: now(), level, text });
    if (lines.value.length > max) {
      lines.value.splice(0, lines.value.length - max);
    }
  }

  function clear() {
    lines.value = [];
  }

  return {
    lines,
    clear,
    info: (t: string) => push("info", t),
    hit: (t: string) => push("hit", t),
    ok: (t: string) => push("ok", t),
    valid: (t: string) => push("valid", t),
    warn: (t: string) => push("warn", t),
    err: (t: string) => push("err", t),
    dim: (t: string) => push("dim", t),
  };
}
