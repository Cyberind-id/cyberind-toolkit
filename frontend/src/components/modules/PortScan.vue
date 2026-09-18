<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

const target = ref("insecure.newploit.com");
const portSpec = ref("top1000");
const concurrency = ref(200);
const timeoutMs = ref(1500);
const running = ref(false);
const progress = ref({ scanned: 0, total: 0 });

const log = useTerminal();
const unlistens: UnlistenFn[] = [];

function parsePorts(spec: string): number[] | "top1000" {
  const s = spec.trim();
  if (s === "" || s === "top1000") return "top1000";
  if (s === "all") {
    const arr: number[] = [];
    for (let i = 1; i <= 65535; i++) arr.push(i);
    return arr;
  }
  const out = new Set<number>();
  for (const part of s.split(",")) {
    const p = part.trim();
    if (p.includes("-")) {
      const [a, b] = p.split("-").map((x) => parseInt(x, 10));
      if (!isNaN(a) && !isNaN(b)) for (let i = a; i <= b; i++) out.add(i);
    } else {
      const n = parseInt(p, 10);
      if (!isNaN(n)) out.add(n);
    }
  }
  return Array.from(out);
}

const TOP_1000 = ref<number[]>([]);

onMounted(async () => {
  try {
    TOP_1000.value = await invoke<number[]>("default_ports");
  } catch {
    TOP_1000.value = [21, 22, 80, 443, 3306, 3389, 8080];
  }
});

async function run() {
  if (running.value) return;
  running.value = true;
  log.clear();
  progress.value = { scanned: 0, total: 0 };

  const parsed = parsePorts(portSpec.value);
  const ports = parsed === "top1000" ? TOP_1000.value : parsed;

  log.info(`target: ${target.value}`);
  log.info(`ports: ${ports.length} | concurrency: ${concurrency.value} | timeout: ${timeoutMs.value}ms`);
  log.dim("resolving...");

  unlistens.push(
    await listen<{ scanned: number; total: number }>("portscan:progress", (e) => {
      progress.value = e.payload;
    })
  );
  unlistens.push(
    await listen<{ port: number; service: string | null }>("portscan:hit", (e) => {
      const s = e.payload.service ? ` (${e.payload.service})` : "";
      log.valid(`open  ${String(e.payload.port).padEnd(5)}/tcp${s}`);
    })
  );

  try {
    const results: Array<{ port: number; service: string | null }> = await invoke("port_scan", {
      req: { target: target.value, ports, concurrency: concurrency.value, timeout_ms: timeoutMs.value },
    });
    log.ok(`scan complete: ${results.length} open port(s)`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() {
  while (unlistens.length) {
    const u = unlistens.pop();
    if (u) u();
  }
}

onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <Prompt label="target" v-model="target" placeholder="host or IP" />
      <Prompt label="ports" v-model="portSpec" placeholder="top1000 | 1-1024 | 22,80,443 | all" />
      <div class="row">
        <label class="mini">
          <span>conc</span>
          <input v-model.number="concurrency" type="number" min="1" max="2000" />
        </label>
        <label class="mini">
          <span>timeout</span>
          <input v-model.number="timeoutMs" type="number" min="100" max="10000" />
        </label>
        <button class="exec" :disabled="running" @click="run">
          {{ running ? "[ scanning... ]" : "> execute" }}
        </button>
      </div>
      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.scanned / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.scanned }} / {{ progress.total }}</span>
      </div>
    </div>
    <Terminal :lines="log.lines.value" title="port-scan // output" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.module {
  display: flex;
  flex-direction: column;
  gap: 10px;
  height: 100%;
  min-height: 0;
}
.form {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.row {
  display: flex;
  gap: 6px;
  align-items: stretch;
}
.mini {
  display: flex;
  align-items: center;
  gap: 4px;
  border: 1px solid var(--border);
  padding: 4px 8px;
  background: var(--bg-panel);
}
.mini span {
  color: var(--fg-dim);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.mini input {
  width: 60px;
  color: var(--fg);
  text-align: right;
}
.exec {
  flex: 1;
  border: 1px solid var(--accent);
  color: var(--accent);
  background: transparent;
  padding: 6px 12px;
  font-weight: 500;
  letter-spacing: 0.05em;
  text-transform: lowercase;
  transition: all 0.15s;
}
.exec:hover:not(:disabled) {
  background: var(--alert);
  color: #fff;
  border-color: var(--alert);
  box-shadow: 0 0 16px rgba(255, 47, 74, 0.35);
}
.exec:disabled {
  color: var(--fg-dim);
  border-color: var(--border-hot);
  cursor: wait;
}
.bar {
  position: relative;
  height: 14px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  overflow: hidden;
}
.bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent-dim), var(--accent));
  transition: width 0.1s linear;
}
.bar-text {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  color: var(--fg);
  mix-blend-mode: difference;
  letter-spacing: 0.1em;
}
</style>
