<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Prompt from "../Prompt.vue";
import Terminal from "../Terminal.vue";
import { useTerminal } from "../../composables/useTerminal";

interface Hit {
  port: number;
  banner: string;
  service: string;
  version?: string;
  bytes: number;
}

const host = ref("insecure.newploit.com");
const portSpec = ref("21,22,23,25,80,110,143,443,445,465,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017");
const concurrency = ref(30);
const timeoutMs = ref(4000);
const running = ref(false);
const hits = ref<Hit[]>([]);
const progress = ref({ done: 0, total: 0 });
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

function parsePorts(s: string): number[] {
  const out = new Set<number>();
  for (const p of s.split(/[,\s]+/)) {
    const t = p.trim();
    if (t.includes("-")) {
      const [a, b] = t.split("-").map(x => parseInt(x, 10));
      if (!isNaN(a) && !isNaN(b)) for (let i = a; i <= b; i++) out.add(i);
    } else {
      const n = parseInt(t, 10);
      if (!isNaN(n)) out.add(n);
    }
  }
  return Array.from(out);
}

async function run() {
  if (running.value) return;
  running.value = true;
  hits.value = [];
  progress.value = { done: 0, total: 0 };
  log.clear();

  const ports = parsePorts(portSpec.value);
  if (!ports.length) { log.err("no ports"); running.value = false; return; }

  unlistens.push(await listen<string>("banner:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ done: number; total: number }>("banner:progress", (e) => { progress.value = e.payload; }));
  unlistens.push(await listen<Hit>("banner:hit", (e) => {
    const h = e.payload;
    hits.value.push(h);
    const ver = h.version ? ` :: ${h.version}` : "";
    log.valid(`${String(h.port).padEnd(5)} [${h.service.padEnd(12)}]${ver}`);
  }));

  try {
    await invoke("banner_grab", {
      req: { host: host.value.trim(), ports, concurrency: concurrency.value, timeout_ms: timeoutMs.value },
    });
    log.ok(`banner grab done: ${hits.value.length} service(s) fingerprinted`);
  } catch (e: any) { log.err(String(e)); }
  finally { running.value = false; cleanup(); }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <Prompt label="host" v-model="host" placeholder="target.com or 1.2.3.4" />
      <Prompt label="ports" v-model="portSpec" placeholder="22,80,443 or 1-1024" />
      <div class="row">
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="300" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="500" max="15000" /></label>
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ grabbing... ]" : "> grab banners" }}</button>
      </div>
      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>
    </div>

    <div v-if="hits.length" class="bgrid">
      <div v-for="h in hits" :key="h.port" class="b">
        <div class="b-head">
          <span class="b-port">{{ h.port }}</span>
          <span class="b-svc">{{ h.service }}</span>
          <span v-if="h.version" class="b-ver">{{ h.version }}</span>
          <span class="b-bytes">{{ h.bytes }}b</span>
        </div>
        <pre class="b-banner">{{ h.banner.slice(0, 500) }}</pre>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="banner // service fingerprint" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.bgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 6px; max-height: 280px; overflow-y: auto; }
.b { background: var(--bg-panel); border: 1px solid var(--border); padding: 5px 8px; border-left: 2px solid var(--valid); }
.b-head { display: flex; gap: 6px; align-items: center; font-size: 11px; margin-bottom: 3px; }
.b-port { color: var(--alert); font-weight: 700; min-width: 44px; font-variant-numeric: tabular-nums; }
.b-svc { color: var(--valid); font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; font-size: 10px; flex-shrink: 0; }
.b-ver { color: var(--info); font-size: 10px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.b-bytes { color: var(--fg-ghost); font-size: 9px; font-variant-numeric: tabular-nums; }
.b-banner {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 4px 6px;
  font-size: 10px;
  color: var(--fg-dim);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 100px;
  overflow-y: auto;
  margin: 0;
  line-height: 1.4;
}
</style>
