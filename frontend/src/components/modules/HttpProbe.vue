<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import { useTerminal } from "../../composables/useTerminal";

const targets = ref("insecure.newploit.com");
const ports = ref("80,443,8080,8443");
const concurrency = ref(50);
const timeoutMs = ref(5000);
const follow = ref(true);
const running = ref(false);
const progress = ref({ done: 0, total: 0 });

const log = useTerminal();
const unlistens: UnlistenFn[] = [];

function statusColor(s: number): "valid" | "ok" | "warn" | "err" {
  if (s >= 200 && s < 300) return "valid";
  if (s >= 300 && s < 400) return "ok";
  if (s >= 400 && s < 500) return "warn";
  return "err";
}

async function run() {
  if (running.value) return;
  running.value = true;
  log.clear();
  progress.value = { done: 0, total: 0 };

  const tgts = targets.value.split(/[\s,\n]+/).map((s) => s.trim()).filter(Boolean);
  const pts = ports.value.split(/[\s,]+/).map((s) => parseInt(s, 10)).filter((n) => !isNaN(n));

  log.info(`targets: ${tgts.length} | ports: ${pts.join(",")} | conc: ${concurrency.value}`);

  unlistens.push(
    await listen<{ done: number; total: number }>("httpx:progress", (e) => {
      progress.value = e.payload;
    })
  );
  unlistens.push(
    await listen<{
      url: string;
      status: number;
      title: string | null;
      server: string | null;
      tech: string[];
    }>("httpx:hit", (e) => {
      const p = e.payload;
      const lvl = statusColor(p.status);
      const parts = [
        `${p.status}`.padEnd(4),
        p.url.padEnd(40),
        p.title ? `"${p.title.slice(0, 40)}"` : "",
        p.server ? `[${p.server}]` : "",
        p.tech.length ? `{${p.tech.join(",")}}` : "",
      ].filter(Boolean).join(" ");
      (log as any)[lvl](parts);
    })
  );

  try {
    const res: unknown[] = await invoke("http_probe", {
      req: {
        targets: tgts,
        ports: pts,
        concurrency: concurrency.value,
        timeout_ms: timeoutMs.value,
        follow_redirects: follow.value,
      },
    });
    log.ok(`probe complete: ${res.length} alive`);
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
      <label class="ta">
        <span class="lbl">targets</span>
        <textarea v-model="targets" placeholder="one host per line" spellcheck="false" rows="3" />
      </label>
      <div class="row">
        <label class="mini wide">
          <span>ports</span>
          <input v-model="ports" placeholder="80,443,8080,8443" />
        </label>
      </div>
      <div class="row">
        <label class="mini">
          <span>conc</span>
          <input v-model.number="concurrency" type="number" min="1" max="500" />
        </label>
        <label class="mini">
          <span>t/out</span>
          <input v-model.number="timeoutMs" type="number" min="500" max="30000" />
        </label>
        <label class="toggle">
          <input type="checkbox" v-model="follow" />
          <span>follow</span>
        </label>
      </div>
      <div class="row">
        <button class="exec" :disabled="running" @click="run">
          {{ running ? "[ probing... ]" : "> execute" }}
        </button>
      </div>
      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>
    </div>
    <Terminal :lines="log.lines.value" title="http-probe // output" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.module { display: flex; flex-direction: column; gap: 10px; height: 100%; min-height: 0; }
.form { display: flex; flex-direction: column; gap: 6px; }
.row { display: flex; gap: 6px; }
.ta { display: flex; flex-direction: column; }
.lbl { color: var(--fg-dim); font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; padding: 2px 0; }
textarea { background: var(--bg-panel); border: 1px solid var(--border); color: var(--fg); padding: 6px 8px; resize: vertical; font-family: inherit; font-size: 12px; }
textarea:focus { border-color: var(--accent); }

.mini { display: flex; align-items: center; gap: 4px; border: 1px solid var(--border); padding: 4px 8px; background: var(--bg-panel); }
.mini.wide { flex: 1; }
.mini span { color: var(--fg-dim); font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; }
.mini input { flex: 1; width: 60px; color: var(--fg); }
.mini.wide input { text-align: left; }

.toggle { display: flex; align-items: center; gap: 6px; border: 1px solid var(--border); padding: 4px 10px; background: var(--bg-panel); color: var(--fg-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; cursor: pointer; }
.toggle input { accent-color: var(--accent); }
.toggle:has(input:checked) { color: var(--accent); border-color: var(--accent); }

.exec { flex: 1; border: 1px solid var(--accent); color: var(--accent); padding: 6px 12px; font-weight: 500; transition: all 0.15s; }
.exec:hover:not(:disabled) { background: var(--alert); color: #fff; border-color: var(--alert); box-shadow: 0 0 16px rgba(255, 47, 74, 0.35); }
.exec:disabled { color: var(--fg-dim); border-color: var(--border-hot); cursor: wait; }

.bar { position: relative; height: 14px; background: var(--bg-panel); border: 1px solid var(--border); overflow: hidden; }
.bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent-dim), var(--accent)); transition: width 0.1s linear; }
.bar-text { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 10px; mix-blend-mode: difference; letter-spacing: 0.1em; }
</style>
