<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import { useTerminal } from "../../composables/useTerminal";

const token = ref("");
const wordlist = ref("");
const running = ref(false);
const result = ref<any>(null);
const progress = ref({ done: 0, total: 0 });
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

async function copy(text: string) {
  try { await navigator.clipboard.writeText(text); log.ok("copied to clipboard"); }
  catch { log.err("clipboard failed"); }
}

async function run() {
  if (running.value) return;
  running.value = true;
  result.value = null;
  log.clear();

  const words = wordlist.value.split(/[,\n\s]+/).map(s => s.trim()).filter(Boolean);

  unlistens.push(await listen<string>("jwt:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ done: number; total: number }>("jwt:progress", (e) => { progress.value = e.payload; }));

  try {
    const res: any = await invoke("jwt_analyze", {
      req: { token: token.value, wordlist: words.length ? words : null },
    });
    result.value = res;
    log.info(`alg: ${res.alg}`);
    for (const i of res.issues) {
      const m = `[${i.severity}] ${i.title} :: ${i.detail}`;
      if (i.severity === "CRITICAL" || i.severity === "HIGH") log.hit(m);
      else if (i.severity === "MEDIUM") log.warn(m);
      else log.dim(m);
    }
    for (const f of res.forgeries) {
      log.ok(`[FORGERY] ${f.attack} :: ${f.description}`);
    }
    log.ok(`analysis complete: ${res.issues.length} issue(s), ${res.forgeries.length} forgery candidate(s)`);
  } catch (e: any) {
    log.err(String(e));
  } finally { running.value = false; cleanup(); }
}
function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <label class="ta">
        <span class="lbl">jwt token</span>
        <textarea class="term-input" v-model="token" placeholder="eyJhbGciOi..." spellcheck="false" rows="3" />
      </label>
      <label class="ta">
        <span class="lbl">hmac wordlist (optional, newline/comma separated)</span>
        <textarea class="term-input" v-model="wordlist" placeholder="secret&#10;password&#10;jwt_secret" spellcheck="false" rows="2" />
      </label>
      <div class="row">
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ attacking... ]" : "> analyze + attack" }}</button>
      </div>
      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>
    </div>

    <div v-if="result" class="result-grid">
      <div class="result-block">
        <div class="rb-head">header</div>
        <pre>{{ JSON.stringify(result.header, null, 2) }}</pre>
      </div>
      <div class="result-block">
        <div class="rb-head">payload</div>
        <pre>{{ JSON.stringify(result.payload, null, 2) }}</pre>
      </div>
      <div class="result-block full">
        <div class="rb-head">forgery candidates ({{ result.forgeries.length }})</div>
        <div v-for="(f, i) in result.forgeries" :key="i" class="forgery">
          <div class="forgery-head">
            <span class="sev sev-high">{{ f.attack }}</span>
            <span class="forgery-desc">{{ f.description }}</span>
            <button class="btn-ghost" @click="copy(f.token)">copy</button>
          </div>
          <code class="forgery-token">{{ f.token }}</code>
        </div>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="jwt // alg:none + HMAC brute + forgery" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.result-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
}
.result-block {
  border: 1px solid var(--border);
  background: var(--bg-panel);
  overflow: hidden;
}
.result-block.full { grid-column: 1 / -1; }
.rb-head {
  padding: 4px 8px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-elev);
  font-size: 10px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
pre {
  padding: 8px;
  font-size: 11px;
  color: var(--fg);
  max-height: 180px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
.forgery { border-bottom: 1px solid var(--border); padding: 6px 8px; }
.forgery:last-child { border: none; }
.forgery-head { display: flex; gap: 8px; align-items: center; margin-bottom: 4px; }
.forgery-desc { flex: 1; color: var(--fg-dim); font-size: 11px; }
.forgery-token {
  display: block;
  font-size: 10px;
  color: var(--info);
  word-break: break-all;
  padding: 4px;
  background: var(--bg);
  border: 1px solid var(--border);
}

@media (max-width: 640px) {
  .result-grid { grid-template-columns: 1fr; }
}
</style>
