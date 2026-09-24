<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

interface SourceList { free: string[]; key_based: string[]; }
interface SourceStat { source: string; count: number; error?: string | null; took_ms: number; }

const domain = ref("newploit.com");
const wordlist = ref("www,api,dev,staging,admin,mail,ftp,test,portal,app,beta,vpn,m,blog,shop");
const concurrency = ref(50);
const running = ref(false);
const progress = ref({ done: 0, total: 0 });

const sources = ref<SourceList>({ free: [], key_based: [] });
const enabledSources = ref<Set<string>>(new Set());
const apiKeys = ref<Record<string, string>>({});
const sourceStats = ref<SourceStat[]>([]);

const log = useTerminal();
const unlistens: UnlistenFn[] = [];

async function loadSources() {
  try {
    sources.value = await invoke<SourceList>("subdomain_sources");
    // load saved keys + enabled state from localStorage
    const savedKeys = JSON.parse(localStorage.getItem("subenum:keys") || "{}");
    apiKeys.value = savedKeys;
    const savedEnabled = JSON.parse(localStorage.getItem("subenum:enabled") || "null");
    if (savedEnabled) {
      enabledSources.value = new Set(savedEnabled);
    } else {
      enabledSources.value = new Set(sources.value.free);
    }
  } catch (e: any) { log.err(String(e)); }
}

function toggleSource(name: string) {
  if (enabledSources.value.has(name)) enabledSources.value.delete(name);
  else enabledSources.value.add(name);
  enabledSources.value = new Set(enabledSources.value);
  localStorage.setItem("subenum:enabled", JSON.stringify(Array.from(enabledSources.value)));
}

function saveKeys() {
  localStorage.setItem("subenum:keys", JSON.stringify(apiKeys.value));
  log.dim("api keys saved (local storage)");
}

async function run() {
  if (running.value) return;
  running.value = true;
  sourceStats.value = [];
  log.clear();
  progress.value = { done: 0, total: 0 };

  const words = wordlist.value.split(/[,\n\s]+/).map((w) => w.trim()).filter(Boolean);
  // If localStorage contains an empty selection (for example from an older
  // version), fall back to the free sources instead of sending zero sources.
  const enabled = enabledSources.value.size
    ? Array.from(enabledSources.value)
    : sources.value.free.length
      ? Array.from(sources.value.free)
      : [];
  log.info(`domain: ${domain.value}`);
  log.info(`sources: ${enabled.join(",")} (${enabled.length}) | brute: ${words.length} words`);

  unlistens.push(await listen<string>("subenum:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ done: number; total: number }>("subenum:progress", (e) => { progress.value = e.payload; }));
  unlistens.push(await listen<SourceStat>("subenum:source", (e) => {
    const s = e.payload;
    if (s.error) return;
    sourceStats.value.push(s);
    log.valid(`● ${s.source.padEnd(15)} +${String(s.count).padStart(4)}  ${s.took_ms}ms`);
  }));
  unlistens.push(await listen<any>("subenum:hit", (e) => {
    const p = e.payload;
    log.valid(`${p.host.padEnd(40)} → ${p.ips.join(",")} [${p.source}]`);
  }));

  try {
    const hits: unknown[] = await invoke("subdomain_enum", {
      req: {
        domain: domain.value,
        sources: enabled,
        wordlist: words,
        concurrency: concurrency.value,
        api_keys: apiKeys.value,
      },
    });
    log.ok(`enum complete: ${hits.length} live host(s)`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }

onMounted(loadSources);
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <Prompt label="domain" v-model="domain" placeholder="example.com" />

      <details class="adv">
        <summary>sources · {{ enabledSources.size }} / {{ sources.free.length + sources.key_based.length }} enabled</summary>

        <div class="src-section">
          <div class="src-head">free <span class="src-sub">no api key required</span></div>
          <div class="src-grid">
            <label v-for="s in sources.free" :key="s" class="src-chip" :class="{ on: enabledSources.has(s) }">
              <input type="checkbox" :checked="enabledSources.has(s)" @change="toggleSource(s)" />
              <span>{{ s }}</span>
            </label>
          </div>
        </div>

        <div class="src-section">
          <div class="src-head">key-based <span class="src-sub">paste API key to enable</span></div>
          <div class="key-list">
            <div v-for="s in sources.key_based" :key="s" class="key-row">
              <label class="src-chip" :class="{ on: enabledSources.has(s) }">
                <input type="checkbox" :checked="enabledSources.has(s)" @change="toggleSource(s)" />
                <span>{{ s }}</span>
              </label>
              <input
                v-model="apiKeys[s]"
                class="key-input"
                type="password"
                :placeholder="`${s} api key`"
                @blur="saveKeys"
                spellcheck="false"
              />
            </div>
          </div>
        </div>
      </details>

      <details class="adv">
        <summary>brute · dns wordlist</summary>
        <textarea class="term-input" v-model="wordlist" rows="2" spellcheck="false" placeholder="www,api,dev..." />
      </details>

      <div class="row">
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="500" /></label>
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ enumerating... ]" : "> enumerate" }}</button>
      </div>

      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>

      <div v-if="sourceStats.length" class="stat-grid">
        <div v-for="s in sourceStats" :key="s.source" class="stat">
          <span class="st-src">{{ s.source }}</span>
          <span class="st-cnt">+{{ s.count }}</span>
          <span class="st-ms">{{ s.took_ms }}ms</span>
        </div>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="subdomain // multi-source enum" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.adv { border: 1px solid var(--border); background: var(--bg-panel); padding: 4px 8px; }
.adv summary {
  cursor: pointer;
  font-size: 10px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 4px 0;
}
.adv summary:hover { color: var(--fg); }
.adv > *:not(summary) { margin-top: 6px; }

.src-section { margin-bottom: 8px; }
.src-section:last-child { margin-bottom: 0; }
.src-head {
  font-size: 9px;
  color: var(--alert);
  text-transform: uppercase;
  letter-spacing: 0.15em;
  margin-bottom: 4px;
}
.src-sub { color: var(--fg-ghost); margin-left: 6px; }
.src-grid { display: flex; gap: 4px; flex-wrap: wrap; }
.src-chip {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border: 1px solid var(--border);
  background: var(--bg);
  color: var(--fg-dim);
  font-size: 11px;
  cursor: pointer;
  transition: all 0.1s;
}
.src-chip input { display: none; }
.src-chip.on { color: var(--alert); border-color: var(--alert); background: rgba(255, 47, 74, 0.05); }

.key-list { display: flex; flex-direction: column; gap: 4px; }
.key-row { display: flex; gap: 6px; align-items: center; }
.key-row .src-chip { min-width: 100px; flex-shrink: 0; }
.key-input {
  flex: 1;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 3px 6px;
  font-size: 11px;
  font-family: inherit;
  min-width: 0;
}
.key-input:focus { border-color: var(--info); outline: none; }

.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 4px;
}
.stat {
  display: flex;
  gap: 6px;
  align-items: center;
  padding: 3px 6px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  font-size: 10px;
  border-left: 2px solid var(--accent);
}
.stat.err { border-left-color: var(--alert); }
.st-src { flex: 1; color: var(--fg); text-overflow: ellipsis; overflow: hidden; white-space: nowrap; }
.st-cnt { color: var(--accent); font-weight: 700; font-variant-numeric: tabular-nums; }
.st-err { color: var(--alert); font-weight: 700; }
.st-ms { color: var(--fg-ghost); font-variant-numeric: tabular-nums; }
</style>
