<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

interface IanaTld { tld: string; kind: string; sponsor: string; }
interface Hit { domain: string; source: string; }
interface SourceStat { source: string; count: number; error?: string | null; took_ms: number; }

const tld = ref("id");
const keyword = ref("");
const apexOnly = ref(true);
const maxPerSource = ref(500);
const timeoutMs = ref(30000);

// wordlists default OFF (slow) — user opt-in via UI
const sWordlistId = ref(false);
const sWordlistIdFull = ref(false);
const sWordlistEn = ref(false);
const sWordlistSubs = ref(false);
const wordlistConcurrency = ref(150);
const wordlistInfo = ref<Record<string, { name: string; count: number }>>({});
const wlProgress = ref<Record<string, { done: number; total: number }>>({});

const running = ref(false);
const hits = ref<Hit[]>([]);
const stats = ref<SourceStat[]>([]);
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

// IANA TLD list
const ianaList = ref<IanaTld[]>([]);
const ianaLoading = ref(false);
const ianaKindFilter = ref<"all" | "generic" | "country-code" | "sponsored" | "generic-restricted">("all");
const ianaSearch = ref("");

const filteredIana = computed(() => {
  let list = ianaList.value;
  if (ianaKindFilter.value !== "all") list = list.filter(t => t.kind === ianaKindFilter.value);
  const q = ianaSearch.value.toLowerCase().trim();
  if (q) list = list.filter(t => t.tld.includes(q) || t.sponsor.toLowerCase().includes(q));
  return list.slice(0, 200);
});

async function loadIana() {
  if (ianaLoading.value) return;
  ianaLoading.value = true;
  log.dim("fetching IANA root database...");
  try {
    ianaList.value = await invoke<IanaTld[]>("iana_tld_list");
    log.ok(`IANA loaded: ${ianaList.value.length} TLDs`);
  } catch (e: any) {
    log.err(`iana fetch failed: ${e}`);
  } finally {
    ianaLoading.value = false;
  }
}

function pickTld(t: IanaTld) {
  tld.value = t.tld.replace(/^\./, "");
}

async function run() {
  if (running.value) return;
  running.value = true;
  hits.value = [];
  stats.value = [];
  log.clear();

  // passive sources always run — user doesn't pick
  const sources: string[] = ["crtsh", "commoncrawl", "rapiddns", "hackertarget", "certspotter"];
  if (sWordlistId.value) sources.push("wordlist-id");
  if (sWordlistIdFull.value) sources.push("wordlist-id-full");
  if (sWordlistEn.value) sources.push("wordlist-en");
  if (sWordlistSubs.value) sources.push("wordlist-subs");
  if (!sources.length) { log.err("pick at least one source"); running.value = false; return; }

  log.info(`tld: .${tld.value.replace(/^\./, "")}${keyword.value ? ` /keyword=${keyword.value}` : ""}`);
  log.info(`apex=${apexOnly.value} | max=${maxPerSource.value}`);

  unlistens.push(await listen<string>("grab:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ source: string; done: number; total: number }>("grab:wl-progress", (e) => {
    wlProgress.value[e.payload.source] = { done: e.payload.done, total: e.payload.total };
  }));
  unlistens.push(await listen<SourceStat>("grab:source", (e) => {
    // track internally for potential future use, but don't surface in UI/log
    stats.value.push(e.payload);
  }));
  unlistens.push(await listen<Hit>("grab:hit", (e) => {
    const h = e.payload;
    hits.value.push(h);
    // log domain only — source info hidden from user
    log.valid(h.domain);
  }));

  try {
    await invoke("domain_grab", {
      req: {
        tld: tld.value,
        keyword: keyword.value || null,
        sources,
        max_per_source: maxPerSource.value,
        apex_only: apexOnly.value,
        timeout_ms: timeoutMs.value,
        wordlist_concurrency: wordlistConcurrency.value,
      },
    });
    log.ok(`grab complete: ${hits.value.length} unique domains`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }

async function copyAll() {
  const txt = hits.value.map(h => h.domain).join("\n");
  try { await navigator.clipboard.writeText(txt); log.dim("copied to clipboard"); } catch {}
}

function downloadTxt() {
  const txt = hits.value.map(h => h.domain).join("\n");
  const blob = new Blob([txt], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `domains-${tld.value}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

onMounted(async () => {
  const cached = localStorage.getItem("grab:iana");
  if (cached) {
    try { ianaList.value = JSON.parse(cached); } catch {}
  }
  try {
    wordlistInfo.value = await invoke("wordlist_info");
  } catch {}
});

onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <div class="row">
        <label class="mini wide">
          <span>TLD</span>
          <input v-model="tld" placeholder="id, com, org, co.uk, gov.uk..." />
        </label>
      </div>

      <details class="adv" :open="!ianaList.length">
        <summary>iana tld catalog · {{ ianaList.length || "not loaded" }}</summary>
        <div class="row">
          <button class="btn-ghost" :disabled="ianaLoading" @click="loadIana">
            {{ ianaLoading ? "loading..." : (ianaList.length ? "reload" : "load from iana.org") }}
          </button>
          <label class="mini wide"><span>search</span><input v-model="ianaSearch" placeholder="gov, bank, id..." /></label>
        </div>
        <div class="row">
          <label class="toggle"><input type="radio" value="all" v-model="ianaKindFilter" /><span>all</span></label>
          <label class="toggle"><input type="radio" value="generic" v-model="ianaKindFilter" /><span>generic</span></label>
          <label class="toggle"><input type="radio" value="country-code" v-model="ianaKindFilter" /><span>ccTLD</span></label>
          <label class="toggle"><input type="radio" value="sponsored" v-model="ianaKindFilter" /><span>sponsored</span></label>
        </div>
        <div v-if="filteredIana.length" class="iana-grid">
          <button v-for="t in filteredIana" :key="t.tld" class="iana-chip" :class="`k-${t.kind.split('-')[0]}`" @click="pickTld(t)" :title="t.sponsor">
            {{ t.tld }}
          </button>
        </div>
      </details>

      <Prompt label="keyword" v-model="keyword" placeholder="optional: bank, gov, pemerintah... (empty = all)" />

      <details class="adv">
        <summary>wordlist brute · dns + http alive verify</summary>
        <div class="row">
          <label class="toggle"><input type="checkbox" v-model="sWordlistId" /><span>id-common ({{ wordlistInfo['id-kompas']?.count ?? 0 }})</span></label>
          <label class="toggle"><input type="checkbox" v-model="sWordlistIdFull" /><span>id-full ({{ wordlistInfo['id-kbbi']?.count ?? 0 }})</span></label>
          <label class="toggle"><input type="checkbox" v-model="sWordlistEn" /><span>en-common ({{ wordlistInfo['en-common']?.count ?? 0 }})</span></label>
          <label class="toggle"><input type="checkbox" v-model="sWordlistSubs" /><span>subs-top5k ({{ wordlistInfo['subs-top5k']?.count ?? 0 }})</span></label>
        </div>
        <div class="row">
          <label class="mini"><span>dns-conc</span><input v-model.number="wordlistConcurrency" type="number" min="10" max="500" /></label>
          <span class="wl-hint">
            patterns: <code>w.tld</code> <code>www.w.tld</code> · keyword adds <code>w-k.tld</code> <code>k-w.tld</code> <code>www.w.k.tld</code>
          </span>
        </div>
      </details>

      <div class="row">
        <label class="toggle"><input type="checkbox" v-model="apexOnly" /><span>apex only</span></label>
      </div>

      <div class="row">
        <label class="mini"><span>max/src</span><input v-model.number="maxPerSource" type="number" min="50" max="10000" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="5000" max="120000" /></label>
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ grabbing... ]" : "> grab domains" }}</button>
      </div>

      <div v-if="Object.keys(wlProgress).length" class="summary-line">
        <span v-for="(p, src) in wlProgress" :key="src" class="sum-piece wl">
          {{ String(src).replace('wordlist-', '') }} {{ p.done }}/{{ p.total }}
        </span>
      </div>
    </div>

    <div v-if="hits.length" class="results">
      <div class="res-head">
        <span class="res-count">{{ hits.length }} unique</span>
        <button class="btn-ghost tiny" @click="copyAll">copy all</button>
        <button class="btn-ghost tiny" @click="downloadTxt">download .txt</button>
      </div>
      <textarea
        class="term-input res-box"
        readonly
        :value="hits.map(h => h.domain).join('\n')"
        rows="8"
        spellcheck="false"
      />
    </div>

    <Terminal :lines="log.lines.value" title="domain-grab // bulk harvest" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.adv { border: 1px solid var(--border); background: var(--bg-panel); padding: 4px 8px; }
.adv summary { cursor: pointer; font-size: 10px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; padding: 2px 0; }
.adv summary:hover { color: var(--fg); }
.adv > *:not(summary) { margin-top: 6px; }

.iana-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 3px;
  max-height: 180px;
  overflow-y: auto;
  padding: 4px;
  background: var(--bg);
  border: 1px solid var(--border);
}
.iana-chip {
  padding: 2px 6px;
  font-size: 10px;
  color: var(--fg);
  background: var(--bg-panel);
  border: 1px solid var(--border);
  cursor: pointer;
  white-space: nowrap;
  transition: all 0.1s;
}
.iana-chip:hover { border-color: var(--alert); color: var(--alert); }
.k-generic { border-left: 2px solid var(--info); }
.k-country { border-left: 2px solid var(--warn); }
.k-sponsored { border-left: 2px solid var(--valid); }
.k-infrastructure { border-left: 2px solid var(--fg-ghost); }

.wl-hint {
  color: var(--fg-dim);
  font-size: 10px;
  font-style: italic;
  align-self: center;
}
.wl-hint code { color: var(--info); background: var(--bg); padding: 0 3px; border: 1px solid var(--border); font-style: normal; margin: 0 2px; }

.hint-box {
  padding: 6px 10px;
  border: 1px solid rgba(127, 179, 213, 0.3);
  background: rgba(127, 179, 213, 0.05);
  color: var(--fg-dim);
  font-size: 10px;
  line-height: 1.6;
}
.hint-box b { color: var(--info); text-transform: uppercase; letter-spacing: 0.1em; font-size: 10px; }
.hint-box code { color: var(--valid); background: var(--bg); padding: 0 4px; border: 1px solid var(--border); font-size: 10px; margin: 0 2px; }
.hint-box ul { margin: 4px 0 0 16px; padding: 0; }
.hint-box li { padding: 1px 0; }

.summary-line {
  display: flex;
  gap: 6px;
  align-items: center;
  padding: 4px 8px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  font-size: 10px;
  flex-wrap: wrap;
}
.sum-piece {
  padding: 1px 6px;
  border: 1px solid var(--border-hot);
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.sum-piece.ok { color: var(--valid); border-color: var(--valid); }
.sum-piece.wl { color: var(--info); border-color: var(--info); font-variant-numeric: tabular-nums; text-transform: none; }

.results { display: flex; flex-direction: column; gap: 4px; background: var(--bg-panel); border: 1px solid var(--border); padding: 6px 8px; }
.res-head { display: flex; gap: 6px; align-items: center; }
.res-count { color: var(--valid); font-weight: 700; font-size: 11px; flex: 1; }
.btn-ghost.tiny { padding: 1px 8px; font-size: 9px; }
.res-box { font-size: 11px; color: var(--valid); background: var(--bg); }
</style>
