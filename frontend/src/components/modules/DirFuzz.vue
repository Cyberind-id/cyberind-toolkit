<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

interface DirHit {
  url: string;
  status: number;
  size: number;
  words: number;
  lines: number;
  redirect?: string;
  title?: string;
  content_type?: string;
  time_ms: number;
}

const baseUrl = ref("https://insecure.newploit.com");
const wordlist = ref("");
const extensions = ref(".php,.html,.bak,.zip,.json,.txt");
const acceptStatusStr = ref("200,201,204,301,302,307,308,401,403,405");
const sizeMin = ref<number | null>(null);
const sizeMax = ref<number | null>(null);
const concurrency = ref(40);
const timeoutMs = ref(5000);
const followRedirects = ref(false);
const recursive = ref(false);
const recursionDepth = ref(2);
const running = ref(false);
const progress = ref({ done: 0 });
const hits = ref<DirHit[]>([]);
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

async function loadDefault() {
  try {
    const words: string[] = await invoke("dirfuzz_common_wordlist");
    wordlist.value = words.join("\n");
  } catch (e: any) { log.err(String(e)); }
}

function statusKind(s: number): "valid" | "ok" | "warn" | "err" {
  if (s >= 200 && s < 300) return "valid";
  if (s >= 300 && s < 400) return "ok";
  if (s >= 400 && s < 500) return "warn";
  return "err";
}

async function run() {
  if (running.value) return;
  running.value = true;
  hits.value = [];
  progress.value = { done: 0 };
  log.clear();

  const words = wordlist.value.split(/[\s,\n]+/).map(s => s.trim()).filter(Boolean);
  const exts = extensions.value.split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
  const statuses = acceptStatusStr.value.split(/[,\s]+/).map(s => parseInt(s, 10)).filter(n => !isNaN(n));

  log.info(`target: ${baseUrl.value}`);
  log.info(`paths: ${words.length} × ${exts.length + 1} (incl. plain) = ${words.length * (exts.length + 1)} tests per level`);

  unlistens.push(await listen<string>("dirfuzz:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ done: number }>("dirfuzz:progress", (e) => { progress.value = e.payload; }));
  unlistens.push(await listen<DirHit>("dirfuzz:hit", (e) => {
    const h = e.payload;
    hits.value.push(h);
    const redir = h.redirect ? ` → ${h.redirect}` : "";
    const title = h.title ? ` "${h.title.slice(0, 40)}"` : "";
    const line = `${String(h.status).padEnd(4)} ${h.size.toString().padStart(7)}b ${h.url}${redir}${title}`;
    (log as any)[statusKind(h.status)](line);
  }));

  try {
    await invoke("dirfuzz_run", {
      req: {
        base_url: baseUrl.value.trim(),
        wordlist: words,
        extensions: exts,
        accept_status: statuses,
        size_min: sizeMin.value,
        size_max: sizeMax.value,
        concurrency: concurrency.value,
        timeout_ms: timeoutMs.value,
        follow_redirects: followRedirects.value,
        recursive: recursive.value,
        recursion_depth: recursionDepth.value,
        headers: {},
        user_agent: null,
      },
    });
    log.ok(`fuzz done: ${hits.value.length} hits`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }

onMounted(loadDefault);
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <Prompt label="base url" v-model="baseUrl" placeholder="https://target.com" />

      <details class="adv">
        <summary>wordlist · {{ wordlist.split(/\s+/).filter(Boolean).length }} paths</summary>
        <textarea class="term-input" v-model="wordlist" rows="4" spellcheck="false" placeholder="one path per line" />
      </details>

      <div class="row">
        <label class="mini wide"><span>ext</span><input v-model="extensions" placeholder=".php,.bak,.zip" /></label>
        <label class="mini wide"><span>status</span><input v-model="acceptStatusStr" placeholder="200,403" /></label>
      </div>

      <div class="row">
        <label class="mini"><span>size≥</span><input v-model.number="sizeMin" type="number" placeholder="min" /></label>
        <label class="mini"><span>size≤</span><input v-model.number="sizeMax" type="number" placeholder="max" /></label>
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="300" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="500" max="30000" /></label>
      </div>

      <div class="row">
        <label class="toggle"><input type="checkbox" v-model="followRedirects" /><span>follow</span></label>
        <label class="toggle"><input type="checkbox" v-model="recursive" /><span>recursive</span></label>
        <label v-if="recursive" class="mini"><span>depth</span><input v-model.number="recursionDepth" type="number" min="1" max="5" /></label>
      </div>

      <div class="row">
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ fuzzing... ]" : "> fuzz" }}</button>
      </div>

      <div v-if="running" class="scan-stat">
        <span>seen {{ progress.done }}</span>
        <span class="sep">│</span>
        <span>hits {{ hits.length }}</span>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="dir-fuzz // content discovery" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.adv { border: 1px solid var(--border); background: var(--bg-panel); padding: 4px 8px; }
.adv summary { cursor: pointer; font-size: 10px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; padding: 2px 0; }
.adv summary:hover { color: var(--fg); }
.adv > *:not(summary) { margin-top: 6px; }

.scan-stat {
  display: flex;
  gap: 8px;
  padding: 4px 8px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  font-size: 11px;
  color: var(--fg-dim);
  font-variant-numeric: tabular-nums;
}
.scan-stat .sep { color: var(--fg-ghost); }
</style>
