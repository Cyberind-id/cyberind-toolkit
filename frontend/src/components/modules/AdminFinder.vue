<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

interface AdminHit {
  url: string;
  status: number;
  size: number;
  title?: string;
  platform?: string;
  login_form: boolean;
  auth_header?: string;
  redirect?: string;
}

const baseUrl = ref("https://insecure.newploit.com");
const useBuiltin = ref(true);
const extraPaths = ref("");
const acceptStatusStr = ref("200,301,302,401,403");
const concurrency = ref(40);
const timeoutMs = ref(5000);
const followRedirects = ref(false);
const running = ref(false);
const progress = ref({ done: 0, total: 0 });
const hits = ref<AdminHit[]>([]);
const log = useTerminal();
const unlistens: UnlistenFn[] = [];
const builtinCount = ref(0);

async function loadCount() {
  try {
    const list: string[] = await invoke("admin_finder_wordlist");
    builtinCount.value = list.length;
  } catch {}
}

async function run() {
  if (running.value) return;
  running.value = true;
  hits.value = [];
  progress.value = { done: 0, total: 0 };
  log.clear();

  const extras = extraPaths.value.split(/[\s\n,]+/).map(s => s.trim()).filter(Boolean);
  const statuses = acceptStatusStr.value.split(/[,\s]+/).map(s => parseInt(s, 10)).filter(n => !isNaN(n));

  log.info(`target: ${baseUrl.value}`);
  log.info(`paths: builtin=${useBuiltin.value ? builtinCount.value : 0} + ${extras.length} extra`);

  unlistens.push(await listen<string>("adminfind:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ done: number; total: number }>("adminfind:progress", (e) => { progress.value = e.payload; }));
  unlistens.push(await listen<AdminHit>("adminfind:hit", (e) => {
    const h = e.payload;
    hits.value.push(h);
    const flags: string[] = [];
    if (h.login_form) flags.push("LOGIN");
    if (h.auth_header) flags.push("AUTH");
    if (h.platform) flags.push(h.platform);
    const flagStr = flags.length ? `[${flags.join("|")}]` : "";
    const line = `${String(h.status).padEnd(4)} ${h.url} ${flagStr}${h.title ? ` "${h.title.slice(0, 50)}"` : ""}`;
    if (h.login_form || h.auth_header) log.hit(line);
    else log.valid(line);
  }));

  try {
    await invoke("admin_finder_run", {
      req: {
        base_url: baseUrl.value.trim(),
        extra_paths: extras,
        use_builtin: useBuiltin.value,
        accept_status: statuses,
        concurrency: concurrency.value,
        timeout_ms: timeoutMs.value,
        follow_redirects: followRedirects.value,
      },
    });
    const logins = hits.value.filter(h => h.login_form || h.auth_header).length;
    log.ok(`done: ${hits.value.length} responses, ${logins} login panel(s) found`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }

onMounted(loadCount);
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <Prompt label="target" v-model="baseUrl" placeholder="https://target.com" />

      <div class="row">
        <label class="mini wide"><span>status</span><input v-model="acceptStatusStr" placeholder="200,301,302,401,403" /></label>
      </div>

      <div class="row">
        <label class="toggle"><input type="checkbox" v-model="useBuiltin" /><span>builtin ({{ builtinCount }})</span></label>
        <label class="toggle"><input type="checkbox" v-model="followRedirects" /><span>follow</span></label>
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="200" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="500" max="30000" /></label>
      </div>

      <details class="adv">
        <summary>extra paths (optional)</summary>
        <textarea class="term-input" v-model="extraPaths" rows="3" spellcheck="false" placeholder="one path per line, e.g. panel/admin, custom-admin-path" />
      </details>

      <div class="row">
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ probing... ]" : "> find admin" }}</button>
      </div>

      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="admin-finder // panel discovery" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.adv { border: 1px solid var(--border); background: var(--bg-panel); padding: 4px 8px; }
.adv summary { cursor: pointer; font-size: 10px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; padding: 2px 0; }
.adv summary:hover { color: var(--fg); }
.adv > *:not(summary) { margin-top: 6px; }
</style>
