<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

interface Hit {
  user: string;
  pass: string;
  status: number;
  size: number;
  redirect?: string;
  reason: string;
  time_ms: number;
}

const url = ref("https://insecure.newploit.com/login.php");
const method = ref("POST");
const bodyTemplate = ref("username={USER}&password={PASS}");
const headersRaw = ref("");
const users = ref("admin\nroot\nuser\ntest");
const passwords = ref("");
const mode = ref("clusterbomb");
const primeUrl = ref("");
const csrfRegex = ref("");
const successRegex = ref("");
const failRegex = ref("(?i)(invalid|wrong|incorrect|failed|error)");
const successStatusStr = ref("302");
const sizeDelta = ref<number | null>(null);
const concurrency = ref(5);
const timeoutMs = ref(10000);
const followRedirects = ref(false);
const stopOnFirst = ref(true);
const running = ref(false);
const progress = ref({ done: 0, total: 0 });
const hits = ref<Hit[]>([]);
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

async function loadCommonPass() {
  try {
    const list: string[] = await invoke("form_brute_common_passwords");
    passwords.value = list.join("\n");
  } catch {}
}

function parseHeaders(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of headersRaw.value.split("\n")) {
    const i = line.indexOf(":");
    if (i === -1) continue;
    const k = line.slice(0, i).trim();
    const v = line.slice(i + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

async function run() {
  if (running.value) return;
  running.value = true;
  hits.value = [];
  progress.value = { done: 0, total: 0 };
  log.clear();

  const us = users.value.split(/[\s\n,]+/).map(s => s.trim()).filter(Boolean);
  const ps = passwords.value.split(/\n/).map(s => s.trim()).filter(Boolean);
  const statuses = successStatusStr.value.split(/[,\s]+/).map(s => parseInt(s, 10)).filter(n => !isNaN(n));

  const total = mode.value === "pitchfork" ? Math.min(us.length, ps.length) : us.length * ps.length;
  log.info(`target: ${method.value} ${url.value}`);
  log.info(`${us.length} users × ${ps.length} passwords = ${total} attempts (${mode.value})`);

  unlistens.push(await listen<string>("brute:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ done: number; total: number }>("brute:progress", (e) => { progress.value = e.payload; }));
  unlistens.push(await listen<Hit>("brute:hit", (e) => {
    const h = e.payload;
    hits.value.push(h);
    log.hit(`[VALID] ${h.user}:${h.pass}  status=${h.status} size=${h.size}b  reason: ${h.reason}`);
  }));

  try {
    await invoke("form_brute_run", {
      req: {
        url: url.value,
        method: method.value,
        body_template: bodyTemplate.value,
        headers: parseHeaders(),
        users: us,
        passwords: ps,
        mode: mode.value,
        prime_url: primeUrl.value || null,
        csrf_regex: csrfRegex.value || null,
        csrf_field: "{CSRF}",
        success_regex: successRegex.value || null,
        fail_regex: failRegex.value || null,
        success_status: statuses.length ? statuses : null,
        size_delta_threshold: sizeDelta.value,
        concurrency: concurrency.value,
        timeout_ms: timeoutMs.value,
        follow_redirects: followRedirects.value,
        stop_on_first: stopOnFirst.value,
      },
    });
    log.ok(`brute done: ${hits.value.length} valid cred(s)`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }

onMounted(loadCommonPass);
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <div class="row">
        <select v-model="method" class="method-sel">
          <option>POST</option>
          <option>GET</option>
          <option>PUT</option>
        </select>
        <input v-model="url" class="url-input" placeholder="https://target.com/login" spellcheck="false" />
      </div>

      <label class="ta">
        <span class="lbl">body template — use <code>{{ "{USER}" }}</code> <code>{{ "{PASS}" }}</code> <code>{{ "{CSRF}" }}</code></span>
        <textarea class="term-input" v-model="bodyTemplate" rows="2" spellcheck="false" placeholder="username={USER}&password={PASS}&_token={CSRF}" />
      </label>

      <details class="adv">
        <summary>wordlists · {{ users.split(/\s+/).filter(Boolean).length }} users × {{ passwords.split(/\n/).filter(Boolean).length }} passwords</summary>
        <div class="two-col">
          <label class="ta">
            <span class="lbl">users</span>
            <textarea class="term-input" v-model="users" rows="5" spellcheck="false" />
          </label>
          <label class="ta">
            <span class="lbl">passwords</span>
            <textarea class="term-input" v-model="passwords" rows="5" spellcheck="false" />
          </label>
        </div>
        <div class="row">
          <label class="toggle"><input type="radio" value="clusterbomb" v-model="mode" /><span>clusterbomb (all × all)</span></label>
          <label class="toggle"><input type="radio" value="pitchfork" v-model="mode" /><span>pitchfork (parallel)</span></label>
        </div>
      </details>

      <details class="adv">
        <summary>detection rules</summary>
        <label class="ta"><span class="lbl">success regex (match = valid)</span>
          <input class="inp" v-model="successRegex" placeholder='(?i)(welcome|dashboard|logout|my-account)' /></label>
        <label class="ta"><span class="lbl">fail regex (no match = valid) <span class="hint">used if success regex empty/no-match</span></span>
          <input class="inp" v-model="failRegex" placeholder='(?i)(invalid|wrong|incorrect)' /></label>
        <div class="row">
          <label class="mini wide"><span>success-status</span><input v-model="successStatusStr" placeholder="302" /></label>
          <label class="mini"><span>size-delta</span><input v-model.number="sizeDelta" type="number" placeholder="off" /></label>
        </div>
      </details>

      <details class="adv">
        <summary>csrf + headers</summary>
        <Prompt label="prime url" v-model="primeUrl" placeholder="https://target.com/login (GET first)" />
        <label class="ta"><span class="lbl">csrf regex — capture group 1</span>
          <input class="inp" v-model="csrfRegex" placeholder='name="_token"\s+value="([^"]+)"' /></label>
        <label class="ta"><span class="lbl">extra headers (Key: Value per line)</span>
          <textarea class="term-input" v-model="headersRaw" rows="3" spellcheck="false" placeholder="Referer: https://target.com/login&#10;X-Requested-With: XMLHttpRequest" /></label>
      </details>

      <div class="row">
        <label class="toggle"><input type="checkbox" v-model="stopOnFirst" /><span>stop on first</span></label>
        <label class="toggle"><input type="checkbox" v-model="followRedirects" /><span>follow</span></label>
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="50" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="1000" max="60000" /></label>
      </div>
      <div class="row">
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ bruting... ]" : "> brute" }}</button>
      </div>

      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="form-brute // credential attack" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.adv { border: 1px solid var(--border); background: var(--bg-panel); padding: 4px 8px; }
.adv summary { cursor: pointer; font-size: 10px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; padding: 2px 0; }
.adv summary:hover { color: var(--fg); }
.adv > *:not(summary) { margin-top: 6px; }

.method-sel {
  background: var(--bg-panel);
  border: 1px solid var(--alert);
  color: var(--alert);
  padding: 4px 8px;
  font-weight: 700;
  font-size: 12px;
  font-family: inherit;
}
.method-sel option { background: var(--bg); color: var(--fg); }

.url-input {
  flex: 1;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 4px 8px;
  font-size: 12px;
}
.url-input:focus { border-color: var(--accent); outline: none; }

.inp {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 4px 8px;
  font-size: 12px;
  font-family: inherit;
  width: 100%;
}
.inp:focus { border-color: var(--info); outline: none; }

.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
}
code {
  color: var(--info);
  background: var(--bg);
  padding: 0 4px;
  border: 1px solid var(--border);
  font-size: 10px;
}
.hint { color: var(--fg-ghost); font-size: 9px; text-transform: none; font-style: italic; }

@media (max-width: 640px) {
  .two-col { grid-template-columns: 1fr; }
}
</style>
