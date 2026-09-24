<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

interface TemplateRef {
  filename: string;
  path: string;
  id: string;
  name: string;
  severity: string;
  tags: string[];
  builtin: boolean;
}

interface StageState {
  status: "idle" | "running" | "done";
  done: number;
  total: number;
  hits: number;
}

const domain = ref("insecure.newploit.com");
const usePassive = ref(true);
const bruteList = ref("www,api,dev,staging,admin,mail,app,portal,vpn,test,beta,m,shop,blog,docs,git,jenkins,jira,grafana,prometheus,sso,auth,login,dashboard,internal");
const ports = ref("80,443");
const concurrency = ref(30);
const timeoutMs = ref(8000);

const templates = ref<TemplateRef[]>([]);
const selectedTpls = ref<Set<string>>(new Set());
const sevCritical = ref(true);
const sevHigh = ref(true);
const sevMedium = ref(true);
const sevLow = ref(false);
const sevInfo = ref(false);

const running = ref(false);
const recon = ref<StageState>({ status: "idle", done: 0, total: 0, hits: 0 });
const probe = ref<StageState>({ status: "idle", done: 0, total: 0, hits: 0 });
const exploit = ref<StageState>({ status: "idle", done: 0, total: 0, hits: 0 });
const currentStage = ref<string>("");

const foundFindings = ref<any[]>([]);
const criticalCount = computed(() => foundFindings.value.filter(f => f.severity === "critical").length);
const highCount = computed(() => foundFindings.value.filter(f => f.severity === "high").length);

const log = useTerminal();
const unlistens: UnlistenFn[] = [];

const selectedSevs = computed(() => {
  const out: string[] = [];
  if (sevCritical.value) out.push("critical");
  if (sevHigh.value) out.push("high");
  if (sevMedium.value) out.push("medium");
  if (sevLow.value) out.push("low");
  if (sevInfo.value) out.push("info");
  return out;
});

async function loadTemplates() {
  try {
    await invoke("xploit_store_init");
    templates.value = await invoke("xploit_store_list", {
      severity: selectedSevs.value,
      tag: null,
      query: null,
    });
    // auto-arm all matching templates
    selectedTpls.value = new Set(templates.value.map(t => t.path));
  } catch (e: any) {
    log.err(`template load: ${e}`);
  }
}

function reset() {
  recon.value = { status: "idle", done: 0, total: 0, hits: 0 };
  probe.value = { status: "idle", done: 0, total: 0, hits: 0 };
  exploit.value = { status: "idle", done: 0, total: 0, hits: 0 };
  foundFindings.value = [];
  currentStage.value = "";
}

async function go() {
  if (running.value) return;
  if (!domain.value.trim()) { log.err("enter a domain"); return; }
  if (!selectedTpls.value.size) { log.warn("no templates armed — recon + probe only"); }

  running.value = true;
  reset();
  log.clear();
  log.info(`target: ${domain.value}`);
  log.info(`passive: ${usePassive.value ? "crt.sh" : "off"} | brute: ${bruteList.value.split(",").length} words | templates: ${selectedTpls.value.size}`);

  // collect selected template YAMLs
  const paths = Array.from(selectedTpls.value);
  const yamls: string[] = [];
  for (const p of paths) {
    try { yamls.push(await invoke<string>("xploit_store_read", { path: p })); }
    catch { /* skip */ }
  }

  const brute = bruteList.value.split(/[\s,\n]+/).map(s => s.trim()).filter(Boolean);
  const probe_ports = ports.value.split(/[\s,]+/).map(s => parseInt(s, 10)).filter(n => !isNaN(n));

  // listeners
  unlistens.push(await listen<string>("autopwn:stage", (e) => {
    currentStage.value = String(e.payload);
    const stage = currentStage.value.split(":")[0];
    if (stage === "recon") recon.value.status = "running";
    else if (stage === "probe") probe.value.status = "running";
    else if (stage === "exploit") exploit.value.status = "running";
    log.dim(`► stage: ${currentStage.value}`);
  }));
  unlistens.push(await listen<string>("autopwn:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<any>("autopwn:progress", (e) => {
    const p = e.payload;
    if (p.stage === "recon") { recon.value.done = p.done; recon.value.total = p.total; }
    else if (p.stage === "probe") { probe.value.done = p.done; probe.value.total = p.total; }
    else if (p.stage === "exploit") { exploit.value.done = p.done; exploit.value.total = p.total; }
  }));
  unlistens.push(await listen<any>("autopwn:sub", (e) => {
    recon.value.hits++;
    const p = e.payload;
    log.valid(`sub: ${p.host.padEnd(40)} → ${p.ips.join(",")} [${p.source}]`);
  }));
  unlistens.push(await listen<any>("autopwn:alive", (e) => {
    probe.value.hits++;
    const p = e.payload;
    log.valid(`alive: ${p.status} ${p.url}${p.title ? ` "${p.title.slice(0, 40)}"` : ""}${p.server ? ` [${p.server}]` : ""}`);
  }));
  unlistens.push(await listen<any>("autopwn:xpl:hit", (e) => {
    exploit.value.hits++;
    const f = e.payload;
    foundFindings.value.push(f);
    const sev = (f.severity || "info").toLowerCase();
    const extras = [f.cve_id, f.cvss ? `cvss:${f.cvss}` : null].filter(Boolean).join(" ");
    const msg = `PWN [${sev.toUpperCase()}] ${f.template_id} :: ${f.matched_url} (${f.status})${extras ? ` [${extras}]` : ""}`;
    if (["critical", "high"].includes(sev)) log.hit(msg);
    else if (sev === "medium") log.warn(msg);
    else log.ok(msg);
  }));
  unlistens.push(await listen<any>("autopwn:stage-done", (e) => {
    const p = e.payload;
    if (p.stage === "recon") recon.value.status = "done";
    else if (p.stage === "probe") probe.value.status = "done";
    else if (p.stage === "exploit") exploit.value.status = "done";
    log.dim(`✓ stage ${p.stage} done: ${p.count}`);
  }));

  try {
    const report: any = await invoke("autopwn_run", {
      req: {
        domain: domain.value.trim(),
        use_passive: usePassive.value,
        brute_wordlist: brute,
        templates_yaml: yamls,
        probe_ports: probe_ports.length ? probe_ports : null,
        concurrency: concurrency.value,
        timeout_ms: timeoutMs.value,
      },
    });
    log.ok(`pwn complete: ${report.subdomains.length} subs, ${report.alive.length} alive, ${report.findings.length} findings`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }

onMounted(loadTemplates);
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <Prompt label="target" v-model="domain" placeholder="example.com (root domain only)" />

      <div class="row">
        <label class="mini wide"><span>ports</span><input v-model="ports" placeholder="80,443,8080,8443" /></label>
      </div>
      <div class="row">
        <label class="toggle"><input type="checkbox" v-model="usePassive" /><span>passive crt.sh</span></label>
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="200" /></label>
      </div>
      <div class="row">
        <label class="mini"><span>timeout ms</span><input v-model.number="timeoutMs" type="number" min="1000" max="30000" /></label>
      </div>

      <details class="adv">
        <summary>advanced · brute wordlist + template filter</summary>
        <label class="ta">
          <span class="lbl">dns brute wordlist</span>
          <textarea class="term-input" v-model="bruteList" rows="2" spellcheck="false" />
        </label>
        <div class="row">
          <label class="toggle"><input type="checkbox" v-model="sevCritical" @change="loadTemplates" /><span>critical</span></label>
          <label class="toggle"><input type="checkbox" v-model="sevHigh" @change="loadTemplates" /><span>high</span></label>
          <label class="toggle"><input type="checkbox" v-model="sevMedium" @change="loadTemplates" /><span>medium</span></label>
          <label class="toggle"><input type="checkbox" v-model="sevLow" @change="loadTemplates" /><span>low</span></label>
          <label class="toggle"><input type="checkbox" v-model="sevInfo" @change="loadTemplates" /><span>info</span></label>
        </div>
        <div class="tpl-count">
          {{ selectedTpls.size }} / {{ templates.length }} templates armed
          <button class="btn-ghost" @click="loadTemplates">reload</button>
        </div>
      </details>

      <button class="exec big" :disabled="running" @click="go">
        {{ running ? "[ pwning... ]" : "► AUTO-PWN" }}
      </button>
    </div>

    <!-- stage tracker — compact single row -->
    <div class="stages-bar">
      <div class="sb-cell" :class="recon.status">
        <span class="sb-n">01</span>
        <span class="sb-name">recon</span>
        <span class="sb-hits">{{ recon.hits }}</span>
        <span class="sb-sub">subs</span>
        <div class="sb-fill" :style="{ width: recon.total ? (recon.done/recon.total)*100+'%' : '0%' }" />
      </div>
      <div class="sb-cell" :class="probe.status">
        <span class="sb-n">02</span>
        <span class="sb-name">probe</span>
        <span class="sb-hits">{{ probe.hits }}</span>
        <span class="sb-sub">alive</span>
        <div class="sb-fill" :style="{ width: probe.total ? (probe.done/probe.total)*100+'%' : '0%' }" />
      </div>
      <div class="sb-cell" :class="exploit.status">
        <span class="sb-n">03</span>
        <span class="sb-name">exploit</span>
        <span class="sb-hits danger">{{ exploit.hits }}</span>
        <span class="sb-sub">pwn</span>
        <div class="sb-fill hot" :style="{ width: exploit.total ? (exploit.done/exploit.total)*100+'%' : '0%' }" />
      </div>
    </div>

    <!-- finding summary -->
    <div v-if="foundFindings.length" class="summary">
      <span class="sum-head">findings</span>
      <span v-if="criticalCount" class="sev sev-critical">{{ criticalCount }} critical</span>
      <span v-if="highCount" class="sev sev-high">{{ highCount }} high</span>
      <span class="sum-total">{{ foundFindings.length }} total</span>
    </div>

    <Terminal :lines="log.lines.value" title="auto-pwn // pipeline output" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.adv {
  border: 1px solid var(--border);
  background: var(--bg-panel);
  padding: 4px 8px;
}
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
.tpl-count {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 11px;
  color: var(--fg-dim);
}

.exec.big {
  flex: 0 0 auto;
  width: 100%;
  min-width: 0;
  height: auto;
  padding: 8px 12px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.15em;
  text-transform: uppercase;
}

.stages-bar {
  display: flex;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  flex-shrink: 0;
}
.sb-cell {
  position: relative;
  flex: 1;
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 5px 8px;
  border-right: 1px solid var(--border);
  font-size: 10px;
  color: var(--fg-dim);
  overflow: hidden;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  min-width: 0;
}
.sb-cell:last-child { border-right: none; }
.sb-cell.running { color: var(--fg); }
.sb-cell.done { color: var(--accent); }

.sb-n { color: var(--fg-ghost); font-size: 9px; flex-shrink: 0; }
.sb-name { flex: 1; color: inherit; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.sb-hits { color: var(--valid); font-weight: 700; font-size: 11px; font-variant-numeric: tabular-nums; }
.sb-hits.danger { color: var(--alert); }
.sb-sub { color: var(--fg-ghost); font-size: 9px; flex-shrink: 0; }

.sb-fill {
  position: absolute;
  bottom: 0;
  left: 0;
  height: 2px;
  background: linear-gradient(90deg, var(--accent-dim), var(--accent));
  transition: width 0.15s;
}
.sb-fill.hot { background: linear-gradient(90deg, #a82020, var(--alert)); }

.summary {
  display: flex;
  gap: 6px;
  align-items: center;
  padding: 3px 8px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  font-size: 10px;
  flex-wrap: wrap;
  flex-shrink: 0;
}
.sum-head {
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-size: 10px;
  margin-right: 4px;
}
.sum-total {
  margin-left: auto;
  color: var(--fg-dim);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

@media (max-width: 520px) {
  .stages { grid-template-columns: 1fr; }
}
</style>
