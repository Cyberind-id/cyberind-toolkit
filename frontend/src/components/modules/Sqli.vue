<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

interface Finding {
  param: string;
  location: string;
  technique: string;
  dbms?: string;
  prefix: string;
  suffix: string;
  payload: string;
  full_payload: string;
  evidence: string;
  confidence: string;
  extracted: Record<string, string>;
  base_value: string;
  union_cols?: number | null;
  union_position?: number | null;
}

interface DumpResult {
  dbms: string;
  action: string;
  headers: string[];
  rows: string[][];
  count: number;
  truncated: boolean;
  raw_payload: string;
  raw_captured: string;
}

interface DumpSession {
  finding: Finding;
  databases: string[];
  selectedDb: string;
  tables: string[];
  selectedTable: string;
  columns: string[];
  selectedCols: Set<string>;
  limit: number;
  offset: number;
  rowsResult: DumpResult | null;
  busy: boolean;
  err: string;
  lastPayload: string;
}

const url = ref("https://insecure.newploit.com/profile.php?id=1");
const method = ref("GET");
const body = ref("");
const headersRaw = ref("");
const cookies = ref("");
const paramsFilter = ref("");

const tHeuristic = ref(true);
const tError = ref(true);
const tBoolean = ref(true);
const tUnion = ref(true);
const tTime = ref(false);

const level = ref(2);
const risk = ref(1);
const stopOnFirst = ref(false);
const autoExtract = ref(true);
const followRedirects = ref(true);

const tamperRandomcase = ref(false);
const tamperSpace2comment = ref(false);
const tamperEqualToLike = ref(false);

const concurrency = ref(4);
const timeoutMs = ref(15000);
const running = ref(false);
const findings = ref<Finding[]>([]);
const dumpSessions = ref<Record<number, DumpSession>>({});
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

function getOrCreateSession(idx: number, f: Finding): DumpSession {
  if (!dumpSessions.value[idx]) {
    dumpSessions.value[idx] = {
      finding: f,
      databases: [],
      selectedDb: "",
      tables: [],
      selectedTable: "",
      columns: [],
      selectedCols: new Set(),
      limit: 100,
      offset: 0,
      rowsResult: null,
      busy: false,
      err: "",
      lastPayload: "",
    };
  }
  return dumpSessions.value[idx];
}

function currentTamper(): string[] {
  const tamper: string[] = [];
  if (tamperRandomcase.value) tamper.push("randomcase");
  if (tamperSpace2comment.value) tamper.push("space2comment");
  if (tamperEqualToLike.value) tamper.push("equaltolike");
  return tamper;
}

async function ensureUnion(f: Finding): Promise<boolean> {
  if (f.union_cols && f.union_position) return true;
  log.dim(`◌ probing UNION columns for ${f.location}:${f.param}…`);
  try {
    const r = await invoke<{ prefix: string; cols: number; position: number; dbms: string | null; extracted: Record<string, string> }>(
      "sqli_probe_union",
      {
        req: {
          url: url.value,
          method: method.value,
          body: body.value || null,
          headers: parseHeaders(),
          cookies: cookies.value || null,
          param: f.param,
          location: f.location,
          base_value: f.base_value,
          level: level.value,
          tamper: currentTamper(),
          timeout_ms: timeoutMs.value,
          follow_redirects: followRedirects.value,
        },
      },
    );
    f.prefix = r.prefix;
    f.union_cols = r.cols;
    f.union_position = r.position;
    if (r.dbms) f.dbms = r.dbms;
    if (r.extracted) {
      for (const [k, v] of Object.entries(r.extracted)) f.extracted[k] = v;
    }
    log.valid(`● UNION ok → ${r.cols} col(s), injectable @ position ${r.position}, prefix="${r.prefix}"`);
    return true;
  } catch (e: any) {
    log.err(`union probe: ${e}`);
    return false;
  }
}

async function callDump(f: Finding, action: string, extra: Partial<{
  database: string; table: string; columns: string[]; limit: number; offset: number; custom_sql: string;
}>): Promise<DumpResult> {
  return await invoke<DumpResult>("sqli_dump", {
    req: {
      url: url.value,
      method: method.value,
      body: body.value || null,
      headers: parseHeaders(),
      cookies: cookies.value || null,
      param: f.param,
      location: f.location,
      base_value: f.base_value,
      prefix: f.prefix,
      cols: f.union_cols ?? 1,
      position: f.union_position ?? 1,
      dbms: f.dbms ?? "MySQL",
      action,
      database: extra.database ?? null,
      table: extra.table ?? null,
      columns: extra.columns ?? null,
      limit: extra.limit ?? 100,
      offset: extra.offset ?? 0,
      custom_sql: extra.custom_sql ?? null,
      tamper: currentTamper(),
      timeout_ms: timeoutMs.value,
      follow_redirects: followRedirects.value,
    },
  });
}

async function listDatabases(idx: number, f: Finding) {
  const s = getOrCreateSession(idx, f);
  s.busy = true; s.err = "";
  try {
    if (!(await ensureUnion(f))) { s.err = "union probe failed"; return; }
    const r = await callDump(f, "databases", {});
    s.databases = r.rows.map(row => row[0]);
    s.lastPayload = r.raw_payload;
    log.valid(`● databases: ${s.databases.length} → ${s.databases.join(", ")}`);
  } catch (e: any) {
    s.err = String(e); log.err(`databases: ${e}`);
  } finally { s.busy = false; }
}

async function listTables(idx: number, f: Finding) {
  const s = getOrCreateSession(idx, f);
  if (!s.selectedDb) { s.err = "select a database first"; return; }
  s.busy = true; s.err = "";
  try {
    if (!(await ensureUnion(f))) { s.err = "union probe failed"; return; }
    const r = await callDump(f, "tables", { database: s.selectedDb });
    s.tables = r.rows.map(row => row[0]);
    s.lastPayload = r.raw_payload;
    log.valid(`● tables in ${s.selectedDb}: ${s.tables.length}`);
  } catch (e: any) {
    s.err = String(e); log.err(`tables: ${e}`);
  } finally { s.busy = false; }
}

async function listColumns(idx: number, f: Finding) {
  const s = getOrCreateSession(idx, f);
  if (!s.selectedTable) { s.err = "select a table first"; return; }
  s.busy = true; s.err = "";
  try {
    if (!(await ensureUnion(f))) { s.err = "union probe failed"; return; }
    const r = await callDump(f, "columns", { database: s.selectedDb, table: s.selectedTable });
    s.columns = r.rows.map(row => row[0]);
    s.selectedCols = new Set(s.columns);
    s.lastPayload = r.raw_payload;
    log.valid(`● columns in ${s.selectedTable}: ${s.columns.join(", ")}`);
  } catch (e: any) {
    s.err = String(e); log.err(`columns: ${e}`);
  } finally { s.busy = false; }
}

async function dumpRows(idx: number, f: Finding) {
  const s = getOrCreateSession(idx, f);
  if (!s.selectedTable) { s.err = "select a table first"; return; }
  if (s.selectedCols.size === 0) { s.err = "select at least one column"; return; }
  s.busy = true; s.err = "";
  try {
    if (!(await ensureUnion(f))) { s.err = "union probe failed"; return; }
    const orderedCols = s.columns.filter(c => s.selectedCols.has(c));
    const r = await callDump(f, "rows", {
      database: s.selectedDb,
      table: s.selectedTable,
      columns: orderedCols,
      limit: s.limit,
      offset: s.offset,
    });
    s.rowsResult = r;
    s.lastPayload = r.raw_payload;
    log.valid(`● dumped ${r.count} row(s) from ${s.selectedTable}${r.truncated ? " [TRUNCATED - increase group_concat_max_len]" : ""}`);
  } catch (e: any) {
    s.err = String(e); log.err(`dump: ${e}`);
  } finally { s.busy = false; }
}

function toggleCol(idx: number, f: Finding, col: string) {
  const s = getOrCreateSession(idx, f);
  if (s.selectedCols.has(col)) s.selectedCols.delete(col); else s.selectedCols.add(col);
  s.selectedCols = new Set(s.selectedCols);
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
  findings.value = [];
  log.clear();

  const techniques: string[] = [];
  if (tHeuristic.value) techniques.push("heuristic");
  if (tError.value) techniques.push("error");
  if (tBoolean.value) techniques.push("boolean");
  if (tUnion.value) techniques.push("union");
  if (tTime.value) techniques.push("time");
  if (!techniques.length) { log.err("pick at least one technique"); running.value = false; return; }

  const tamper: string[] = [];
  if (tamperRandomcase.value) tamper.push("randomcase");
  if (tamperSpace2comment.value) tamper.push("space2comment");
  if (tamperEqualToLike.value) tamper.push("equaltolike");

  const params = paramsFilter.value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);

  log.info(`target: ${method.value} ${url.value}`);
  log.info(`techniques: ${techniques.join(",")} | level=${level.value} risk=${risk.value} tamper=${tamper.join(",") || "none"}`);

  unlistens.push(await listen<string>("sqli:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<Finding>("sqli:hit", (e) => {
    const f = e.payload;
    findings.value.push(f);
    const dbms = f.dbms ? ` [DBMS:${f.dbms}]` : "";
    log.hit(`[${f.confidence}] ${f.technique}  ${f.location}:${f.param}${dbms}`);
    log.hit(`  payload:  ${f.full_payload}`);
    log.hit(`  evidence: ${f.evidence}`);
    for (const [k, v] of Object.entries(f.extracted)) {
      log.valid(`  ${k} = ${v}`);
    }
  }));

  try {
    const result = await invoke<Finding[]>("sqli_scan", {
      req: {
        url: url.value,
        method: method.value,
        body: body.value || null,
        headers: parseHeaders(),
        cookies: cookies.value || null,
        params: params.length ? params : null,
        techniques,
        level: level.value,
        risk: risk.value,
        stop_on_first: stopOnFirst.value,
        auto_extract: autoExtract.value,
        tamper,
        concurrency: concurrency.value,
        timeout_ms: timeoutMs.value,
        follow_redirects: followRedirects.value,
      },
    });
    // Replace with final results (has backfilled union_cols/union_position)
    if (result && result.length) findings.value = result;
    log.ok(`scan done: ${findings.value.length} injection point(s)`);

    // summary table
    if (findings.value.length) {
      const cols = { param: 5, loc: 3, tech: 4, dbms: 4, conf: 4, payload: 7 };
      for (const f of findings.value) {
        cols.param = Math.max(cols.param, f.param.length);
        cols.loc   = Math.max(cols.loc, f.location.length);
        cols.tech  = Math.max(cols.tech, f.technique.length);
        cols.dbms  = Math.max(cols.dbms, (f.dbms || "-").length);
        cols.conf  = Math.max(cols.conf, f.confidence.length);
        cols.payload = Math.max(cols.payload, Math.min(f.full_payload.length, 48));
      }
      const pad = (s: string, w: number) => s.length > w ? s.slice(0, w - 1) + "…" : s.padEnd(w);
      const hdr = `${pad("Param", cols.param)} │ ${pad("Loc", cols.loc)} │ ${pad("Tech", cols.tech)} │ ${pad("DBMS", cols.dbms)} │ ${pad("Conf", cols.conf)} │ ${pad("Payload", cols.payload)}`;
      const sep = `${"─".repeat(cols.param)}─┼─${"─".repeat(cols.loc)}─┼─${"─".repeat(cols.tech)}─┼─${"─".repeat(cols.dbms)}─┼─${"─".repeat(cols.conf)}─┼─${"─".repeat(cols.payload)}`;
      log.info(hdr);
      log.dim(sep);
      for (const f of findings.value) {
        log.hit(`${pad(f.param, cols.param)} │ ${pad(f.location, cols.loc)} │ ${pad(f.technique, cols.tech)} │ ${pad(f.dbms || "-", cols.dbms)} │ ${pad(f.confidence, cols.conf)} │ ${pad(f.full_payload, cols.payload)}`);
      }
    }
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <div class="row">
        <select v-model="method" class="method-sel">
          <option>GET</option>
          <option>POST</option>
          <option>PUT</option>
          <option>PATCH</option>
        </select>
        <input v-model="url" class="url-input" placeholder="https://target.com/item?id=1  (use * to mark injection point)" spellcheck="false" />
      </div>

      <details class="adv" open>
        <summary>request · body · cookies · headers</summary>
        <label class="ta">
          <span class="lbl">body (POST/PUT) · <code>*</code> marks injection point</span>
          <textarea class="term-input" v-model="body" rows="2" spellcheck="false" placeholder="user=admin&id=1*" />
        </label>
        <label class="ta">
          <span class="lbl">cookies · <code>*</code> marks injection point</span>
          <input class="inp" v-model="cookies" placeholder='sess=abc123; tracking=xxx*' />
        </label>
        <label class="ta">
          <span class="lbl">headers · <code>*</code> on value to inject there</span>
          <textarea class="term-input" v-model="headersRaw" rows="2" spellcheck="false" placeholder="Referer: https://x.com&#10;X-Forwarded-For: 1.2.3.4*" />
        </label>
        <Prompt label="params filter" v-model="paramsFilter" placeholder="id,cat (blank = test all)" />
      </details>

      <details class="adv">
        <summary>techniques</summary>
        <div class="row">
          <label class="toggle"><input type="checkbox" v-model="tHeuristic" /><span>heuristic</span></label>
          <label class="toggle"><input type="checkbox" v-model="tError" /><span>error</span></label>
          <label class="toggle"><input type="checkbox" v-model="tBoolean" /><span>bool-blind</span></label>
          <label class="toggle"><input type="checkbox" v-model="tUnion" /><span>union</span></label>
          <label class="toggle"><input type="checkbox" v-model="tTime" /><span>time-blind</span></label>
        </div>
      </details>

      <details class="adv">
        <summary>tuning · level / risk / tamper</summary>
        <div class="row">
          <label class="mini"><span>level</span><input v-model.number="level" type="number" min="1" max="3" /></label>
          <label class="mini"><span>risk</span><input v-model.number="risk" type="number" min="1" max="3" /></label>
          <label class="toggle"><input type="checkbox" v-model="stopOnFirst" /><span>stop first</span></label>
          <label class="toggle"><input type="checkbox" v-model="autoExtract" /><span>extract</span></label>
          <label class="toggle"><input type="checkbox" v-model="followRedirects" /><span>follow</span></label>
        </div>
        <div class="row">
          <span class="waf-label">tamper/WAF</span>
          <label class="toggle"><input type="checkbox" v-model="tamperRandomcase" /><span>randomcase</span></label>
          <label class="toggle"><input type="checkbox" v-model="tamperSpace2comment" /><span>space→/**/</span></label>
          <label class="toggle"><input type="checkbox" v-model="tamperEqualToLike" /><span>=→LIKE</span></label>
        </div>
      </details>

      <div class="row">
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="20" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="2000" max="60000" /></label>
      </div>

      <div class="row">
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ injecting... ]" : "> inject" }}</button>
      </div>
    </div>

    <div v-if="findings.length" class="findings">
      <div v-for="(f, i) in findings" :key="i" class="finding" :class="`conf-${f.confidence.toLowerCase()}`">
        <div class="f-head">
          <span class="f-tech">{{ f.technique }}</span>
          <span class="f-loc">{{ f.location }} / <b>{{ f.param }}</b></span>
          <span v-if="f.dbms" class="f-dbms">{{ f.dbms }}</span>
          <span v-if="f.union_cols" class="f-dbms">{{ f.union_cols }}col @ {{ f.union_position }}</span>
          <span class="sev" :class="`sev-${f.confidence.toLowerCase()}`">{{ f.confidence }}</span>
        </div>
        <div class="f-payload">
          <span class="f-prefix" v-if="f.prefix">prefix <code>{{ f.prefix }}</code></span>
          <span class="f-suffix" v-if="f.suffix">suffix <code>{{ f.suffix }}</code></span>
        </div>
        <pre class="f-full">{{ f.full_payload }}</pre>
        <div class="f-evidence">» {{ f.evidence }}</div>
        <div v-if="Object.keys(f.extracted).length" class="f-extracted">
          <div v-for="(v, k) in f.extracted" :key="k" class="kv">
            <span class="k">{{ k }}:</span> <span class="v">{{ v }}</span>
          </div>
        </div>

        <!-- Dump panel — shown for any finding. Union cols are
             probed on-demand if the scan never ran UNION. -->
        <div class="dump-panel">
          <div class="dump-head">[ DUMP ]
            <span v-if="!f.union_cols" class="dump-hint">union will be probed on first click</span>
          </div>

          <div class="dump-row">
            <button class="mini-btn" :disabled="(dumpSessions[i]?.busy)" @click="listDatabases(i, f)">
              {{ dumpSessions[i]?.busy ? "…" : "list databases" }}
            </button>
            <select v-if="dumpSessions[i]?.databases?.length"
                    v-model="dumpSessions[i].selectedDb"
                    @change="dumpSessions[i].tables = []; dumpSessions[i].columns = []; dumpSessions[i].rowsResult = null">
              <option value="">— db —</option>
              <option v-for="d in dumpSessions[i].databases" :key="d" :value="d">{{ d }}</option>
            </select>
          </div>

          <div v-if="dumpSessions[i]?.selectedDb" class="dump-row">
            <button class="mini-btn" :disabled="dumpSessions[i].busy" @click="listTables(i, f)">
              {{ dumpSessions[i].busy ? "…" : "list tables" }}
            </button>
            <select v-if="dumpSessions[i]?.tables?.length"
                    v-model="dumpSessions[i].selectedTable"
                    @change="dumpSessions[i].columns = []; dumpSessions[i].rowsResult = null">
              <option value="">— table —</option>
              <option v-for="t in dumpSessions[i].tables" :key="t" :value="t">{{ t }}</option>
            </select>
          </div>

          <div v-if="dumpSessions[i]?.selectedTable" class="dump-row">
            <button class="mini-btn" :disabled="dumpSessions[i].busy" @click="listColumns(i, f)">
              {{ dumpSessions[i].busy ? "…" : "list columns" }}
            </button>
          </div>

          <div v-if="dumpSessions[i]?.columns?.length" class="col-chips">
            <label v-for="c in dumpSessions[i].columns" :key="c" class="col-chip" :class="{ on: dumpSessions[i].selectedCols.has(c) }">
              <input type="checkbox" :checked="dumpSessions[i].selectedCols.has(c)" @change="toggleCol(i, f, c)" />
              <span>{{ c }}</span>
            </label>
          </div>

          <div v-if="dumpSessions[i]?.columns?.length" class="dump-row">
            <label class="mini"><span>limit</span><input v-model.number="dumpSessions[i].limit" type="number" min="1" max="10000" /></label>
            <label class="mini"><span>offset</span><input v-model.number="dumpSessions[i].offset" type="number" min="0" /></label>
            <button class="mini-btn hit" :disabled="dumpSessions[i].busy" @click="dumpRows(i, f)">
              {{ dumpSessions[i].busy ? "…" : "> dump rows" }}
            </button>
          </div>

          <div v-if="dumpSessions[i]?.err" class="dump-err">{{ dumpSessions[i].err }}</div>

          <div v-if="dumpSessions[i]?.rowsResult" class="dump-table-wrap">
            <div class="dump-meta">
              {{ dumpSessions[i].rowsResult.count }} row(s)
              <span v-if="dumpSessions[i].rowsResult.truncated" class="trunc">· TRUNCATED</span>
            </div>
            <table class="dump-table">
              <thead><tr><th v-for="h in dumpSessions[i].rowsResult.headers" :key="h">{{ h }}</th></tr></thead>
              <tbody>
                <tr v-for="(row, ri) in dumpSessions[i].rowsResult.rows" :key="ri">
                  <td v-for="(cell, ci) in row" :key="ci">{{ cell }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <details v-if="dumpSessions[i]?.lastPayload" class="dump-payload">
            <summary>last payload</summary>
            <pre>{{ dumpSessions[i].lastPayload }}</pre>
          </details>
        </div>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="sqli // sqlmap-style detection" @clear="log.clear()" />
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
  flex-shrink: 0;
}
.method-sel option { background: var(--bg); color: var(--fg); }
.url-input {
  flex: 1;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 4px 8px;
  font-size: 12px;
  min-width: 0;
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

code {
  color: var(--info);
  background: var(--bg);
  padding: 0 4px;
  border: 1px solid var(--border);
  font-size: 10px;
}
.waf-label {
  color: var(--warn);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  align-self: center;
  padding-right: 4px;
}

.findings { display: flex; flex-direction: column; gap: 6px; max-height: 300px; overflow-y: auto; }
.finding {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  padding: 6px 8px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.finding.conf-high { border-left: 3px solid var(--alert); }
.finding.conf-medium { border-left: 3px solid var(--warn); }
.finding.conf-low { border-left: 3px solid var(--fg-dim); }
.f-head { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; font-size: 11px; }
.f-tech {
  font-weight: 700;
  color: var(--alert);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-size: 10px;
}
.f-loc { color: var(--info); font-size: 11px; }
.f-loc b { color: var(--fg); }
.f-dbms { color: var(--valid); font-size: 10px; border: 1px solid var(--valid); padding: 0 5px; }
.f-payload { display: flex; gap: 8px; font-size: 10px; color: var(--fg-dim); flex-wrap: wrap; }
.f-full {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 4px 6px;
  font-size: 11px;
  color: var(--valid);
  white-space: pre-wrap;
  word-break: break-all;
  font-family: var(--mono);
  margin: 0;
}
.f-evidence { color: var(--fg-dim); font-size: 10px; font-style: italic; }
.f-extracted {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 3px;
  margin-top: 3px;
}
.kv {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 2px 6px;
  font-size: 10px;
}
.kv .k { color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; font-size: 9px; }
.kv .v { color: var(--valid); font-weight: 700; }

.dump-panel {
  margin-top: 6px;
  padding-top: 6px;
  border-top: 1px dashed var(--border);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.dump-head {
  color: var(--alert);
  font-size: 9px;
  letter-spacing: 0.25em;
  font-weight: 700;
}
.dump-hint { color: var(--fg-ghost); font-size: 9px; letter-spacing: 0.1em; margin-left: 6px; font-weight: 400; text-transform: none; }
.dump-row {
  display: flex;
  gap: 6px;
  align-items: center;
  flex-wrap: wrap;
}
.mini-btn {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 3px 10px;
  font-family: inherit;
  font-size: 10px;
  cursor: pointer;
  flex-shrink: 0;
  height: auto;
}
.mini-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.mini-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.mini-btn.hit { border-color: var(--alert); color: var(--alert); }
.mini-btn.hit:hover:not(:disabled) { background: rgba(255, 47, 74, 0.08); }
.dump-panel select {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 3px 6px;
  font-family: inherit;
  font-size: 11px;
  min-width: 120px;
}
.dump-panel select:focus { border-color: var(--accent); outline: none; }
.col-chips { display: flex; flex-wrap: wrap; gap: 3px; }
.col-chip {
  display: inline-flex;
  gap: 4px;
  align-items: center;
  padding: 1px 6px;
  border: 1px solid var(--border);
  font-size: 10px;
  color: var(--fg-dim);
  cursor: pointer;
}
.col-chip input { display: none; }
.col-chip.on { color: var(--valid); border-color: var(--valid); background: rgba(92, 217, 130, 0.06); }
.dump-err { color: var(--alert); font-size: 10px; font-family: var(--mono); }
.dump-meta { color: var(--fg-dim); font-size: 10px; }
.dump-meta .trunc { color: var(--warn); margin-left: 6px; }
.dump-table-wrap { max-height: 240px; overflow: auto; border: 1px solid var(--border); }
.dump-table {
  border-collapse: collapse;
  width: 100%;
  font-size: 10px;
  font-family: var(--mono);
}
.dump-table th, .dump-table td {
  border: 1px solid var(--border);
  padding: 2px 6px;
  text-align: left;
  white-space: nowrap;
  max-width: 240px;
  overflow: hidden;
  text-overflow: ellipsis;
}
.dump-table th { background: var(--bg); color: var(--alert); text-transform: uppercase; letter-spacing: 0.1em; font-size: 9px; }
.dump-table td { color: var(--valid); }
.dump-payload summary { font-size: 9px; color: var(--fg-ghost); text-transform: uppercase; letter-spacing: 0.15em; cursor: pointer; }
.dump-payload pre {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 4px 6px;
  font-size: 10px;
  color: var(--fg-dim);
  white-space: pre-wrap;
  word-break: break-all;
  margin: 4px 0 0;
  max-height: 120px;
  overflow: auto;
}
</style>
