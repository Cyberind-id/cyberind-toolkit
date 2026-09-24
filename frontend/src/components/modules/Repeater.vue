<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { invoke } from "../../lib/api";

interface RepeaterResp {
  status: number;
  status_text: string;
  http_version: string;
  headers: [string, string][];
  body: string;
  body_len: number;
  content_type?: string;
  time_ms: number;
  final_url: string;
  redirected: boolean;
  is_text: boolean;
}

interface HistoryItem {
  ts: number;
  method: string;
  url: string;
  headers_raw: string;
  body: string;
  status?: number;
  time_ms?: number;
}

const method = ref("GET");
const url = ref("https://insecure.newploit.com/");
const headersRaw = ref("User-Agent: Mozilla/5.0 (Cyberind Toolkit)\nAccept: */*");
const body = ref("");
const followRedirects = ref(false);
const ignoreTls = ref(true);
const timeoutMs = ref(15000);
const sending = ref(false);
const resp = ref<RepeaterResp | null>(null);
const err = ref("");
const history = ref<HistoryItem[]>([]);
const tab = ref<"body" | "preview" | "headers" | "curl">("body");
const curlText = ref("");

const methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function parseHeaders(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of headersRaw.value.split("\n")) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

const payload = computed(() => ({
  method: method.value,
  url: url.value,
  headers: parseHeaders(),
  body: body.value || null,
  timeout_ms: timeoutMs.value,
  follow_redirects: followRedirects.value,
  ignore_tls: ignoreTls.value,
}));

const previewKind = computed<"html" | "json" | "xml" | "image" | "text" | "none">(() => {
  const r = resp.value;
  if (!r) return "none";
  const ct = (r.content_type ?? "").toLowerCase();
  if (ct.includes("html") || r.body.trim().startsWith("<!DOCTYPE") || r.body.trim().startsWith("<html")) return "html";
  if (ct.includes("json") || (r.body.trim().startsWith("{") || r.body.trim().startsWith("["))) return "json";
  if (ct.includes("xml") || r.body.trim().startsWith("<?xml")) return "xml";
  if (ct.startsWith("image/")) return "image";
  return "text";
});

const prettyBody = computed(() => {
  const r = resp.value;
  if (!r) return "";
  try {
    if (previewKind.value === "json") {
      return JSON.stringify(JSON.parse(r.body), null, 2);
    }
    if (previewKind.value === "xml") {
      return prettyXml(r.body);
    }
  } catch {}
  return r.body;
});

function prettyXml(xml: string): string {
  let formatted = "";
  let indent = 0;
  const nodes = xml.replace(/(>)(<)(\/*)/g, "$1\n$2$3").split("\n");
  for (const line of nodes) {
    const t = line.trim();
    if (!t) continue;
    if (t.match(/^<\/.+>/)) indent = Math.max(0, indent - 1);
    formatted += "  ".repeat(indent) + t + "\n";
    if (t.match(/^<[^/!?][^>]*[^/]>$/) && !t.match(/<.+<\/.+>/)) indent++;
  }
  return formatted;
}

function isSafeBody(b: string): boolean {
  // limit preview to 2MB to avoid browser lag
  return b.length < 2_000_000;
}

async function send() {
  if (sending.value) return;
  sending.value = true;
  err.value = "";
  resp.value = null;
  try {
    resp.value = await invoke<RepeaterResp>("repeater_send", { req: payload.value });
    tab.value = "body";
    pushHistory(resp.value);
  } catch (e: any) {
    err.value = String(e);
  } finally {
    sending.value = false;
  }
}

function pushHistory(r: RepeaterResp) {
  const item: HistoryItem = {
    ts: Date.now(),
    method: method.value,
    url: url.value,
    headers_raw: headersRaw.value,
    body: body.value,
    status: r.status,
    time_ms: r.time_ms,
  };
  history.value.unshift(item);
  if (history.value.length > 30) history.value.pop();
  localStorage.setItem("repeater:history", JSON.stringify(history.value));
}

function loadHistory(h: HistoryItem) {
  method.value = h.method;
  url.value = h.url;
  headersRaw.value = h.headers_raw;
  body.value = h.body;
}

async function buildCurl() {
  try {
    curlText.value = await invoke<string>("repeater_to_curl", { req: payload.value });
    tab.value = "curl";
  } catch (e: any) {
    err.value = String(e);
  }
}

async function copyTo(text: string) {
  try { await navigator.clipboard.writeText(text); } catch {}
}

function statusClass(s: number) {
  if (s >= 200 && s < 300) return "s-2xx";
  if (s >= 300 && s < 400) return "s-3xx";
  if (s >= 400 && s < 500) return "s-4xx";
  return "s-5xx";
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

onMounted(() => {
  try { history.value = JSON.parse(localStorage.getItem("repeater:history") || "[]"); } catch {}
});
</script>

<template>
  <div class="module">
    <div class="req-row">
      <select v-model="method" class="method-sel">
        <option v-for="m in methods" :key="m">{{ m }}</option>
      </select>
      <input v-model="url" class="url-input" placeholder="https://target.com/path" spellcheck="false" />
    </div>

    <div class="row">
      <label class="toggle"><input type="checkbox" v-model="followRedirects" /><span>follow</span></label>
      <label class="toggle"><input type="checkbox" v-model="ignoreTls" /><span>ignore-tls</span></label>
      <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="1000" max="120000" /></label>
      <button class="btn-ghost curl-btn" @click="buildCurl">→ curl</button>
    </div>

    <button class="exec send-btn" :disabled="sending" @click="send">{{ sending ? "[ sending... ]" : "▸ SEND" }}</button>

    <div class="split">
      <div class="pane">
        <div class="pane-head">request</div>
        <label class="ta">
          <span class="lbl">headers (Key: Value per line)</span>
          <textarea class="term-input" v-model="headersRaw" rows="4" spellcheck="false" />
        </label>
        <label class="ta">
          <span class="lbl">body</span>
          <textarea class="term-input body-area" v-model="body" rows="6" spellcheck="false" placeholder='{"k":"v"} or form data' />
        </label>
      </div>

      <div class="pane">
        <div class="pane-head">response</div>

        <div v-if="err" class="err-box">{{ err }}</div>

        <div v-else-if="resp" class="resp-wrap">
          <div class="resp-meta">
            <span class="stat-badge" :class="statusClass(resp.status)">{{ resp.status }} {{ resp.status_text }}</span>
            <span class="resp-time">{{ resp.time_ms }}ms</span>
            <span class="resp-size">{{ fmtBytes(resp.body_len) }}</span>
            <span v-if="resp.redirected" class="resp-redirect">→ redirected</span>
            <button class="btn-ghost tiny" @click="copyTo(resp!.body)">copy body</button>
          </div>
          <div class="tabs-mini">
            <button :class="{ on: tab === 'body' }" @click="tab = 'body'">body</button>
            <button :class="{ on: tab === 'preview' }" @click="tab = 'preview'">
              preview <span class="kind-tag">[{{ previewKind }}]</span>
            </button>
            <button :class="{ on: tab === 'headers' }" @click="tab = 'headers'">headers ({{ resp.headers.length }})</button>
            <button :class="{ on: tab === 'curl' }" @click="tab = 'curl'" :disabled="!curlText">curl</button>
          </div>

          <pre v-if="tab === 'body'" class="body-view">{{ resp.is_text ? resp.body : "[binary response — " + fmtBytes(resp.body_len) + "]" }}</pre>

          <div v-else-if="tab === 'preview'" class="preview-wrap">
            <iframe
              v-if="previewKind === 'html' && isSafeBody(resp.body)"
              class="html-frame"
              :srcdoc="resp.body"
              sandbox="allow-same-origin"
              referrerpolicy="no-referrer"
            ></iframe>
            <pre v-else-if="previewKind === 'json'" class="body-view json-view">{{ prettyBody }}</pre>
            <pre v-else-if="previewKind === 'xml'" class="body-view xml-view">{{ prettyBody }}</pre>
            <div v-else-if="previewKind === 'image'" class="preview-msg">image/binary content — preview unavailable (response was read as text)</div>
            <div v-else-if="!isSafeBody(resp.body)" class="preview-msg">response too large to preview safely ({{ fmtBytes(resp.body_len) }}) — use body tab</div>
            <div v-else class="preview-msg">no structured preview for this content-type — showing plain text</div>
          </div>

          <div v-else-if="tab === 'headers'" class="hdr-list">
            <div v-for="[k, v] in resp.headers" :key="k + v" class="hdr-item">
              <span class="hdr-k">{{ k }}</span>
              <span class="hdr-v">{{ v }}</span>
            </div>
          </div>
          <pre v-else-if="tab === 'curl'" class="body-view curl-view">{{ curlText }}</pre>
        </div>

        <div v-else class="placeholder">no response yet — hit SEND</div>
      </div>
    </div>

    <details class="adv">
      <summary>history · {{ history.length }}</summary>
      <div class="hist-list">
        <div v-if="!history.length" class="placeholder">no history yet</div>
        <div v-for="(h, i) in history" :key="i" class="hist-row" @click="loadHistory(h)">
          <span class="h-method">{{ h.method }}</span>
          <span v-if="h.status" class="stat-badge tiny" :class="statusClass(h.status)">{{ h.status }}</span>
          <span class="h-url">{{ h.url }}</span>
          <span class="h-time">{{ h.time_ms }}ms</span>
        </div>
      </div>
    </details>
  </div>
</template>

<style scoped>
.req-row {
  display: flex;
  gap: 4px;
  align-items: stretch;
  min-width: 0;
  width: 100%;
}
.method-sel {
  background: var(--bg-panel);
  border: 1px solid var(--alert);
  color: var(--alert);
  padding: 4px 8px;
  font-weight: 700;
  font-size: 12px;
  font-family: inherit;
  flex: 0 0 auto;
  min-width: 80px;
}
.method-sel option { background: var(--bg); color: var(--fg); }
.url-input {
  flex: 1 1 auto;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 4px 8px;
  font-size: 12px;
  min-width: 0;
}
.url-input:focus { border-color: var(--accent); outline: none; }

.send-btn {
  flex: 0 0 auto;
  padding: 8px 12px;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  width: 100%;
  min-width: 0;
  height: auto;
}
.exec.small { padding: 4px 14px; font-size: 12px; font-weight: 700; letter-spacing: 0.1em; }
.curl-btn { margin-left: auto; }

.split {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
  min-height: 0;
  flex: 1;
}
.pane {
  display: flex;
  flex-direction: column;
  gap: 4px;
  border: 1px solid var(--border);
  background: var(--bg-panel);
  padding: 6px;
  min-width: 0;
  min-height: 0;
}
.pane-head {
  font-size: 10px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.15em;
  border-bottom: 1px solid var(--border);
  padding-bottom: 3px;
}
.body-area { min-height: 90px; }

.resp-wrap { display: flex; flex-direction: column; gap: 6px; min-height: 0; flex: 1; }
.resp-meta { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; font-size: 11px; }
.stat-badge {
  padding: 1px 6px;
  font-weight: 700;
  border: 1px solid;
  font-size: 10px;
  letter-spacing: 0.05em;
}
.stat-badge.tiny { padding: 0 4px; font-size: 9px; }
.s-2xx { color: var(--valid); border-color: var(--valid); background: rgba(92, 217, 130, 0.07); }
.s-3xx { color: var(--info); border-color: var(--info); }
.s-4xx { color: var(--warn); border-color: var(--warn); }
.s-5xx { color: var(--alert); border-color: var(--alert); }
.resp-time, .resp-size { color: var(--fg-dim); font-size: 10px; font-variant-numeric: tabular-nums; }
.resp-redirect { color: var(--info); font-size: 10px; }
.btn-ghost.tiny { padding: 1px 6px; font-size: 9px; margin-left: auto; }

.tabs-mini { display: flex; border-bottom: 1px solid var(--border); }
.tabs-mini button {
  padding: 3px 10px;
  color: var(--fg-dim);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
}
.tabs-mini button.on { color: var(--alert); border-bottom-color: var(--alert); }
.tabs-mini button:disabled { opacity: 0.4; cursor: not-allowed; }

.body-view {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 6px 8px;
  font-size: 11px;
  color: var(--fg);
  overflow: auto;
  max-height: 280px;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: var(--mono);
  line-height: 1.4;
}
.curl-view { color: var(--valid); white-space: pre-wrap; }
.json-view { color: var(--info); }
.xml-view { color: var(--warn); }
.kind-tag { color: var(--fg-ghost); font-size: 8px; margin-left: 2px; }

.preview-wrap {
  background: var(--bg);
  border: 1px solid var(--border);
  max-height: 320px;
  overflow: hidden;
  display: flex;
}
.html-frame {
  width: 100%;
  min-height: 280px;
  border: none;
  background: #fff;
}
.preview-msg {
  padding: 20px;
  color: var(--fg-ghost);
  font-size: 11px;
  text-align: center;
  font-style: italic;
  width: 100%;
}

.hdr-list {
  max-height: 280px;
  overflow-y: auto;
  border: 1px solid var(--border);
  background: var(--bg);
}
.hdr-item {
  display: flex;
  gap: 6px;
  padding: 2px 6px;
  font-size: 10px;
  border-bottom: 1px solid var(--border);
}
.hdr-item:last-child { border: none; }
.hdr-k { color: var(--info); flex-shrink: 0; min-width: 0; max-width: 200px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; }
.hdr-v { color: var(--fg-dim); word-break: break-all; }

.err-box {
  padding: 8px;
  color: var(--alert);
  border: 1px solid var(--alert);
  background: rgba(255, 47, 74, 0.05);
  font-size: 11px;
  word-break: break-all;
}

.placeholder {
  color: var(--fg-ghost);
  font-size: 11px;
  text-align: center;
  padding: 20px;
  font-style: italic;
}

.adv { border: 1px solid var(--border); background: var(--bg-panel); padding: 4px 8px; }
.adv summary { cursor: pointer; font-size: 10px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; }
.hist-list { display: flex; flex-direction: column; gap: 2px; margin-top: 6px; max-height: 200px; overflow-y: auto; }
.hist-row {
  display: flex;
  gap: 6px;
  align-items: center;
  padding: 3px 6px;
  font-size: 11px;
  cursor: pointer;
  border: 1px solid transparent;
}
.hist-row:hover { border-color: var(--border-hot); background: var(--bg); }
.h-method { color: var(--alert); font-weight: 700; min-width: 50px; }
.h-url { flex: 1; color: var(--fg-dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.h-time { color: var(--fg-ghost); font-size: 9px; }

@media (max-width: 640px) {
  .split { grid-template-columns: 1fr; }
  .body-view, .hdr-list { max-height: 200px; }
}
</style>
