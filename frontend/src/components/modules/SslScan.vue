<script setup lang="ts">
import { ref } from "vue";
import { invoke } from "../../lib/api";
import Prompt from "../Prompt.vue";
import Terminal from "../Terminal.vue";
import { useTerminal } from "../../composables/useTerminal";

interface Cert {
  subject: string;
  issuer: string;
  serial: string;
  not_before: string;
  not_after: string;
  days_remaining: number;
  sans: string[];
  key_algo: string;
  signature_algo: string;
  sha256_fingerprint: string;
  is_ca: boolean;
  self_signed: boolean;
  expired: boolean;
}
interface Report {
  host: string;
  port: number;
  tls_version: string;
  cipher_suite?: string;
  sni_presented: string;
  cert_chain: Cert[];
  chain_valid: boolean;
  issues: string[];
  alpn?: string;
}

const host = ref("insecure.newploit.com");
const port = ref(443);
const timeoutMs = ref(8000);
const running = ref(false);
const report = ref<Report | null>(null);
const log = useTerminal();

async function run() {
  if (running.value) return;
  running.value = true;
  report.value = null;
  log.clear();
  try {
    report.value = await invoke<Report>("ssl_scan", {
      req: { host: host.value.trim(), port: port.value, timeout_ms: timeoutMs.value },
    });
    const r = report.value;
    log.valid(`${r.tls_version}${r.cipher_suite ? " / " + r.cipher_suite : ""}${r.alpn ? " / ALPN: " + r.alpn : ""}`);
    log.info(`chain: ${r.cert_chain.length} cert(s)`);
    for (const iss of r.issues) log.warn(iss);
  } catch (e: any) { log.err(String(e)); }
  finally { running.value = false; }
}

function daysClass(d: number) {
  if (d < 0) return "expired";
  if (d < 14) return "warn";
  return "ok";
}
</script>

<template>
  <div class="module">
    <div class="form">
      <Prompt label="host" v-model="host" placeholder="example.com" />
      <div class="row">
        <label class="mini"><span>port</span><input v-model.number="port" type="number" min="1" max="65535" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="1000" max="30000" /></label>
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ handshaking... ]" : "> inspect" }}</button>
      </div>
    </div>

    <div v-if="report" class="report">
      <div class="meta">
        <span class="meta-k">TLS</span>
        <span class="meta-v tls">{{ report.tls_version }}</span>
        <span v-if="report.cipher_suite" class="meta-v">{{ report.cipher_suite }}</span>
        <span v-if="report.alpn" class="meta-v alpn">ALPN: {{ report.alpn }}</span>
      </div>

      <div v-if="report.issues.length" class="issues">
        <div class="issues-head">⚠ {{ report.issues.length }} issue(s)</div>
        <div v-for="(i, idx) in report.issues" :key="idx" class="issue">» {{ i }}</div>
      </div>

      <div v-for="(c, i) in report.cert_chain" :key="i" class="cert">
        <div class="cert-head">
          <span class="cert-idx">[{{ i === 0 ? "LEAF" : i === report.cert_chain.length - 1 ? "ROOT" : `CHAIN ${i}` }}]</span>
          <span class="cert-subj">{{ c.subject.slice(0, 80) }}</span>
          <span v-if="c.expired" class="tag danger">EXPIRED</span>
          <span v-else-if="c.days_remaining < 14" class="tag warn">{{ c.days_remaining }}d</span>
          <span v-else class="tag ok">{{ c.days_remaining }}d</span>
        </div>
        <div class="cert-row"><span class="k">issuer</span><span>{{ c.issuer }}</span></div>
        <div class="cert-row"><span class="k">valid</span><span>{{ c.not_before }} → {{ c.not_after }}</span></div>
        <div class="cert-row"><span class="k">days</span><span :class="daysClass(c.days_remaining)">{{ c.days_remaining }}</span></div>
        <div class="cert-row"><span class="k">key</span><span>{{ c.key_algo }}</span></div>
        <div class="cert-row"><span class="k">sig</span><span>{{ c.signature_algo }}</span></div>
        <div v-if="c.sans.length" class="cert-row sans-row">
          <span class="k">SANs ×{{ c.sans.length }}</span>
          <span class="sans">{{ c.sans.join(", ") }}</span>
        </div>
        <div class="cert-row"><span class="k">sha256</span><span class="fp">{{ c.sha256_fingerprint }}</span></div>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="ssl // tls inspector" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.report { display: flex; flex-direction: column; gap: 6px; max-height: 440px; overflow-y: auto; }

.meta { display: flex; gap: 6px; flex-wrap: wrap; padding: 6px 10px; background: var(--bg-panel); border: 1px solid var(--border); font-size: 11px; }
.meta-k { color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.15em; font-size: 10px; }
.meta-v { color: var(--fg); padding: 0 6px; border: 1px solid var(--border-hot); font-size: 10px; }
.meta-v.tls { color: var(--valid); border-color: var(--valid); }
.meta-v.alpn { color: var(--info); border-color: var(--info); }

.issues { background: rgba(255, 47, 74, 0.05); border: 1px solid var(--alert); padding: 6px 10px; }
.issues-head { color: var(--alert); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 3px; }
.issue { color: var(--alert); font-size: 11px; padding: 1px 0; }

.cert { background: var(--bg-panel); border: 1px solid var(--border); padding: 6px 10px; }
.cert-head { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; padding-bottom: 4px; border-bottom: 1px solid var(--border); margin-bottom: 4px; }
.cert-idx { color: var(--alert); font-size: 10px; font-weight: 700; letter-spacing: 0.15em; flex-shrink: 0; }
.cert-subj { color: var(--fg); font-size: 11px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.tag { font-size: 9px; padding: 1px 5px; border: 1px solid; letter-spacing: 0.1em; flex-shrink: 0; }
.tag.ok { color: var(--valid); border-color: var(--valid); }
.tag.warn { color: var(--warn); border-color: var(--warn); }
.tag.danger { color: var(--alert); border-color: var(--alert); }

.cert-row { display: flex; gap: 8px; font-size: 10px; padding: 1px 0; }
.cert-row .k { color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; min-width: 60px; flex-shrink: 0; font-size: 9px; }
.cert-row .k + span { color: var(--fg); word-break: break-all; }
.cert-row .expired { color: var(--alert); }
.cert-row .warn { color: var(--warn); }
.cert-row .ok { color: var(--valid); }
.sans { color: var(--info) !important; font-size: 10px; word-break: break-all; }
.fp { color: var(--fg-dim) !important; font-size: 9px; word-break: break-all; }
</style>
