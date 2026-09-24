<script setup lang="ts">
import { ref } from "vue";
import { invoke } from "../../lib/api";
import Prompt from "../Prompt.vue";
import Terminal from "../Terminal.vue";
import { useTerminal } from "../../composables/useTerminal";

interface DnsRecord { rtype: string; values: string[]; }
interface Axfr { success: boolean; nameserver: string; records_dumped: string[]; error?: string; }
interface Report {
  domain: string;
  records: DnsRecord[];
  axfr?: Axfr;
  dnssec: { dnskey_count: number; has_dnssec: boolean };
  errors: string[];
}

const domain = ref("insecure.newploit.com");
const resolver = ref("");
const tryAxfr = ref(false);
const running = ref(false);
const report = ref<Report | null>(null);
const log = useTerminal();

async function run() {
  if (running.value) return;
  running.value = true;
  log.clear();
  report.value = null;
  try {
    report.value = await invoke<Report>("dns_query", {
      req: {
        domain: domain.value.trim(),
        resolver: resolver.value.trim() || null,
        types: null,
        try_axfr: tryAxfr.value,
      },
    });
    log.ok(`${report.value.records.reduce((a, b) => a + b.values.length, 0)} records resolved`);
    if (report.value.dnssec.has_dnssec) log.valid(`DNSSEC: ${report.value.dnssec.dnskey_count} DNSKEY record(s)`);
    else log.dim("DNSSEC: none");
    if (report.value.axfr) {
      if (report.value.axfr.success) log.hit(`AXFR SUCCESS on ${report.value.axfr.nameserver} — ${report.value.axfr.records_dumped.length} records leaked`);
      else log.warn(`AXFR refused: ${report.value.axfr.error ?? "unknown"}`);
    }
    for (const e of report.value.errors) log.warn(e);
  } catch (e: any) { log.err(String(e)); }
  finally { running.value = false; }
}
</script>

<template>
  <div class="module">
    <div class="form">
      <Prompt label="domain" v-model="domain" placeholder="example.com" />
      <Prompt label="resolver" v-model="resolver" placeholder="1.1.1.1, 8.8.8.8, internal-dns.corp (blank = cloudflare)" />
      <div class="row">
        <label class="toggle"><input type="checkbox" v-model="tryAxfr" /><span>try zone transfer (AXFR)</span></label>
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ querying... ]" : "> resolve" }}</button>
      </div>
    </div>

    <div v-if="report" class="rec-grid">
      <div v-for="r in report.records" :key="r.rtype" class="rec">
        <div class="rec-head">{{ r.rtype }} <span class="rec-count">×{{ r.values.length }}</span></div>
        <div v-for="v in r.values" :key="v" class="rec-val">{{ v }}</div>
      </div>
      <div class="rec" :class="{ ok: report.dnssec.has_dnssec, miss: !report.dnssec.has_dnssec }">
        <div class="rec-head">DNSSEC</div>
        <div class="rec-val">{{ report.dnssec.has_dnssec ? `${report.dnssec.dnskey_count} DNSKEY` : "not signed" }}</div>
      </div>
      <div v-if="report.axfr" class="rec" :class="{ hit: report.axfr.success }">
        <div class="rec-head">AXFR</div>
        <div v-if="report.axfr.success" class="rec-val">
          LEAKED {{ report.axfr.records_dumped.length }} records
          <div class="axfr-list">
            <div v-for="n in report.axfr.records_dumped.slice(0, 20)" :key="n">» {{ n }}</div>
            <div v-if="report.axfr.records_dumped.length > 20" class="rec-val">... +{{ report.axfr.records_dumped.length - 20 }} more</div>
          </div>
        </div>
        <div v-else class="rec-val">refused / {{ report.axfr.error }}</div>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="dns // recon" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.rec-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 6px; }
.rec { background: var(--bg-panel); border: 1px solid var(--border); padding: 6px 8px; border-left: 2px solid var(--border-hot); }
.rec.hit { border-left-color: var(--alert); background: rgba(255, 47, 74, 0.05); }
.rec.ok { border-left-color: var(--valid); }
.rec.miss { border-left-color: var(--warn); }
.rec-head { font-size: 10px; color: var(--alert); font-weight: 700; text-transform: uppercase; letter-spacing: 0.15em; margin-bottom: 3px; }
.rec-count { color: var(--fg-dim); font-weight: 400; }
.rec-val { color: var(--fg); font-size: 11px; word-break: break-all; padding: 1px 0; }
.axfr-list { max-height: 160px; overflow-y: auto; margin-top: 4px; font-size: 10px; color: var(--fg-dim); }
</style>
