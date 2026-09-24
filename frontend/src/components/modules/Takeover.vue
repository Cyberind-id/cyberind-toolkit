<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import { useTerminal } from "../../composables/useTerminal";

const hosts = ref("");
const concurrency = ref(20);
const timeoutMs = ref(5000);
const running = ref(false);
const progress = ref({ done: 0, total: 0 });
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

async function run() {
  if (running.value) return;
  running.value = true;
  log.clear();
  progress.value = { done: 0, total: 0 };

  const list = hosts.value.split(/[\s,\n]+/).map((s) => s.trim()).filter(Boolean);
  if (!list.length) { log.err("no hosts"); running.value = false; return; }
  log.info(`checking ${list.length} host(s) against fingerprint DB`);

  unlistens.push(await listen<{ done: number; total: number }>("takeover:progress", (e) => { progress.value = e.payload; }));
  unlistens.push(await listen<any>("takeover:hit", (e) => {
    const p = e.payload;
    const tag = p.vulnerable ? "VULN" : "INFO";
    const msg = `[${tag}/${p.confidence}] ${p.host} → ${p.cname ?? "?"} [${p.service ?? "?"}] :: ${p.evidence}`;
    if (p.vulnerable) log.hit(msg); else log.valid(msg);
  }));

  try {
    const res: any[] = await invoke("takeover_scan", {
      req: { hosts: list, concurrency: concurrency.value, timeout_ms: timeoutMs.value },
    });
    const vulns = res.filter((r) => r.vulnerable).length;
    log.ok(`done: ${res.length} fingerprinted, ${vulns} VULN`);
  } catch (e: any) {
    log.err(String(e));
  } finally { running.value = false; cleanup(); }
}
function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <label class="ta">
        <span class="lbl">targets // subdomains</span>
        <textarea class="term-input" v-model="hosts" placeholder="stale.example.com&#10;old.subdomain.target.com" spellcheck="false" rows="5" />
      </label>
      <div class="row">
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="200" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="500" max="30000" /></label>
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ hunting... ]" : "> hunt-takeover" }}</button>
      </div>
      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>
    </div>
    <Terminal :lines="log.lines.value" title="takeover // fingerprint DB: S3/GH/Heroku/Azure/Vercel/+" @clear="log.clear()" />
  </div>
</template>
