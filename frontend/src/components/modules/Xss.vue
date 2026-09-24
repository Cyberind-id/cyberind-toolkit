<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

const url = ref("https://insecure.newploit.com/search.php?q=test");
const paramsFilter = ref("");
const useGet = ref(true);
const usePost = ref(false);
const concurrency = ref(5);
const timeoutMs = ref(10000);
const running = ref(false);
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

async function run() {
  if (running.value) return;
  running.value = true;
  log.clear();

  const methods: string[] = [];
  if (useGet.value) methods.push("GET");
  if (usePost.value) methods.push("POST");
  if (!methods.length) { log.err("pick a method"); running.value = false; return; }

  const paramsList = paramsFilter.value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
  log.info(`target: ${url.value}`);

  unlistens.push(await listen<string>("xss:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<any>("xss:hit", (e) => {
    const p = e.payload;
    const msg = `[${p.confidence}] ${p.method} ${p.param} :: ctx=${p.context} :: ${p.evidence} :: payload="${p.payload}"`;
    if (p.confidence === "HIGH") log.hit(msg);
    else log.warn(msg);
  }));

  try {
    const res: any[] = await invoke("xss_scan", {
      req: {
        url: url.value,
        params: paramsList.length ? paramsList : null,
        methods,
        concurrency: concurrency.value,
        timeout_ms: timeoutMs.value,
      },
    });
    log.ok(`scan done: ${res.length} reflection(s)`);
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
      <Prompt label="url" v-model="url" placeholder="https://target.com/search?q=test" />
      <Prompt label="params" v-model="paramsFilter" placeholder="q,name (blank = auto)" />
      <div class="row">
        <label class="toggle"><input type="checkbox" v-model="useGet" /><span>GET</span></label>
        <label class="toggle"><input type="checkbox" v-model="usePost" /><span>POST</span></label>
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="50" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="1000" max="30000" /></label>
      </div>
      <div class="row">
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ probing... ]" : "> fire" }}</button>
      </div>
    </div>
    <Terminal :lines="log.lines.value" title="xss // canary + context-aware payload" @clear="log.clear()" />
  </div>
</template>
