<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import Prompt from "../Prompt.vue";
import { useTerminal } from "../../composables/useTerminal";

interface Device {
  ip: string;
  hostname?: string;
  open_ports: number[];
  services: string[];
  upnp: string[];
  guess?: string;
}

interface LocalInfo {
  local_ip: string;
  subnet: string;
  platform: string;
  android: boolean;
}

const info = ref<LocalInfo | null>(null);
const subnet = ref("");
const probeMdns = ref(true);
const probeSsdp = ref(true);
const concurrency = ref(80);
const timeoutMs = ref(800);
const running = ref(false);
const progress = ref({ done: 0, total: 0 });
const devices = ref<Device[]>([]);
const log = useTerminal();
const unlistens: UnlistenFn[] = [];

async function loadInfo() {
  try {
    info.value = await invoke<LocalInfo>("lan_local_info");
    if (!subnet.value && info.value.subnet) subnet.value = info.value.subnet;
  } catch (e: any) { log.err(String(e)); }
}

async function run() {
  if (running.value) return;
  running.value = true;
  devices.value = [];
  progress.value = { done: 0, total: 0 };
  log.clear();

  unlistens.push(await listen<string>("lanmap:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ done: number; total: number }>("lanmap:progress", (e) => { progress.value = e.payload; }));
  unlistens.push(await listen<Device>("lanmap:device", (e) => {
    const p = e.payload;
    log.valid(`${p.ip.padEnd(16)} ports: ${p.open_ports.join(",")} ${p.guess ? `→ ${p.guess}` : ""}`);
  }));

  try {
    const report: any = await invoke("lan_scan", {
      req: {
        subnet_cidr: subnet.value || null,
        ports: null,
        probe_mdns: probeMdns.value,
        probe_ssdp: probeSsdp.value,
        concurrency: concurrency.value,
        timeout_ms: timeoutMs.value,
      },
    });
    devices.value = report.devices;
    log.ok(`scan done: ${report.devices.length} devices on ${report.subnet}`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }

onMounted(loadInfo);
onUnmounted(cleanup);
</script>

<template>
  <div class="module">
    <div class="form">
      <div class="info-strip">
        <div class="info-cell">
          <span class="info-key">my ip</span>
          <span class="info-val">{{ info?.local_ip ?? "—" }}</span>
        </div>
        <div class="info-cell">
          <span class="info-key">subnet</span>
          <span class="info-val">{{ info?.subnet ?? "—" }}</span>
        </div>
        <div class="info-cell">
          <span class="info-key">platform</span>
          <span class="info-val">{{ info?.platform ?? "—" }}</span>
        </div>
      </div>

      <Prompt label="subnet" v-model="subnet" placeholder="192.168.1.0/24 (auto)" />

      <div class="row">
        <label class="toggle"><input type="checkbox" v-model="probeMdns" /><span>mdns</span></label>
        <label class="toggle"><input type="checkbox" v-model="probeSsdp" /><span>ssdp/upnp</span></label>
        <label class="mini"><span>conc</span><input v-model.number="concurrency" type="number" min="1" max="500" /></label>
        <label class="mini"><span>t/out</span><input v-model.number="timeoutMs" type="number" min="100" max="5000" /></label>
      </div>
      <div class="row">
        <button class="exec" :disabled="running" @click="run">{{ running ? "[ scanning... ]" : "> sweep LAN" }}</button>
      </div>

      <div v-if="info?.android" class="warn-strip">
        <b>android note:</b> mDNS/SSDP multicast may be dropped without MulticastLock from a native plugin. TCP sweep is unaffected.
      </div>

      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>
    </div>

    <div v-if="devices.length" class="dev-grid">
      <div v-for="d in devices" :key="d.ip" class="dev">
        <div class="dev-head">
          <span class="dev-ip">{{ d.ip }}</span>
          <span v-if="d.guess" class="dev-guess">{{ d.guess }}</span>
        </div>
        <div v-if="d.open_ports.length" class="dev-row">
          <span class="dev-key">ports</span>
          <span class="port-chips">
            <span v-for="p in d.open_ports" :key="p" class="port-chip">{{ p }}</span>
          </span>
        </div>
        <div v-if="d.services.length" class="dev-row">
          <span class="dev-key">mdns</span>
          <span class="dev-list">{{ d.services.slice(0, 3).join(", ") }}<span v-if="d.services.length > 3"> +{{ d.services.length - 3 }}</span></span>
        </div>
        <div v-if="d.upnp.length" class="dev-row">
          <span class="dev-key">upnp</span>
          <span class="dev-list">{{ d.upnp[0].slice(0, 80) }}</span>
        </div>
      </div>
    </div>

    <Terminal :lines="log.lines.value" title="lan-map // discovery" @clear="log.clear()" />
  </div>
</template>

<style scoped>
.info-strip {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  padding: 6px 8px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  font-size: 11px;
}
.info-cell { display: flex; gap: 6px; align-items: center; min-width: 0; }
.info-key { color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; font-size: 10px; }
.info-val { color: var(--info); }

.warn-strip {
  font-size: 11px;
  padding: 6px 8px;
  color: var(--warn);
  border: 1px solid rgba(212, 165, 55, 0.3);
  background: rgba(212, 165, 55, 0.05);
}

.dev-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 6px;
  max-height: 260px;
  overflow-y: auto;
}
.dev {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  padding: 6px 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
.dev:hover { border-color: var(--alert); }
.dev-head { display: flex; justify-content: space-between; align-items: baseline; gap: 6px; }
.dev-ip { color: var(--fg); font-weight: 700; font-size: 12px; }
.dev-guess { color: var(--info); font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; }
.dev-row { display: flex; gap: 6px; align-items: center; min-width: 0; }
.dev-key {
  color: var(--fg-dim);
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  min-width: 32px;
}
.dev-list {
  color: var(--fg-dim);
  font-size: 10px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}
.port-chips { display: flex; gap: 3px; flex-wrap: wrap; }
.port-chip {
  font-size: 9px;
  color: var(--alert);
  border: 1px solid var(--border-hot);
  padding: 0 4px;
}
</style>
