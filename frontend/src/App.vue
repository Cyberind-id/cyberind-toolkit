<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { invoke } from "./lib/api";
import PortScan from "./components/modules/PortScan.vue";
import SubEnum from "./components/modules/SubEnum.vue";
import HttpProbe from "./components/modules/HttpProbe.vue";
import Takeover from "./components/modules/Takeover.vue";
import Sqli from "./components/modules/Sqli.vue";
import Xss from "./components/modules/Xss.vue";
import Jwt from "./components/modules/Jwt.vue";
import Xploiter from "./components/modules/Xploiter.vue";
import AutoPwn from "./components/modules/AutoPwn.vue";
import LanMap from "./components/modules/LanMap.vue";
import Repeater from "./components/modules/Repeater.vue";
import DirFuzz from "./components/modules/DirFuzz.vue";
import PayloadGen from "./components/modules/PayloadGen.vue";
import AdminFinder from "./components/modules/AdminFinder.vue";
import FormBrute from "./components/modules/FormBrute.vue";
import DnsTools from "./components/modules/DnsTools.vue";
import SslScan from "./components/modules/SslScan.vue";
import Banner from "./components/modules/Banner.vue";
import Encoder from "./components/modules/Encoder.vue";
import HashTools from "./components/modules/HashTools.vue";
import DomainGrabber from "./components/modules/DomainGrabber.vue";
import SplashScreen from "./components/SplashScreen.vue";

type ToolId = "ports" | "subs" | "httpx" | "takeguard" | "sqltrace" | "xenxss" | "tokenscope" | "vulnforge" | "autopwn" | "lanmap" | "reqlab" | "dirfuzz" | "payloadgen" | "adminfinder" | "formbrute" | "dnscope" | "ssl" | "banner" | "codeshift" | "hash" | "domgrab";

interface Tool {
  id: ToolId;
  code: string;
  name: string;
  tagline: string;
  desc: string;
  cat: "recon" | "exploit" | "utility" | "wifi" | "manual";
  severity: "info" | "low" | "medium" | "high" | "critical";
}

const tools: Tool[] = [
  { id: "ports",    code: "01", name: "portray",  tagline: "tcp connect",       desc: "async port discovery, service hints",                cat: "recon",   severity: "info" },
  { id: "subs",     code: "02", name: "subfindr",  tagline: "passive + brute",   desc: "crt.sh enum, wordlist bruteforce",                   cat: "recon",   severity: "info" },
  { id: "httpx",    code: "03", name: "webprobex", tagline: "status + tech",     desc: "fingerprint live hosts, tech stack",                 cat: "recon",   severity: "info" },
  { id: "takeguard", code: "04", name: "takeguard",   tagline: "CNAME hijack",      desc: "S3/GH/Heroku/Azure/Vercel/+15 more",                 cat: "exploit", severity: "high" },
  { id: "sqltrace",     code: "05", name: "sqltrace",       tagline: "error/bool/time",   desc: "auto-detect injection, 6 DBMS",                      cat: "exploit", severity: "critical" },
  { id: "xenxss",      code: "06", name: "xenxss",        tagline: "context-aware",     desc: "canary reflection, HTML/attr/JS payloads",           cat: "exploit", severity: "high" },
  { id: "tokenscope",      code: "07", name: "tokenscope",        tagline: "alg:none + brute",  desc: "decode + HMAC crack + forgery",                      cat: "exploit", severity: "critical" },
  { id: "vulnforge", code: "08", name: "vulnforge",   tagline: "template engine",   desc: "YAML-driven RCE/LFI/SSRF/SSTI, bring your own template", cat: "exploit", severity: "critical" },
  { id: "autopwn",  code: "09", name: "reconflow",   tagline: "full chain",        desc: "domain → subs → probe → exploit, one-button pipeline", cat: "exploit", severity: "critical" },
  { id: "lanmap",   code: "10", name: "netgrid",    tagline: "local network",     desc: "discover devices on WiFi: TCP sweep + mDNS + SSDP",  cat: "wifi",    severity: "info" },
  { id: "reqlab", code: "11", name: "reqlab",   tagline: "burp-lite",         desc: "manual HTTP: craft, send, inspect, replay, curl export", cat: "manual",  severity: "info" },
  { id: "dirfuzz",  code: "12", name: "dirtrace",   tagline: "content discovery", desc: "wordlist + ext bruteforce, recursive, size/status filter", cat: "exploit", severity: "medium" },
  { id: "payloadgen", code: "13", name: "payloadforge", tagline: "shells + codeshifts", desc: "reverse/bind shells 15+ langs, webshells, msfvenom, codeshifts", cat: "utility", severity: "info" },
  { id: "adminfinder", code: "14", name: "panelseek", tagline: "panel discovery", desc: "320+ admin paths, CMS/platform fingerprint, login form detect", cat: "exploit", severity: "medium" },
  { id: "formbrute",   code: "15", name: "authprobe",   tagline: "login bruteforce", desc: "POST/GET credential attack, regex match, CSRF handling", cat: "exploit", severity: "high" },
  { id: "dnscope",         code: "16", name: "dnscope",           tagline: "record lookup",    desc: "A/AAAA/MX/TXT/NS/CNAME/SOA/CAA + DNSSEC + AXFR",     cat: "wifi",    severity: "info" },
  { id: "ssl",         code: "17", name: "certscope",      tagline: "tls inspector",    desc: "cert chain, SANs, expiry, signature algo, weak version", cat: "wifi",    severity: "info" },
  { id: "banner",      code: "18", name: "serviceeye",   tagline: "service fingerprint", desc: "TCP banner + SSH/SMTP/FTP/HTTP/Redis/MySQL recognize", cat: "wifi", severity: "info" },
  { id: "codeshift",     code: "19", name: "codeshift",       tagline: "chain transforms", desc: "b64/url/hex/html/rot13/morse/tokenscope — pipeline ops",    cat: "utility", severity: "info" },
  { id: "hash",        code: "20", name: "hashlens",    tagline: "id + calc",        desc: "identify 28+ hash types, compute MD5/SHA/CRC32",    cat: "utility", severity: "info" },
  { id: "domgrab",     code: "21", name: "domaintrace",   tagline: "bulk TLD harvest", desc: "grab domains per TLD from crt.sh/urlscan/wayback + IANA catalog", cat: "recon", severity: "info" },
];

const active = ref<ToolId | null>(null);
const banner = ref<string>("");
const clock = ref<string>("");
const showSplash = ref(true);

function tick() {
  const d = new Date();
  clock.value = d.toTimeString().slice(0, 8);
}

onMounted(async () => {
  try { banner.value = await invoke<string>("banner"); }
  catch { banner.value = "CYBERIND TOOLKIT"; }
  tick();
  setInterval(tick, 1000);
});

const activeTool = computed(() => tools.find((t) => t.id === active.value) ?? null);

interface Group {
  id: Tool["cat"];
  label: string;
  desc: string;
  mark: string;
}

const groups: Group[] = [
  { id: "recon",   label: "recon",         desc: "passive + active reconnaissance", mark: "◉" },
  { id: "exploit", label: "exploitation",  desc: "attack vectors & vulnerability",  mark: "⚔" },
  { id: "manual",  label: "manual",        desc: "hand-crafted request tooling",    mark: "✎" },
  { id: "wifi",    label: "network",       desc: "local / wifi reconnaissance",     mark: "≋" },
  { id: "utility", label: "utility",       desc: "helpers & payload generation",    mark: "⚙" },
];

const grouped = computed(() =>
  groups.map((g) => ({ ...g, tools: tools.filter((t) => t.cat === g.id) }))
        .filter((g) => g.tools.length > 0)
);

function back() { active.value = null; }
function open(id: ToolId) { active.value = id; }
</script>

<template>
  <SplashScreen v-if="showSplash" @done="showSplash = false" />
  <div class="shell" v-show="!showSplash">
    <!-- ============ CYBERIND HEADER ============ -->
    <header class="site-header">
      <div class="nav-shell">
        <button v-if="activeTool" class="mobile-back" @click="back" aria-label="Kembali">←</button>
        <button class="brand" @click="back" aria-label="Cyberind Toolkit">
          <span class="brand-mark">&lt;/&gt;</span>
          <span class="brand-text">
            <strong>CYBERIND</strong>
            <small>TOOLKIT</small>
          </span>
        </button>

        <nav class="site-nav" aria-label="Navigasi">
          <button :class="{ active: !activeTool }" @click="back">Tools</button>
          <a href="https://cyberind.my.id" target="_blank" rel="noreferrer">Cyberind.id</a>
          <span class="nav-divider"></span>
          <span class="nav-status"><i></i> SYSTEM ONLINE</span>
        </nav>

        <div class="nav-actions">
          <span class="version">v0.1.0</span>
          <span class="clock">{{ clock }}</span>
        </div>
      </div>

      <div class="commandbar">
        <span class="command-user">cyberind</span>
        <span class="command-sep">/</span>
        <span class="command-path">{{ activeTool ? activeTool.name : 'toolkit' }}</span>
        <span class="command-cursor">_</span>
      </div>
    </header>

    <!-- ============ MAIN ============ -->
    <main class="main">
      <!-- ARSENAL / HOME -->
      <div v-show="!activeTool" class="arsenal">
        <section class="tool-hero">
          <div class="hero-copy">
            <span class="eyebrow"><i></i> CYBERIND TOOLKIT</span>
            <h1>Security tools, <span>built for the web.</span></h1>
            <p>Reconnaissance, analysis, diagnostics, and security utilities in one clean workspace.</p>
          </div>
          <div class="hero-terminal">
            <span>$ toolkit --status</span>
            <strong>READY</strong>
            <small>21 modules available</small>
          </div>
        </section>

        <div class="arsenal-stats">
          <span class="stats-total">{{ tools.length }} modules</span>
          <span v-for="g in grouped" :key="g.id" class="stats-grp" :class="`cat-${g.id}`">
            <span class="stats-mark">{{ g.mark }}</span>
            <span>{{ g.tools.length }} {{ g.label }}</span>
          </span>
        </div>

        <div class="group-stack">
          <section v-for="g in grouped" :key="g.id" class="group" :class="`cat-${g.id}`">
            <header class="group-head">
              <span class="grp-mark">{{ g.mark }}</span>
              <span class="grp-label">{{ g.label }}</span>
              <span class="grp-desc">// {{ g.desc }}</span>
              <span class="grp-count">[{{ g.tools.length }}]</span>
              <span class="grp-rule"></span>
            </header>
            <div class="grid">
              <button
                v-for="t in g.tools"
                :key="t.id"
                class="tile"
                :class="[`cat-${t.cat}`, `sev-${t.severity}`]"
                @click="open(t.id)"
              >
                <div class="tile-top">
                  <span class="tile-code">[{{ t.code }}]</span>
                  <span class="tile-mark">{{ g.mark }}</span>
                </div>
                <div class="tile-name">{{ t.name }}</div>
                <div class="tile-tag">{{ t.tagline }}</div>
                <div class="tile-desc">{{ t.desc }}</div>
                <div class="tile-foot">
                  <span class="sev" :class="`sev-${t.severity}`">{{ t.severity }}</span>
                  <span class="tile-arrow">▶</span>
                </div>
              </button>
            </div>
          </section>
        </div>

      </div>

      <!-- ACTIVE TOOL -->
      <div v-if="activeTool" class="tool">
        <PortScan v-if="active === 'ports'" />
        <SubEnum v-else-if="active === 'subs'" />
        <HttpProbe v-else-if="active === 'httpx'" />
        <Takeover v-else-if="active === 'takeguard'" />
        <Sqli v-else-if="active === 'sqltrace'" />
        <Xss v-else-if="active === 'xenxss'" />
        <Jwt v-else-if="active === 'tokenscope'" />
        <Xploiter v-else-if="active === 'vulnforge'" />
        <AutoPwn v-else-if="active === 'autopwn'" />
        <LanMap v-else-if="active === 'lanmap'" />
        <Repeater v-else-if="active === 'reqlab'" />
        <DirFuzz v-else-if="active === 'dirfuzz'" />
        <PayloadGen v-else-if="active === 'payloadgen'" />
        <AdminFinder v-else-if="active === 'adminfinder'" />
        <FormBrute v-else-if="active === 'formbrute'" />
        <DnsTools v-else-if="active === 'dnscope'" />
        <SslScan v-else-if="active === 'ssl'" />
        <Banner v-else-if="active === 'banner'" />
        <Encoder v-else-if="active === 'codeshift'" />
        <HashTools v-else-if="active === 'hash'" />
        <DomainGrabber v-else-if="active === 'domgrab'" />
      </div>
    </main>

    <!-- ============ FOOTER ============ -->
    <footer class="site-footer">
      <span>© Cyberind.id</span>
      <span class="footer-dot">•</span>
      <span>Independent security toolkit</span>
      <span class="footer-spacer"></span>
      <span>{{ banner }}</span>
    </footer>
  </div>
</template>

<style scoped>
.shell {
  height: 100%;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
}

/* ============ HEADER ============ */
.hdr {
  flex-shrink: 0;
  border-bottom: 1px solid var(--border);
  background: var(--bg-elev);
  position: relative;
}
.hdr::before {
  content: '';
  position: absolute;
  bottom: -1px;
  left: 0;
  width: 50%;
  height: 1px;
  background: linear-gradient(90deg, var(--alert), transparent);
  opacity: 0.6;
}
.hdr-top {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 12px 4px;
  min-width: 0;
}
.hdr-back {
  color: var(--alert);
  border: 1px solid var(--alert);
  padding: 3px 8px;
  font-size: 11px;
  letter-spacing: 0.05em;
  transition: background 0.15s;
  flex-shrink: 0;
  height: fit-content;
  margin-top: 4px;
}
.hdr-back:hover { background: var(--alert); color: #fff; }

.banner-wrap {
  flex: 1;
  min-width: 0;
  overflow-x: auto;
  scrollbar-width: none;
}
.banner-wrap::-webkit-scrollbar { display: none; }
.banner-art {
  color: var(--accent);
  font-size: 9px;
  line-height: 1.1;
  font-weight: 700;
  text-shadow: 0 0 10px rgba(255, 47, 74, 0.25), 0 0 2px rgba(255, 255, 255, 0.4);
  margin: 0;
  white-space: pre;
  font-family: var(--mono);
}

.hdr-meta {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 0 12px;
  flex-wrap: wrap;
}
.tag {
  font-size: 10px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.15em;
  padding: 1px 6px;
  border: 1px solid var(--border);
  flex-shrink: 0;
}
.tag-warn { color: var(--warn); border-color: var(--warn); }

.hdr-spacer { flex: 1; min-width: 0; }

.hdr-status {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 10px;
  color: var(--alert);
  text-transform: uppercase;
  letter-spacing: 0.15em;
  flex-shrink: 0;
}
.pulse {
  width: 6px; height: 6px;
  background: var(--alert);
  box-shadow: 0 0 8px var(--alert);
  animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse { 50% { opacity: 0.3; transform: scale(0.75); } }
.hdr-clock {
  font-size: 10px;
  color: var(--fg-dim);
  font-variant-numeric: tabular-nums;
  flex-shrink: 0;
}

.hdr-sub {
  padding: 4px 12px 6px;
  font-size: 11px;
  display: flex;
  gap: 2px;
  flex-wrap: nowrap;
  overflow: hidden;
  white-space: nowrap;
}
.crumb-user { color: var(--alert); }
.crumb-path { color: var(--info); overflow: hidden; text-overflow: ellipsis; }
.crumb-cmd { color: var(--fg); margin-left: 4px; }
.crumb-sep { color: var(--fg-ghost); }
.crumb-cursor { color: var(--accent); animation: blink 1s steps(2) infinite; }
@keyframes blink { 50% { opacity: 0; } }

/* ============ MAIN ============ */
.main {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* ARSENAL */
.arsenal {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.arsenal-stats {
  display: flex;
  gap: 10px;
  font-size: 11px;
  color: var(--fg-dim);
  padding: 6px 10px;
  border: 1px solid var(--border);
  background: var(--bg-panel);
  flex-wrap: wrap;
  align-items: center;
}
.stats-total {
  color: var(--fg);
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  font-size: 10px;
}
.stats-grp {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 6px;
  border: 1px solid var(--border-hot);
  font-size: 10px;
  letter-spacing: 0.05em;
}
.stats-mark { font-size: 11px; }
.stats-grp.cat-recon { color: var(--info); }
.stats-grp.cat-exploit { color: var(--alert); }
.stats-grp.cat-wifi { color: var(--warn); }
.stats-grp.cat-manual { color: var(--valid); }
.stats-grp.cat-utility { color: var(--fg); }

.group-stack {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.group { display: flex; flex-direction: column; gap: 8px; }
.group-head {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  padding: 2px 0;
}
.grp-mark { font-size: 14px; flex-shrink: 0; }
.group.cat-recon .grp-mark { color: var(--info); }
.group.cat-exploit .grp-mark { color: var(--alert); }
.group.cat-wifi .grp-mark { color: var(--warn); }
.group.cat-manual .grp-mark { color: var(--valid); }
.group.cat-utility .grp-mark { color: var(--fg); }
.grp-label {
  font-weight: 700;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  font-size: 12px;
  color: var(--fg);
}
.group.cat-recon .grp-label { color: var(--info); }
.group.cat-exploit .grp-label { color: var(--alert); }
.group.cat-wifi .grp-label { color: var(--warn); }
.group.cat-manual .grp-label { color: var(--valid); }
.grp-desc {
  color: var(--fg-ghost);
  font-size: 10px;
  font-style: italic;
}
.grp-count {
  color: var(--fg-dim);
  font-size: 10px;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.1em;
}
.grp-rule {
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, var(--border-hot), transparent);
  margin-left: 4px;
}
.group.cat-recon .grp-rule { background: linear-gradient(90deg, rgba(127, 179, 213, 0.3), transparent); }
.group.cat-exploit .grp-rule { background: linear-gradient(90deg, rgba(255, 47, 74, 0.3), transparent); }
.group.cat-wifi .grp-rule { background: linear-gradient(90deg, rgba(212, 165, 55, 0.3), transparent); }
.group.cat-manual .grp-rule { background: linear-gradient(90deg, rgba(92, 217, 130, 0.3), transparent); }

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 8px;
}

.tile {
  display: flex;
  flex-direction: column;
  gap: 4px;
  text-align: left;
  padding: 10px 12px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--fg);
  cursor: pointer;
  position: relative;
  overflow: hidden;
  transition: border-color 0.15s, background 0.15s;
  min-height: 130px;
}
.tile::before {
  content: '';
  position: absolute;
  top: 0; left: 0;
  width: 2px; height: 100%;
  background: var(--border-hot);
  transition: background 0.15s;
}
.tile.cat-exploit::before { background: var(--alert); opacity: 0.5; }
.tile.cat-recon::before { background: var(--info); opacity: 0.4; }
.tile.cat-wifi::before { background: var(--warn); opacity: 0.5; }
.tile.cat-manual::before { background: var(--valid); opacity: 0.5; }
.tile.cat-utility::before { background: var(--fg-dim); opacity: 0.5; }
.tile:hover {
  border-color: var(--alert);
  background: rgba(255, 47, 74, 0.04);
}
.tile:hover::before { opacity: 1; box-shadow: 0 0 10px currentColor; }
.tile:active { transform: translateY(1px); }

.tile-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.tile-code {
  color: var(--fg-ghost);
  font-size: 10px;
  letter-spacing: 0.1em;
}
.tile-mark { font-size: 12px; }
.cat-exploit .tile-mark { color: var(--alert); }
.cat-recon .tile-mark { color: var(--info); }
.cat-wifi .tile-mark { color: var(--warn); }
.cat-manual .tile-mark { color: var(--valid); }
.cat-utility .tile-mark { color: var(--fg-dim); }

.tile-name {
  font-size: 15px;
  font-weight: 700;
  color: var(--fg);
  letter-spacing: -0.01em;
  word-break: break-word;
}
.tile-tag {
  font-size: 10px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  word-break: break-word;
}
.tile-desc {
  font-size: 11px;
  color: var(--fg-dim);
  line-height: 1.4;
  flex: 1;
  word-break: break-word;
  overflow: hidden;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  -webkit-box-orient: vertical;
}
.tile-foot {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 2px;
}
.tile-arrow {
  color: var(--fg-ghost);
  font-size: 10px;
  transition: color 0.15s, transform 0.15s;
}
.tile:hover .tile-arrow { color: var(--alert); transform: translateX(2px); }

.disclaimer {
  margin-top: auto;
  padding: 6px 10px;
  font-size: 10px;
  color: var(--warn);
  border: 1px solid rgba(212, 165, 55, 0.3);
  background: rgba(212, 165, 55, 0.05);
  display: flex;
  align-items: center;
  gap: 8px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.warn-mark {
  width: 16px; height: 16px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--warn);
  color: var(--warn);
  font-weight: 700;
  flex-shrink: 0;
}

/* TOOL VIEW */
.tool {
  flex: 1;
  min-height: 0;
  display: flex;
  padding: 10px 12px;
  overflow: hidden;
}
.tool > :deep(.module) {
  width: 100%;
  min-width: 0;
}

/* ============ FOOTER ============ */
.foot {
  flex-shrink: 0;
  padding: 5px 12px;
  border-top: 1px solid var(--border);
  background: var(--bg-elev);
  font-size: 10px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ============ RESPONSIVE ============ */
@media (max-width: 480px) {
  .banner-art { font-size: 7px; }
  .hdr-clock { display: none; }
  .grid { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); }
  .arsenal { padding: 8px; }
}
@media (max-width: 360px) {
  .banner-art { font-size: 6px; }
  .grid { grid-template-columns: 1fr 1fr; gap: 6px; }
  .tile { padding: 8px 10px; min-height: 110px; }
  .tile-name { font-size: 14px; }
  .tag-warn { display: none; }
}

/* Cyberind web design system — clean, modern, responsive */
.site-header {
  flex-shrink: 0;
  background: rgba(5, 5, 5, 0.92);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(14px);
  position: relative;
  z-index: 10;
}
.site-header::after {
  content: "";
  position: absolute;
  left: 0; right: 0; bottom: -1px;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  opacity: .45;
}
.nav-shell {
  min-height: 64px;
  max-width: 1440px;
  margin: 0 auto;
  padding: 0 24px;
  display: flex;
  align-items: center;
  gap: 28px;
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  color: #fff;
  text-align: left;
  flex-shrink: 0;
}
.brand-mark {
  width: 34px; height: 34px;
  display: grid; place-items: center;
  border: 1px solid rgba(239,68,68,.55);
  color: var(--accent);
  background: rgba(239,68,68,.07);
  font-weight: 800;
  font-size: 13px;
  box-shadow: 0 0 24px rgba(239,68,68,.08);
}
.brand-text { display:flex; flex-direction:column; line-height:1; gap:4px; }
.brand-text strong { font-size: 14px; letter-spacing: .16em; }
.brand-text small { color: var(--fg-dim); font-size: 8px; letter-spacing: .28em; }
.site-nav {
  display: flex;
  align-items: center;
  gap: 22px;
  flex: 1;
}
.site-nav button, .site-nav a {
  color: var(--fg-dim);
  font-size: 11px;
  letter-spacing: .08em;
  text-transform: uppercase;
  transition: color .2s ease;
}
.site-nav button:hover, .site-nav a:hover, .site-nav button.active { color: #fff; }
.site-nav button.active { color: var(--accent); }
.nav-divider { width: 1px; height: 18px; background: var(--border); }
.nav-status { color: var(--fg-dim); font-size: 9px; letter-spacing: .12em; display:flex; align-items:center; gap:7px; }
.nav-status i { width:6px; height:6px; border-radius:50%; background:#55d98b; box-shadow:0 0 10px rgba(85,217,139,.7); }
.nav-actions { display:flex; align-items:center; gap:12px; color:var(--fg-dim); font-size:10px; }
.version { border:1px solid var(--border); padding:5px 8px; }
.clock { font-variant-numeric: tabular-nums; }
.mobile-back { display:none; color:var(--accent); font-size:20px; }
.commandbar {
  max-width: 1440px;
  margin: 0 auto;
  padding: 7px 24px 9px;
  color: var(--fg-ghost);
  font-size: 10px;
  letter-spacing: .04em;
}
.command-user { color: var(--accent); }
.command-sep { padding:0 5px; }
.command-path { color:var(--fg-dim); }
.command-cursor { color:var(--accent); animation: blink 1s steps(2) infinite; }

.arsenal {
  max-width: 1440px;
  width: 100%;
  margin: 0 auto;
  padding: 30px 24px 34px;
  gap: 20px;
}
.tool-hero {
  display:grid;
  grid-template-columns:minmax(0,1fr) 310px;
  gap:18px;
  padding:28px;
  border:1px solid var(--border);
  background:
    radial-gradient(circle at 0% 0%, rgba(239,68,68,.11), transparent 34%),
    linear-gradient(145deg, rgba(255,255,255,.025), rgba(255,255,255,.008));
  position:relative;
  overflow:hidden;
}
.tool-hero::before {
  content:"";
  position:absolute; inset:0;
  background:linear-gradient(90deg, rgba(239,68,68,.06) 1px, transparent 1px);
  background-size:42px 100%;
  mask-image:linear-gradient(90deg,#000,transparent 75%);
  pointer-events:none;
}
.hero-copy, .hero-terminal { position:relative; z-index:1; }
.eyebrow { color:var(--accent); font-size:9px; letter-spacing:.2em; font-weight:700; display:flex; gap:8px; align-items:center; }
.eyebrow i { width:6px; height:6px; background:var(--accent); border-radius:50%; box-shadow:0 0 12px var(--accent); }
.hero-copy h1 { margin-top:12px; color:#fff; font-family:ui-sans-serif,system-ui,sans-serif; font-size:clamp(28px,4vw,48px); line-height:1.02; letter-spacing:-.045em; max-width:720px; }
.hero-copy h1 span { color:var(--accent); }
.hero-copy p { margin-top:12px; color:var(--fg-dim); max-width:650px; font-family:ui-sans-serif,system-ui,sans-serif; font-size:14px; line-height:1.65; }
.hero-terminal { align-self:stretch; border:1px solid var(--border); background:#070707; padding:18px; display:flex; flex-direction:column; justify-content:center; gap:8px; }
.hero-terminal span { color:var(--fg-dim); font-size:10px; }
.hero-terminal strong { color:#fff; font-size:24px; letter-spacing:.08em; }
.hero-terminal small { color:#55d98b; font-size:9px; letter-spacing:.1em; }

.arsenal-stats {
  border:0;
  border-top:1px solid var(--border);
  border-bottom:1px solid var(--border);
  background:transparent;
  padding:12px 2px;
}
.grid { grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:12px; }
.group { gap:10px; }
.group-head { padding:8px 2px; }
.grp-label { letter-spacing:.13em; }
.tile {
  min-height:158px;
  border-radius:10px;
  padding:16px;
  background:linear-gradient(145deg, rgba(255,255,255,.025), rgba(255,255,255,.008));
  transition:transform .2s ease,border-color .2s ease,box-shadow .2s ease,background .2s ease;
}
.tile::before { width:1px; }
.tile:hover {
  transform:translateY(-2px);
  border-color:rgba(239,68,68,.55);
  background:linear-gradient(145deg,rgba(239,68,68,.07),rgba(255,255,255,.012));
  box-shadow:0 14px 40px rgba(0,0,0,.28);
}
.tile-name { font-family:ui-sans-serif,system-ui,sans-serif; font-size:16px; letter-spacing:-.01em; }
.tile-desc { font-family:ui-sans-serif,system-ui,sans-serif; line-height:1.5; }
.sev { border-radius:999px; padding:2px 7px; }
.tool { max-width:1440px; width:100%; margin:0 auto; padding:24px; }
.site-footer {
  flex-shrink:0;
  border-top:1px solid var(--border);
  background:rgba(5,5,5,.92);
  min-height:40px;
  padding:0 24px;
  display:flex; align-items:center; gap:8px;
  color:var(--fg-ghost); font-size:9px; letter-spacing:.08em;
}
.footer-spacer { flex:1; }

@media (max-width: 760px) {
  .nav-shell { min-height:58px; padding:0 14px; gap:10px; }
  .mobile-back { display:block; }
  .brand-mark { width:30px; height:30px; }
  .site-nav { display:none; }
  .nav-actions { margin-left:auto; }
  .clock { display:none; }
  .commandbar { padding:6px 14px 8px; }
  .arsenal { padding:18px 14px 26px; }
  .tool-hero { grid-template-columns:1fr; padding:22px; }
  .hero-terminal { min-height:120px; }
  .grid { grid-template-columns:repeat(2,minmax(0,1fr)); gap:9px; }
  .tile { min-height:145px; padding:13px; }
  .tile-desc { font-size:10px; }
  .tool { padding:14px; }
  .site-footer { padding:0 14px; }
  .site-footer span:nth-child(3), .site-footer span:last-child { display:none; }
}
@media (max-width: 430px) {
  .brand-text strong { font-size:12px; }
  .brand-text small { font-size:7px; }
  .version { display:none; }
  .hero-copy h1 { font-size:29px; }
  .hero-copy p { font-size:13px; }
  .tool-hero { padding:18px; }
  .grid { grid-template-columns:1fr; }
  .tile { min-height:132px; }
  .arsenal-stats { gap:7px; }
  .stats-grp { padding:2px 5px; }
}

</style>
