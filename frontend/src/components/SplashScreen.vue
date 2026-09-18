<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";

const emit = defineEmits<{ (e: "done"): void }>();

interface BootLine { text: string; ok: boolean; }
const boot = ref<BootLine[]>([]);
const progress = ref(0);
const done = ref(false);
const fadeOut = ref(false);

const steps: { text: string; delay: number }[] = [
  { text: "loading kernel modules...",                       delay: 420 },
  { text: "mounting /data/pentester...",                     delay: 380 },
  { text: "init: async runtime (tokio rt-multi-thread)",     delay: 360 },
  { text: "init: rustls tls stack + webpki roots",           delay: 340 },
  { text: "init: hickory-dns resolver (cloudflare)",         delay: 340 },
  { text: "recon: port-scan // subdomain // http-probe",     delay: 360 },
  { text: "exploit: takeover // sqli // xss // jwt",         delay: 360 },
  { text: "exploit: xploiter engine — 13 bundled templates", delay: 380 },
  { text: "exploit: auto-pwn pipeline armed",                delay: 340 },
  { text: "exploit: admin-finder // form-brute // dir-fuzz", delay: 360 },
  { text: "manual: repeater (burp-lite) ready",              delay: 320 },
  { text: "wifi: lan-map // mdns // ssdp",                   delay: 320 },
  { text: "utility: payload-gen 50+ shells loaded",          delay: 320 },
  { text: "xploiter: compiling regex matchers...",           delay: 300 },
  { text: "network: dns // ssl-scan // banner-grab",          delay: 320 },
  { text: "utility: encoder // hash-tools",                   delay: 300 },
  { text: "arsenal armed. 21 modules online.",                delay: 480 },
];

let timers: number[] = [];

function push(text: string, ok = true) {
  boot.value.push({ text, ok });
  progress.value = Math.min(100, (boot.value.length / steps.length) * 100);
}

onMounted(() => {
  let elapsed = 0;
  steps.forEach((s) => {
    elapsed += s.delay;
    timers.push(window.setTimeout(() => push(s.text), elapsed));
  });
  timers.push(window.setTimeout(() => {
    done.value = true;
  }, elapsed + 300));
  // hold on "tap to enter" for a while before auto-advancing
  timers.push(window.setTimeout(() => {
    fadeOut.value = true;
  }, elapsed + 4500));
  timers.push(window.setTimeout(() => {
    emit("done");
  }, elapsed + 4900));
});

function skip() {
  // finish everything instantly and fade
  timers.forEach((t) => clearTimeout(t));
  timers = [];
  for (const s of steps) {
    if (!boot.value.find((b) => b.text === s.text)) boot.value.push({ text: s.text, ok: true });
  }
  progress.value = 100;
  done.value = true;
  fadeOut.value = true;
  setTimeout(() => emit("done"), 300);
}

onUnmounted(() => { timers.forEach((t) => clearTimeout(t)); });
</script>

<template>
  <div class="splash" :class="{ fade: fadeOut }" @click="skip">
    <div class="scanlines" />
    <div class="glitch-line" />

    <div class="frame">
      <!-- top ASCII frame -->
      <div class="ascii-top">
        <span class="corner">┏</span>
        <span class="line"></span>
        <span class="tag">[ SYSTEM BOOT ]</span>
        <span class="line"></span>
        <span class="corner">┓</span>
      </div>

      <!-- Cyberind brand -->
      <div class="brand-row">
        <div class="brand-main">CYBERIND<span class="brand-dot">.</span>ID</div>
      </div>

      <!-- product title -->
      <div class="product">
        <div class="product-name">
          <span class="p-brk">〘</span>
          <span class="p-main">CYBERIND TOOLKIT</span>
          <span class="p-brk">〙</span>
        </div>
        <div class="product-sub">
          offensive toolkit <span class="dot-sep">·</span> v0.1.0
        </div>
      </div>

      <!-- boot log -->
      <div class="boot-log">
        <div class="boot-head">
          <span class="b-prompt">root@cyberind:~$</span>
          <span class="b-cmd">./init --arm</span>
          <span class="cursor" v-if="!done">▊</span>
        </div>
        <div class="boot-lines">
          <div v-for="(l, i) in boot" :key="i" class="boot-line">
            <span class="b-mark" :class="{ ok: l.ok }">{{ l.ok ? "[✓]" : "[x]" }}</span>
            <span class="b-text">{{ l.text }}</span>
          </div>
          <div v-if="!done && boot.length < steps.length" class="boot-line pending">
            <span class="b-mark">[..]</span>
            <span class="b-text">{{ steps[boot.length]?.text ?? "" }}<span class="cursor">▊</span></span>
          </div>
        </div>
      </div>

      <!-- progress bar -->
      <div class="prog">
        <div class="prog-bar">
          <div class="prog-fill" :style="{ width: progress + '%' }" />
        </div>
        <div class="prog-text">{{ Math.round(progress) }}%</div>
      </div>

      <div class="powered">
        <span class="pb-label">independent toolkit · cyberind.id · since 2018</span>
      </div>

      <!-- bottom -->
      <div class="ascii-bottom">
        <span class="corner">┗</span>
        <span class="line"></span>
        <span class="tag" v-if="done">[ tap to enter ]</span>
        <span class="tag" v-else>[ initializing ]</span>
        <span class="line"></span>
        <span class="corner">┛</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.splash {
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse at top, rgba(255, 47, 74, 0.08), transparent 55%),
    radial-gradient(ellipse at bottom, rgba(0, 200, 150, 0.03), transparent 60%),
    var(--bg);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
  overflow: hidden;
  cursor: pointer;
  transition: opacity 0.4s ease-out;
  padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
}
.splash.fade { opacity: 0; pointer-events: none; }

.scanlines {
  position: absolute;
  inset: 0;
  background: repeating-linear-gradient(
    0deg,
    rgba(255, 255, 255, 0.02) 0px,
    rgba(255, 255, 255, 0.02) 1px,
    transparent 1px,
    transparent 3px
  );
  pointer-events: none;
}
.glitch-line {
  position: absolute;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--alert), transparent);
  opacity: 0.6;
  animation: glitch 4s linear infinite;
  pointer-events: none;
  top: 0;
}
@keyframes glitch {
  0% { top: 0%; opacity: 0; }
  10% { opacity: 0.6; }
  50% { top: 100%; opacity: 0.6; }
  60% { opacity: 0; }
  100% { top: 100%; opacity: 0; }
}

.frame {
  width: min(520px, 95vw);
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 20px 24px;
  border: 1px solid var(--border-hot);
  background: rgba(7, 7, 7, 0.85);
  backdrop-filter: blur(2px);
  box-shadow: 0 0 60px rgba(255, 47, 74, 0.12);
  position: relative;
}

.ascii-top, .ascii-bottom {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 10px;
  color: var(--fg-dim);
  letter-spacing: 0.05em;
}
.ascii-top .corner, .ascii-bottom .corner { color: var(--alert); font-size: 14px; }
.ascii-top .line, .ascii-bottom .line {
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, var(--alert), var(--border-hot));
  opacity: 0.5;
}
.ascii-bottom .line { background: linear-gradient(90deg, var(--border-hot), var(--alert)); }
.ascii-top .tag, .ascii-bottom .tag {
  padding: 0 8px;
  color: var(--alert);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.2em;
}

.brand-row {
  display: flex;
  justify-content: center;
  padding: 4px 0;
}
.brand-main {
  font-size: 34px;
  font-weight: 900;
  letter-spacing: 0.12em;
  color: var(--fg);
  text-shadow: 0 0 18px rgba(255, 47, 74, 0.28);
  animation: brand-in 0.7s ease-out;
}
.brand-dot { color: var(--alert); }
@keyframes brand-in {
  0% { opacity: 0; transform: translateY(-10px); }
  100% { opacity: 1; transform: translateY(0); }
}

.product {
  text-align: center;
  padding: 4px 0;
  border-top: 1px dashed var(--border-hot);
  border-bottom: 1px dashed var(--border-hot);
}
.product-name {
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: var(--fg);
}
.product-name .p-brk { color: var(--alert); font-weight: 400; }
.product-name .p-main { padding: 0 6px; }
.product-name .p-p { color: var(--alert); }
.product-sub {
  font-size: 10px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.15em;
  margin-top: 4px;
}
.product-sub .dot-sep { color: var(--fg-ghost); padding: 0 4px; }

.boot-log {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 8px 10px;
  min-height: 130px;
  font-size: 11px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.boot-head {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 4px;
  margin-bottom: 4px;
}
.b-prompt { color: var(--alert); }
.b-cmd { color: var(--info); }
.cursor { color: var(--accent); animation: blink 1s steps(2) infinite; display: inline-block; margin-left: 2px; }
@keyframes blink { 50% { opacity: 0; } }

.boot-lines { display: flex; flex-direction: column; gap: 2px; }
.boot-line {
  display: flex;
  gap: 6px;
  align-items: baseline;
  animation: line-in 0.18s ease-out;
}
@keyframes line-in {
  0% { opacity: 0; transform: translateX(-4px); }
  100% { opacity: 1; transform: translateX(0); }
}
.b-mark { color: var(--fg-ghost); flex-shrink: 0; }
.b-mark.ok { color: var(--valid); }
.boot-line.pending .b-mark { color: var(--warn); }
.boot-line.pending .b-text { color: var(--fg-dim); }
.b-text { color: var(--fg); }

.prog {
  display: flex;
  gap: 8px;
  align-items: center;
}
.prog-bar {
  flex: 1;
  height: 4px;
  background: var(--bg);
  border: 1px solid var(--border);
  overflow: hidden;
}
.prog-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent-dim), var(--alert));
  transition: width 0.2s ease-out;
  box-shadow: 0 0 10px rgba(255, 47, 74, 0.5);
}
.prog-text {
  color: var(--alert);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.1em;
  font-variant-numeric: tabular-nums;
  min-width: 34px;
  text-align: right;
}

.powered {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 4px 0;
}
.pb-label {
  font-size: 9px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.2em;
}
.pb-logo {
  height: 22px;
  width: auto;
  animation: brand-in 0.8s ease-out;
}
.pb-imt {
  filter: drop-shadow(0 0 6px rgba(255, 47, 74, 0.3));
}

@media (max-width: 420px) {
  .frame { padding: 14px 16px; gap: 10px; }
  .brand-main { font-size: 25px; }
  .pb-logo { height: 18px; }
  .product-name { font-size: 15px; }
  .boot-log { min-height: 110px; }
}
</style>
