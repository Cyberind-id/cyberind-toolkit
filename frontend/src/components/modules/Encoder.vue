<script setup lang="ts">
import { ref } from "vue";

type Op =
  | "b64-enc" | "b64-dec" | "url-enc" | "url-dec"
  | "hex-enc" | "hex-dec" | "html-enc" | "html-dec"
  | "unicode-enc" | "unicode-dec" | "rot13" | "reverse"
  | "upper" | "lower" | "morse-enc" | "morse-dec"
  | "jwt-dec";

interface Step { op: Op; label: string; }

const input = ref("");
const output = ref("");
const pipeline = ref<Step[]>([]);
const error = ref("");
const toast = ref("");

const OPS: { id: Op; label: string; group: string }[] = [
  { id: "b64-enc",     label: "base64 encode",  group: "base64" },
  { id: "b64-dec",     label: "base64 decode",  group: "base64" },
  { id: "url-enc",     label: "url encode",     group: "url" },
  { id: "url-dec",     label: "url decode",     group: "url" },
  { id: "hex-enc",     label: "hex encode",     group: "hex" },
  { id: "hex-dec",     label: "hex decode",     group: "hex" },
  { id: "html-enc",    label: "html encode",    group: "html" },
  { id: "html-dec",    label: "html decode",    group: "html" },
  { id: "unicode-enc", label: "\\uXXXX encode", group: "unicode" },
  { id: "unicode-dec", label: "\\uXXXX decode", group: "unicode" },
  { id: "rot13",       label: "rot13",          group: "classic" },
  { id: "reverse",     label: "reverse",        group: "classic" },
  { id: "upper",       label: "UPPERCASE",      group: "classic" },
  { id: "lower",       label: "lowercase",      group: "classic" },
  { id: "morse-enc",   label: "morse encode",   group: "classic" },
  { id: "morse-dec",   label: "morse decode",   group: "classic" },
  { id: "jwt-dec",     label: "jwt decode",     group: "jwt" },
];

const MORSE: Record<string, string> = {
  A:".-",B:"-...",C:"-.-.",D:"-..",E:".",F:"..-.",G:"--.",H:"....",I:"..",J:".---",K:"-.-",L:".-..",
  M:"--",N:"-.",O:"---",P:".--.",Q:"--.-",R:".-.",S:"...",T:"-",U:"..-",V:"...-",W:".--",X:"-..-",
  Y:"-.--",Z:"--..","0":"-----","1":".----","2":"..---","3":"...--","4":"....-","5":".....","6":"-....",
  "7":"--...","8":"---..","9":"----.",".":".-.-.-",",":"--..--","?":"..--..","!":"-.-.--","@":".--.-.",
  " ":"/",
};
const MORSE_INV: Record<string, string> = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));

function b64e(s: string): string {
  try { return btoa(unescape(encodeURIComponent(s))); } catch { throw new Error("invalid utf-8 input"); }
}
function b64d(s: string): string {
  try { return decodeURIComponent(escape(atob(s.replace(/\s+/g, "")))); } catch { throw new Error("invalid base64"); }
}
function hexE(s: string): string {
  return Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexD(s: string): string {
  const h = s.replace(/\s|0x/g, "");
  if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2 !== 0) throw new Error("invalid hex");
  const arr = new Uint8Array(h.length / 2);
  for (let i = 0; i < h.length; i += 2) arr[i / 2] = parseInt(h.substr(i, 2), 16);
  return new TextDecoder().decode(arr);
}
function htmlE(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}
function htmlD(s: string): string {
  const ta = document.createElement("textarea");
  ta.innerHTML = s;
  return ta.value;
}
function uniE(s: string): string {
  return Array.from(s).map(c => c.charCodeAt(0) < 128 ? c : "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("");
}
function uniD(s: string): string {
  return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}
function rot13(s: string): string {
  return s.replace(/[a-zA-Z]/g, c => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
  });
}
function morseE(s: string): string {
  return s.toUpperCase().split("").map(c => MORSE[c] ?? "").filter(Boolean).join(" ");
}
function morseD(s: string): string {
  return s.split("/").map(word =>
    word.trim().split(/\s+/).map(sym => MORSE_INV[sym] ?? "").join("")
  ).join(" ");
}
function jwtD(s: string): string {
  const parts = s.trim().split(".");
  if (parts.length !== 3) throw new Error("not a JWT");
  const pad = (p: string) => p + "=".repeat((4 - p.length % 4) % 4);
  const dec = (p: string) => decodeURIComponent(escape(atob(pad(p).replace(/-/g, "+").replace(/_/g, "/"))));
  try {
    const header = JSON.parse(dec(parts[0]));
    const payload = JSON.parse(dec(parts[1]));
    return JSON.stringify({ header, payload, signature_b64url: parts[2] }, null, 2);
  } catch (e: any) { throw new Error("jwt decode failed: " + e.message); }
}

function apply(op: Op, s: string): string {
  switch (op) {
    case "b64-enc": return b64e(s);
    case "b64-dec": return b64d(s);
    case "url-enc": return encodeURIComponent(s);
    case "url-dec": return decodeURIComponent(s);
    case "hex-enc": return hexE(s);
    case "hex-dec": return hexD(s);
    case "html-enc": return htmlE(s);
    case "html-dec": return htmlD(s);
    case "unicode-enc": return uniE(s);
    case "unicode-dec": return uniD(s);
    case "rot13": return rot13(s);
    case "reverse": return Array.from(s).reverse().join("");
    case "upper": return s.toUpperCase();
    case "lower": return s.toLowerCase();
    case "morse-enc": return morseE(s);
    case "morse-dec": return morseD(s);
    case "jwt-dec": return jwtD(s);
  }
}

function add(op: Op, label: string) {
  pipeline.value.push({ op, label });
  recompute();
}

function remove(i: number) {
  pipeline.value.splice(i, 1);
  recompute();
}

function clear() { pipeline.value = []; output.value = ""; error.value = ""; }

function recompute() {
  error.value = "";
  let cur = input.value;
  try {
    for (const s of pipeline.value) cur = apply(s.op, cur);
    output.value = cur;
  } catch (e: any) {
    error.value = e.message ?? String(e);
    output.value = "";
  }
}

async function copy() {
  try {
    await navigator.clipboard.writeText(output.value);
    toast.value = "copied";
    setTimeout(() => { toast.value = ""; }, 1000);
  } catch {}
}

function swap() {
  input.value = output.value;
  pipeline.value = [];
  output.value = "";
  error.value = "";
}
</script>

<template>
  <div class="module">
    <div class="io-split">
      <label class="ta">
        <span class="lbl">input</span>
        <textarea class="term-input" v-model="input" rows="4" spellcheck="false" @input="recompute" placeholder="paste text to transform..." />
      </label>
      <label class="ta">
        <span class="lbl">output
          <button class="btn-ghost tiny" @click="copy" :disabled="!output">copy</button>
          <button class="btn-ghost tiny" @click="swap" :disabled="!output">swap ↑</button>
        </span>
        <textarea class="term-input valid-out" :value="error || output" rows="4" readonly spellcheck="false" :class="{ err: !!error }" />
      </label>
    </div>

    <div class="pipe">
      <div class="pipe-head">
        <span>pipeline · {{ pipeline.length }} op(s)</span>
        <button class="btn-ghost tiny" @click="clear">clear</button>
      </div>
      <div v-if="!pipeline.length" class="pipe-empty">pick an operation ↓</div>
      <div v-else class="pipe-chain">
        <div v-for="(s, i) in pipeline" :key="i" class="step">
          <span class="step-n">{{ i + 1 }}</span>
          <span class="step-l">{{ s.label }}</span>
          <button class="btn-ghost tiny" @click="remove(i)">×</button>
          <span v-if="i < pipeline.length - 1" class="step-arrow">→</span>
        </div>
      </div>
    </div>

    <div class="ops-grid">
      <button v-for="o in OPS" :key="o.id" class="op-btn" :class="`grp-${o.group}`" @click="add(o.id, o.label)">
        {{ o.label }}
      </button>
    </div>

    <div v-if="toast" class="toast">{{ toast }}</div>
  </div>
</template>

<style scoped>
.io-split { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
.lbl { display: flex; gap: 6px; align-items: center; }
.btn-ghost.tiny { padding: 1px 6px; font-size: 9px; }
.valid-out { color: var(--valid); }
.valid-out.err { color: var(--alert); }

.pipe { background: var(--bg-panel); border: 1px solid var(--border); padding: 6px 8px; }
.pipe-head { display: flex; justify-content: space-between; font-size: 10px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 4px; }
.pipe-empty { color: var(--fg-ghost); font-size: 10px; text-align: center; padding: 6px; font-style: italic; }
.pipe-chain { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }
.step { display: flex; gap: 4px; align-items: center; padding: 3px 8px; background: var(--bg); border: 1px solid var(--info); color: var(--info); font-size: 11px; }
.step-n { color: var(--fg-ghost); font-size: 9px; }
.step-arrow { color: var(--fg-ghost); font-size: 14px; }

.ops-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 3px; }
.op-btn {
  padding: 5px 8px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--fg-dim);
  font-size: 11px;
  text-align: left;
  cursor: pointer;
  transition: all 0.1s;
}
.op-btn:hover { border-color: var(--alert); color: var(--alert); }
.grp-base64 { border-left: 2px solid #3572a5; }
.grp-url { border-left: 2px solid #d4a537; }
.grp-hex { border-left: 2px solid #5cd982; }
.grp-html { border-left: 2px solid #e76f00; }
.grp-unicode { border-left: 2px solid #7fb3d5; }
.grp-classic { border-left: 2px solid #ff2f4a; }
.grp-jwt { border-left: 2px solid #ffb000; }

.toast { position: absolute; bottom: 20px; left: 50%; transform: translateX(-50%); padding: 4px 12px; background: var(--valid); color: #000; font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; animation: toast 1s ease-out; pointer-events: none; z-index: 10; }
@keyframes toast {
  0% { opacity: 0; transform: translate(-50%, 10px); }
  20%,80% { opacity: 1; transform: translate(-50%, 0); }
  100% { opacity: 0; transform: translate(-50%, -10px); }
}

@media (max-width: 640px) {
  .io-split { grid-template-columns: 1fr; }
}
</style>
