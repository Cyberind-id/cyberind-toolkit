<script setup lang="ts">
import { computed, ref } from "vue";

const input = ref("");
const calcText = ref("");

interface Signature { name: string; pattern: RegExp; example?: string; }

const SIGNATURES: Signature[] = [
  { name: "MD5",                 pattern: /^[a-f0-9]{32}$/i, example: "5f4dcc3b5aa765d61d8327deb882cf99" },
  { name: "NTLM",                pattern: /^[A-F0-9]{32}$/, example: "b4b9b02e6f09a9bd760f388b67351e2b" },
  { name: "SHA-1",               pattern: /^[a-f0-9]{40}$/i, example: "356a192b7913b04c54574d18c28d46e6395428ab" },
  { name: "MySQL 4.1+ (SHA1x2)", pattern: /^\*[A-F0-9]{40}$/, example: "*6691484EA6B50DDDE1926A220DA01FA9E575C18A" },
  { name: "RIPEMD-160",          pattern: /^[a-f0-9]{40}$/i },
  { name: "SHA-224",             pattern: /^[a-f0-9]{56}$/i },
  { name: "SHA-256",             pattern: /^[a-f0-9]{64}$/i, example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { name: "SHA-384",             pattern: /^[a-f0-9]{96}$/i },
  { name: "SHA-512",             pattern: /^[a-f0-9]{128}$/i },
  { name: "bcrypt",              pattern: /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/, example: "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW" },
  { name: "scrypt",              pattern: /^\$scrypt\$/ },
  { name: "argon2id",            pattern: /^\$argon2id?\$/, example: "$argon2id$v=19$m=65536,t=3,p=4$..." },
  { name: "PBKDF2-SHA1",         pattern: /^pbkdf2-sha1\$/ },
  { name: "MD5 Crypt (old unix)",pattern: /^\$1\$/, example: "$1$salt$..." },
  { name: "SHA-256 Crypt",       pattern: /^\$5\$/, example: "$5$salt$..." },
  { name: "SHA-512 Crypt",       pattern: /^\$6\$/, example: "$6$salt$..." },
  { name: "WordPress (PHPass)",  pattern: /^\$P\$[./A-Za-z0-9]{31}$/, example: "$P$BPMg6qGb..." },
  { name: "PhpBB3 (PHPass)",     pattern: /^\$H\$[./A-Za-z0-9]{31}$/ },
  { name: "Django PBKDF2",       pattern: /^pbkdf2_sha256\$/ },
  { name: "Django SHA1",         pattern: /^sha1\$[^$]+\$[a-f0-9]{40}$/i },
  { name: "LM Hash",             pattern: /^[A-F0-9]{32}$/, example: "aad3b435b51404eeaad3b435b51404ee" },
  { name: "NetNTLMv2",           pattern: /^[^:]+::[^:]*:[A-F0-9]{16}:[A-F0-9]{32}:.+$/ },
  { name: "Cisco Type 7",        pattern: /^[0-9]{2}[A-F0-9]+$/i },
  { name: "Cisco IOS $9$",       pattern: /^\$9\$/ },
  { name: "CRC32",               pattern: /^[a-f0-9]{8}$/i },
  { name: "MySQL 3.23 (old)",    pattern: /^[a-f0-9]{16}$/i },
  { name: "JWT",                 pattern: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/ },
];

const identified = computed(() => {
  const s = input.value.trim();
  if (!s) return [] as Signature[];
  return SIGNATURES.filter(sig => sig.pattern.test(s));
});

const hashes = ref<Record<string, string>>({});

async function compute() {
  const text = calcText.value;
  if (!text) { hashes.value = {}; return; }
  const buf = new TextEncoder().encode(text);
  const algos: [string, AlgorithmIdentifier][] = [
    ["SHA-1", "SHA-1"],
    ["SHA-256", "SHA-256"],
    ["SHA-384", "SHA-384"],
    ["SHA-512", "SHA-512"],
  ];
  const out: Record<string, string> = {};
  out.MD5 = md5(text);
  out.CRC32 = crc32(text).toString(16).padStart(8, "0");
  for (const [name, algo] of algos) {
    const digest = await crypto.subtle.digest(algo, buf);
    out[name] = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  hashes.value = out;
}

// ---------- MD5 (pure JS) ----------
function md5(str: string): string {
  function rotateLeft(lValue: number, iShiftBits: number) { return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits)); }
  function addUnsigned(lX: number, lY: number) {
    const lX8 = (lX & 0x80000000), lY8 = (lY & 0x80000000);
    const lX4 = (lX & 0x40000000), lY4 = (lY & 0x40000000);
    const lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
    if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
    if (lX4 | lY4) {
      if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
      return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
    }
    return (lResult ^ lX8 ^ lY8);
  }
  function F(x: number, y: number, z: number) { return (x & y) | ((~x) & z); }
  function G(x: number, y: number, z: number) { return (x & z) | (y & (~z)); }
  function H(x: number, y: number, z: number) { return x ^ y ^ z; }
  function I(x: number, y: number, z: number) { return y ^ (x | (~z)); }
  function FF(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function GG(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function HH(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function II(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function convertToWordArray(s: string) {
    let lWordCount;
    const lMessageLength = s.length;
    const lNumberOfWords_temp1 = lMessageLength + 8;
    const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    const lWordArray = new Array(lNumberOfWords - 1);
    let lBytePosition = 0, lByteCount = 0;
    while (lByteCount < lMessageLength) {
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = (lWordArray[lWordCount] | (s.charCodeAt(lByteCount) << lBytePosition));
      lByteCount++;
    }
    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  }
  function wordToHex(lValue: number) {
    let wordToHexValue = "", wordToHexValue_temp = "", lByte;
    for (let lCount = 0; lCount <= 3; lCount++) {
      lByte = (lValue >>> (lCount * 8)) & 255;
      wordToHexValue_temp = "0" + lByte.toString(16);
      wordToHexValue = wordToHexValue + wordToHexValue_temp.substr(wordToHexValue_temp.length - 2, 2);
    }
    return wordToHexValue;
  }
  function utf8Encode(s: string) { return unescape(encodeURIComponent(s)); }

  const x = convertToWordArray(utf8Encode(str));
  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
  const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
  const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
  const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
  const S41 = 6, S42 = 10, S43 = 15, S44 = 21;
  for (let k = 0; k < x.length; k += 16) {
    const AA = a, BB = b, CC = c, DD = d;
    a = FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
    d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
    c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
    b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
    a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
    d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
    c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
    b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
    a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
    d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
    c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
    b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
    a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
    d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
    c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
    b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
    a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
    d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
    c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
    b = GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
    a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
    d = GG(d, a, b, c, x[k + 10], S22, 0x2441453);
    c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
    b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
    a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
    d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
    c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
    b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
    a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
    d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
    c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
    b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
    a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
    d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
    c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
    b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
    a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
    d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
    c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
    b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
    a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
    d = HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
    c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
    b = HH(b, c, d, a, x[k + 6], S34, 0x4881D05);
    a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
    d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
    c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
    b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
    a = II(a, b, c, d, x[k + 0], S41, 0xF4292244);
    d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
    c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
    b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
    a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
    d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
    c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
    b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
    a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
    d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
    c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
    b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
    a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
    d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
    c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
    b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
    a = addUnsigned(a, AA);
    b = addUnsigned(b, BB);
    c = addUnsigned(c, CC);
    d = addUnsigned(d, DD);
  }
  return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

function crc32(str: string): number {
  let c;
  const table = [] as number[];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  let crc = 0 ^ (-1);
  for (let i = 0; i < str.length; i++) crc = (crc >>> 8) ^ table[(crc ^ str.charCodeAt(i)) & 0xFF];
  return (crc ^ (-1)) >>> 0;
}

async function copy(t: string) {
  try { await navigator.clipboard.writeText(t); } catch {}
}
</script>

<template>
  <div class="module">
    <section class="pane">
      <div class="pane-head">HASH IDENTIFIER</div>
      <label class="ta">
        <span class="lbl">hash to identify</span>
        <textarea class="term-input" v-model="input" rows="2" spellcheck="false" placeholder="paste hash or JWT..." />
      </label>
      <div v-if="input.trim()" class="matches">
        <div v-if="!identified.length" class="no-match">⨯ no signatures match</div>
        <div v-else>
          <div v-for="s in identified" :key="s.name" class="match">
            <span class="m-name">{{ s.name }}</span>
            <code class="m-pat">{{ s.pattern }}</code>
          </div>
        </div>
      </div>
    </section>

    <section class="pane">
      <div class="pane-head">HASH CALCULATOR</div>
      <label class="ta">
        <span class="lbl">input</span>
        <textarea class="term-input" v-model="calcText" rows="2" spellcheck="false" @input="compute" placeholder="type to auto-hash..." />
      </label>
      <div v-if="Object.keys(hashes).length" class="hash-list">
        <div v-for="(v, k) in hashes" :key="k" class="h-row">
          <span class="h-k">{{ k }}</span>
          <code class="h-v">{{ v }}</code>
          <button class="btn-ghost tiny" @click="copy(v)">copy</button>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.pane { background: var(--bg-panel); border: 1px solid var(--border); padding: 8px; display: flex; flex-direction: column; gap: 6px; }
.pane-head { font-size: 10px; color: var(--alert); font-weight: 700; text-transform: uppercase; letter-spacing: 0.2em; border-bottom: 1px solid var(--border); padding-bottom: 3px; }
.matches { display: flex; flex-direction: column; gap: 3px; }
.no-match { color: var(--fg-ghost); font-size: 11px; font-style: italic; padding: 4px; }
.match { display: flex; gap: 8px; padding: 3px 6px; background: var(--bg); border-left: 2px solid var(--valid); align-items: center; }
.m-name { color: var(--valid); font-weight: 700; font-size: 11px; min-width: 160px; }
.m-pat { color: var(--fg-dim); font-size: 9px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; background: transparent; border: none; padding: 0; }

.hash-list { display: flex; flex-direction: column; gap: 3px; }
.h-row { display: flex; gap: 6px; align-items: center; font-size: 10px; padding: 2px 0; }
.h-k { color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.1em; min-width: 70px; font-size: 9px; flex-shrink: 0; }
.h-v { color: var(--valid); word-break: break-all; flex: 1; background: var(--bg); border: 1px solid var(--border); padding: 2px 5px; font-size: 10px; min-width: 0; }
.btn-ghost.tiny { padding: 1px 6px; font-size: 9px; flex-shrink: 0; }
</style>
