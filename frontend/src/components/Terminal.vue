<script setup lang="ts">
import { nextTick, ref, watch } from "vue";
import type { LogLine } from "../composables/useTerminal";

const props = defineProps<{ lines: LogLine[]; title?: string }>();
const emit = defineEmits<{ (e: "clear"): void }>();

const box = ref<HTMLDivElement | null>(null);

watch(
  () => props.lines.length,
  async () => {
    await nextTick();
    if (box.value) box.value.scrollTop = box.value.scrollHeight;
  }
);

function prefix(level: LogLine["level"]) {
  switch (level) {
    case "hit": return "[+]";
    case "valid": return "[✓]";
    case "ok": return "[*]";
    case "warn": return "[!]";
    case "err": return "[x]";
    case "dim": return "[ ]";
    default: return "[i]";
  }
}
</script>

<template>
  <div class="term">
    <div class="term-head">
      <span class="term-title">{{ title ?? "output" }}</span>
      <span class="term-controls">
        <span class="dot d-red" />
        <span class="dot d-yellow" />
        <span class="dot d-live" />
      </span>
      <button class="term-clear" @click="emit('clear')">clear</button>
    </div>
    <div class="term-body" ref="box">
      <div v-if="lines.length === 0" class="term-empty">
        <span class="cursor">▊</span> awaiting input...
      </div>
      <div
        v-for="(l, i) in lines"
        :key="i"
        class="term-line"
        :class="`lvl-${l.level}`"
      >
        <span class="ts">{{ l.ts }}</span>
        <span class="pre">{{ prefix(l.level) }}</span>
        <span class="msg">{{ l.text }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.term {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 180px;
}
.term-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-elev);
  font-size: 11px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.term-title { flex: 1; }
.term-controls { display: flex; gap: 4px; }
.dot {
  width: 8px;
  height: 8px;
  border-radius: 0;
  background: var(--fg-ghost);
}
.d-red { background: var(--alert); }
.d-yellow { background: var(--warn); }
.d-live { background: var(--accent); }
.term-clear {
  color: var(--fg-dim);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 2px 6px;
  border: 1px solid var(--border);
}
.term-clear:hover {
  color: var(--accent);
  border-color: var(--accent);
}
.term-body {
  flex: 1;
  overflow-y: auto;
  padding: 8px 10px;
  font-size: 12px;
}
.term-empty {
  color: var(--fg-ghost);
  font-style: italic;
}
.cursor {
  color: var(--accent);
  animation: blink 1s steps(2) infinite;
}
@keyframes blink { 50% { opacity: 0; } }
.term-line {
  white-space: pre-wrap;
  word-break: break-all;
}
.ts { color: var(--fg-ghost); margin-right: 8px; }
.pre { margin-right: 6px; }
.lvl-hit .pre { color: var(--alert); }
.lvl-hit .msg { color: var(--alert); }
.lvl-valid .pre { color: var(--valid); }
.lvl-valid .msg { color: var(--valid); }
.lvl-ok .pre { color: var(--info); }
.lvl-ok .msg { color: var(--fg); }
.lvl-warn .pre, .lvl-warn .msg { color: var(--warn); }
.lvl-err .pre, .lvl-err .msg { color: var(--alert); }
.lvl-dim .pre, .lvl-dim .msg { color: var(--fg-dim); }
.lvl-info .pre { color: var(--fg-dim); }
</style>
