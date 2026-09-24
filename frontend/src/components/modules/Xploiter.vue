<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { invoke } from "../../lib/api";
import { listen, type UnlistenFn } from "../../lib/api";
import Terminal from "../Terminal.vue";
import { useTerminal } from "../../composables/useTerminal";

interface TemplateRef {
  filename: string;
  path: string;
  id: string;
  name: string;
  severity: string;
  tags: string[];
  author: string;
  description: string;
  builtin: boolean;
}

type View = "list" | "editor";

const view = ref<View>("list");

const targets = ref("https://insecure.newploit.com");
const templates = ref<TemplateRef[]>([]);
const selected = ref<Set<string>>(new Set());

const query = ref("");
const tagFilter = ref("");
const severities = ref({ critical: true, high: true, medium: true, low: true, info: true });

const running = ref(false);
const progress = ref({ done: 0, total: 0 });

// editor state
const editorPath = ref<string | null>(null);
const editorFilename = ref("");
const editorContent = ref("");
const editorDirty = ref(false);

const log = useTerminal();
const unlistens: UnlistenFn[] = [];

const selectedSeverities = computed(() =>
  Object.entries(severities.value).filter(([, v]) => v).map(([k]) => k)
);

async function bootstrap() {
  try {
    const res: any = await invoke("xploit_store_init");
    if (res.written > 0) log.dim(`extracted ${res.written} starter templates → ${res.path}`);
  } catch (e: any) { log.err(String(e)); }
  await reload();
}

async function reload() {
  try {
    templates.value = await invoke("xploit_store_list", {
      severity: selectedSeverities.value,
      tag: tagFilter.value || null,
      query: query.value || null,
    });
  } catch (e: any) { log.err(String(e)); }
}

function toggle(path: string) {
  if (selected.value.has(path)) selected.value.delete(path);
  else selected.value.add(path);
  selected.value = new Set(selected.value);
}

function toggleAll() {
  if (selected.value.size === templates.value.length) selected.value = new Set();
  else selected.value = new Set(templates.value.map((t) => t.path));
}

async function openEditor(t: TemplateRef | null) {
  if (t) {
    try {
      editorContent.value = await invoke<string>("xploit_store_read", { path: t.path });
      editorPath.value = t.path;
      editorFilename.value = t.filename;
    } catch (e: any) { log.err(String(e)); return; }
  } else {
    editorContent.value = await invoke<string>("xploit_store_starter_template");
    editorPath.value = null;
    editorFilename.value = `xpl-custom-${Date.now()}.yaml`;
  }
  editorDirty.value = false;
  view.value = "editor";
}

async function save() {
  try {
    const newPath: string = await invoke("xploit_store_save", {
      filename: editorFilename.value,
      content: editorContent.value,
    });
    editorPath.value = newPath;
    editorDirty.value = false;
    log.ok(`saved → ${newPath}`);
    await reload();
  } catch (e: any) {
    log.err(String(e));
  }
}

async function remove(t: TemplateRef) {
  if (t.builtin) {
    log.warn(`${t.filename} is bundled — deleting will reappear on next init`);
  }
  try {
    await invoke("xploit_store_delete", { path: t.path });
    selected.value.delete(t.path);
    selected.value = new Set(selected.value);
    log.dim(`deleted ${t.filename}`);
    await reload();
  } catch (e: any) { log.err(String(e)); }
}

async function duplicate(t: TemplateRef) {
  try {
    const newPath: string = await invoke("xploit_store_duplicate", { path: t.path });
    log.dim(`duplicated → ${newPath}`);
    await reload();
  } catch (e: any) { log.err(String(e)); }
}

async function run() {
  if (running.value) return;
  const tgts = targets.value.split(/[\s,\n]+/).map((s) => s.trim()).filter(Boolean);
  if (!tgts.length) { log.err("no targets"); return; }
  const paths = Array.from(selected.value);
  if (!paths.length) { log.err("no templates selected"); return; }

  running.value = true;
  progress.value = { done: 0, total: 0 };
  log.clear();
  log.info(`loading ${paths.length} template(s) × ${tgts.length} target(s)`);

  // read raw YAMLs
  const yamls: string[] = [];
  for (const p of paths) {
    try { yamls.push(await invoke<string>("xploit_store_read", { path: p })); }
    catch (e: any) { log.warn(`skip ${p}: ${e}`); }
  }

  unlistens.push(await listen<string>("xpl:status", (e) => log.dim(String(e.payload))));
  unlistens.push(await listen<{ done: number; total: number }>("xpl:progress", (e) => { progress.value = e.payload; }));
  unlistens.push(await listen<any>("xpl:hit", (e) => {
    const f = e.payload;
    const sev = (f.severity || "info").toLowerCase();
    const matchers = f.matcher_names?.length ? ` {${f.matcher_names.join(",")}}` : "";
    const extras: string[] = [];
    if (f.cve_id) extras.push(f.cve_id);
    if (f.cvss) extras.push(`cvss:${f.cvss}`);
    const extra = extras.length ? ` [${extras.join(" ")}]` : "";
    const msg = `[${sev.toUpperCase()}] ${f.template_id} :: ${f.target} → ${f.matched_url} (${f.status})${matchers}${extra}`;
    if (sev === "critical" || sev === "high") log.hit(msg);
    else if (sev === "medium") log.warn(msg);
    else log.ok(msg);
  }));

  try {
    const res: any[] = await invoke("xploit_run", {
      req: {
        targets: tgts,
        templates_yaml: yamls,
        concurrency: 15,
        timeout_ms: 10000,
      },
    });
    log.ok(`xploit complete: ${res.length} finding(s)`);
  } catch (e: any) {
    log.err(String(e));
  } finally {
    running.value = false;
    cleanup();
  }
}

function cleanup() { while (unlistens.length) { const u = unlistens.pop(); if (u) u(); } }

onMounted(bootstrap);
onUnmounted(cleanup);

// ---------- editor helpers ----------
const helperPlaceholders = ["{{BaseURL}}", "{{Hostname}}", "{{randstr}}", "{{rand_int}}", "{{unix_time}}"];
const dslExamples = [
  "status == 200",
  "duration > 5000",
  'contains(body, "text")',
  'regex(body, "^pat$")',
];

function onContentChange(e: Event) {
  editorContent.value = (e.target as HTMLTextAreaElement).value;
  editorDirty.value = true;
}
</script>

<template>
  <div class="module">
    <!-- ============ LIST VIEW ============ -->
    <template v-if="view === 'list'">
      <div class="form">
        <label class="ta">
          <span class="lbl">targets</span>
          <textarea class="term-input" v-model="targets" placeholder="https://target.com&#10;https://another.com" rows="2" spellcheck="false" />
        </label>

        <div class="row">
          <label class="mini wide"><span>search</span><input v-model="query" placeholder="rce, lfi, ssti, cve..." @keyup.enter="reload" /></label>
          <label class="mini wide"><span>tag</span><input v-model="tagFilter" placeholder="rce, exposure..." @keyup.enter="reload" /></label>
          <button class="btn-ghost" @click="reload">reload</button>
        </div>

        <div class="row">
          <label class="toggle"><input type="checkbox" v-model="severities.critical" /><span>critical</span></label>
          <label class="toggle"><input type="checkbox" v-model="severities.high" /><span>high</span></label>
          <label class="toggle"><input type="checkbox" v-model="severities.medium" /><span>medium</span></label>
          <label class="toggle"><input type="checkbox" v-model="severities.low" /><span>low</span></label>
          <label class="toggle"><input type="checkbox" v-model="severities.info" /><span>info</span></label>
        </div>
      </div>

      <div class="tpl-panel">
        <div class="tpl-head">
          <span class="tpl-title">arsenal // {{ templates.length }} templates // {{ selected.size }} armed</span>
          <button class="btn-ghost" @click="openEditor(null)">+ new</button>
          <button class="btn-ghost" @click="toggleAll">{{ selected.size === templates.length ? "unarm all" : "arm all" }}</button>
          <button class="exec small" :disabled="running || !selected.size" @click="run">
            {{ running ? "[ firing... ]" : `> fire (${selected.size})` }}
          </button>
        </div>
        <div class="tpl-list">
          <div v-if="!templates.length" class="tpl-empty">no templates match filters. click [+ new] to create one.</div>
          <div
            v-for="t in templates"
            :key="t.path"
            class="tpl-row"
            :class="{ picked: selected.has(t.path) }"
          >
            <input type="checkbox" :checked="selected.has(t.path)" @change="toggle(t.path)" @click.stop />
            <span class="sev" :class="`sev-${t.severity}`" @click="toggle(t.path)">{{ t.severity }}</span>
            <span class="tpl-id" @click="toggle(t.path)">{{ t.id }}</span>
            <span class="tpl-meta" @click="toggle(t.path)">
              <span class="tpl-tags">{{ t.tags.slice(0, 3).join(",") }}</span>
              <span v-if="t.builtin" class="tpl-badge">bundled</span>
            </span>
            <div class="tpl-actions">
              <button class="ico" @click.stop="openEditor(t)" title="edit">✎</button>
              <button class="ico" @click.stop="duplicate(t)" title="duplicate">⎘</button>
              <button class="ico danger" @click.stop="remove(t)" title="delete">✕</button>
            </div>
          </div>
        </div>
      </div>

      <div v-if="progress.total" class="bar">
        <div class="bar-fill" :style="{ width: (progress.done / progress.total) * 100 + '%' }" />
        <span class="bar-text">{{ progress.done }} / {{ progress.total }}</span>
      </div>

      <Terminal :lines="log.lines.value" title="xploiter // output" @clear="log.clear()" />
    </template>

    <!-- ============ EDITOR VIEW ============ -->
    <template v-else>
      <div class="editor-head">
        <button class="btn-ghost" @click="view = 'list'">◀ back</button>
        <input v-model="editorFilename" class="edit-filename" placeholder="filename.yaml" spellcheck="false" />
        <span v-if="editorDirty" class="dirty">● modified</span>
        <button class="exec small" @click="save">save</button>
      </div>
      <textarea
        class="editor-body term-input"
        :value="editorContent"
        @input="onContentChange"
        spellcheck="false"
        placeholder="# paste YAML template here"
      />
      <div class="editor-help">
        <div><strong>helpers:</strong>
          <code v-for="h in helperPlaceholders" :key="h">{{ h }}</code>
        </div>
        <div><strong>matchers:</strong> word, regex, status, size, binary(hex), dsl</div>
        <div><strong>dsl:</strong>
          <template v-for="(d, i) in dslExamples" :key="d">
            <code>{{ d }}</code><span v-if="i < dslExamples.length - 1">, </span>
          </template>
        </div>
        <div><strong>attack:</strong> batteringram | pitchfork | clusterbomb</div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.tpl-panel {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border);
  background: var(--bg-panel);
  min-height: 180px;
  max-height: 340px;
  overflow: hidden;
}
.tpl-head {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-elev);
  flex-wrap: wrap;
}
.tpl-title {
  flex: 1;
  font-size: 10px;
  color: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  min-width: 0;
}
.exec.small { padding: 3px 10px; font-size: 11px; flex: 0 0 auto; min-width: 0; }

.tpl-list { flex: 1; overflow-y: auto; }
.tpl-empty { padding: 16px; color: var(--fg-ghost); text-align: center; font-size: 11px; }

.tpl-row {
  display: grid;
  grid-template-columns: 18px 80px 1fr 1.2fr auto;
  gap: 6px;
  align-items: center;
  padding: 4px 8px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  font-size: 11px;
  transition: background 0.1s;
}
.tpl-row:hover { background: rgba(255, 255, 255, 0.02); }
.tpl-row.picked { background: rgba(255, 47, 74, 0.06); }
.tpl-row input[type="checkbox"] { accent-color: var(--alert); }
.tpl-id { color: var(--fg); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tpl-meta { display: flex; gap: 6px; align-items: center; overflow: hidden; min-width: 0; }
.tpl-tags { color: var(--info); font-size: 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.tpl-badge {
  font-size: 9px;
  color: var(--fg-dim);
  border: 1px solid var(--border-hot);
  padding: 0 4px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  flex-shrink: 0;
}
.tpl-actions { display: flex; gap: 2px; flex-shrink: 0; }
.ico {
  width: 24px; height: 24px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--fg-dim);
  border: 1px solid transparent;
  font-size: 13px;
}
.ico:hover { color: var(--fg); border-color: var(--border-hot); background: var(--bg); }
.ico.danger:hover { color: var(--alert); border-color: var(--alert); }

/* editor */
.editor-head {
  display: flex;
  gap: 6px;
  align-items: center;
  flex-wrap: wrap;
}
.edit-filename {
  flex: 1;
  min-width: 120px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 4px 8px;
  font-size: 12px;
  font-family: inherit;
}
.edit-filename:focus { border-color: var(--info); outline: none; }
.dirty { color: var(--warn); font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; }
.editor-body {
  flex: 1;
  min-height: 260px;
  font-size: 12px;
  line-height: 1.5;
  tab-size: 2;
}
.editor-help {
  font-size: 10px;
  color: var(--fg-dim);
  padding: 6px 8px;
  border: 1px solid var(--border);
  background: var(--bg-panel);
  line-height: 1.6;
}
.editor-help > div { margin-bottom: 3px; }
.editor-help > div:last-child { margin-bottom: 0; }
.editor-help code {
  color: var(--info);
  background: var(--bg);
  padding: 0 4px;
  margin: 0 2px;
  border: 1px solid var(--border);
  display: inline-block;
}
.editor-help strong {
  color: var(--alert);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-size: 9px;
  margin-right: 4px;
}

@media (max-width: 640px) {
  .tpl-row { grid-template-columns: 18px 60px 1fr auto; }
  .tpl-meta { display: none; }
}
</style>
