<script setup lang="ts">
defineProps<{ label: string; modelValue: string; placeholder?: string }>();
defineEmits<{ (e: "update:modelValue", v: string): void }>();
</script>

<template>
  <label class="prompt">
    <span class="plabel">{{ label }}</span>
    <span class="parrow">»</span>
    <input
      :value="modelValue"
      :placeholder="placeholder"
      spellcheck="false"
      autocomplete="off"
      autocapitalize="off"
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    />
  </label>
</template>

<style scoped>
.prompt {
  display: flex;
  align-items: center;
  gap: 6px;
  border: 1px solid var(--border);
  padding: 6px 8px;
  background: var(--bg-panel);
  transition: border-color 0.15s;
}
.prompt:focus-within {
  border-color: var(--accent);
}
.plabel {
  color: var(--accent);
  font-weight: 500;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  min-width: 72px;
}
.parrow {
  color: var(--fg-dim);
}
input {
  flex: 1;
  color: var(--fg);
  min-width: 0;
}
input::placeholder {
  color: var(--fg-ghost);
}
</style>
