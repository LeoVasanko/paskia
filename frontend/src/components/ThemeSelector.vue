<template>
  <div class="theme-selector" @click.stop>
    <button v-for="t in themes" :key="t.value" class="theme-icon" :class="{ hidden: isHidden(t.value) }"
      :style="{ top: getPos(t.value).y + 'px', left: getPos(t.value).x + 'px' }" :title="t.title"
      @click="handleClick(t.value)">{{ t.icon }}</button>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { apiJson } from 'paskia'
import { updateThemeFromSession, getCachedTheme } from '@/utils/theme'

const open = ref(false), closing = ref(false), closingValue = ref(null), selected = ref(getCachedTheme())
const themes = [{ value: '', icon: '🌓', title: 'Auto' }, { value: 'light', icon: '☀️', title: 'Light' }, { value: 'dark', icon: '🌙', title: 'Dark' }]
const center = { x: 16, y: 16 }
const expanded = { '': { x: 16, y: 0 }, light: { x: 0, y: 28 }, dark: { x: 32, y: 28 } }

const getPos = v => closing.value ? (v === closingValue.value ? center : expanded[v]) : open.value ? expanded[v] : (v === selected.value ? center : expanded[v])
const isHidden = v => closing.value ? v !== closingValue.value : !open.value && v !== selected.value

function close(v) {
  closingValue.value = v
  closing.value = true
  setTimeout(() => { open.value = closing.value = false; closingValue.value = null }, 200)
}

function handleClick(v) {
  if (!open.value) { open.value = true; return }
  close(v)
  setTimeout(() => {
    selected.value = v
    updateThemeFromSession({ user: { theme: v } }, true)
    apiJson('/auth/api/user/theme', { method: 'PATCH', body: { theme: v } }).catch(() => {})
  }, 200)
}

function onOutside(e) { if (open.value && !closing.value && !e.target.closest('.theme-selector')) close(selected.value) }
onMounted(() => document.addEventListener('click', onOutside))
onUnmounted(() => document.removeEventListener('click', onOutside))
</script>

<style scoped>
.theme-selector { position: relative; width: 2rem; height: 2rem; }
.theme-icon { position: absolute; transform: translate(-50%, -50%); background: none; border: none; font-size: 1.25rem; cursor: pointer; padding: 0.25rem; transition: top 0.2s, left 0.2s, opacity 0.15s; }
.theme-icon:hover, .theme-icon:focus-visible { transform: translate(-50%, -50%) scale(1.15); }
.theme-icon.hidden { opacity: 0; pointer-events: none; }
</style>
