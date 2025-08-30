<template>
  <div class="dialog-overlay" @keydown.esc.prevent="$emit('close')">
    <div class="device-dialog" role="dialog" aria-modal="true" aria-labelledby="regTitle">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h2 id="regTitle" style="margin:0; font-size:1.25rem;">📱 Device Registration Link</h2>
        <button class="icon-btn" @click="$emit('close')" aria-label="Close">❌</button>
      </div>
      <div class="device-link-section">
        <div class="qr-container">
          <a v-if="url" :href="url" @click.prevent="copy" class="qr-link">
            <canvas ref="qrCanvas" class="qr-code"></canvas>
            <p>{{ displayUrl }}</p>
          </a>
          <div v-else>
            <em>Generating link...</em>
          </div>
          <p>
            <strong>Scan and visit the URL on another device.</strong><br>
            <small>⚠️ Expires in 24 hours and one-time use.</small>
          </p>
          <div v-if="expires" style="font-size:12px; margin-top:6px;">Expires: {{ new Date(expires).toLocaleString() }}</div>
        </div>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:.5rem; margin-top:10px;">
        <button class="btn-secondary" @click="$emit('close')">Close</button>
        <button class="btn-primary" :disabled="!url" @click="copy">Copy Link</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch, computed, nextTick } from 'vue'
import QRCode from 'qrcode/lib/browser'

const props = defineProps({
  endpoint: { type: String, required: true }, // POST endpoint returning {url, expires}
  autoCopy: { type: Boolean, default: true }
})

const emit = defineEmits(['close','generated','copied'])

const url = ref(null)
const expires = ref(null)
const qrCanvas = ref(null)

const displayUrl = computed(() => url.value ? url.value.replace(/^[^:]+:\/\//,'') : '')

async function fetchLink() {
  try {
    const res = await fetch(props.endpoint, { method: 'POST' })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    url.value = data.url
    expires.value = data.expires
    emit('generated', { url: data.url, expires: data.expires })
    await nextTick()
    drawQR()
    if (props.autoCopy) copy()
  } catch (e) {
    url.value = null
    expires.value = null
    console.error('Failed to create link', e)
  }
}

async function drawQR() {
  if (!url.value) return
  await nextTick()
  if (!qrCanvas.value) return
  QRCode.toCanvas(qrCanvas.value, url.value, { scale: 8 }, err => { if (err) console.error(err) })
}

async function copy() {
  if (!url.value) return
  try { await navigator.clipboard.writeText(url.value); emit('copied', url.value); emit('close') } catch (_) { /* ignore */ }
}

onMounted(fetchLink)
watch(url, () => drawQR(), { flush: 'post' })
</script>
<style scoped>
.icon-btn { background:none; border:none; cursor:pointer; font-size:1rem; opacity:.6; }
.icon-btn:hover { opacity:1; }
/* Minimal extra styling; main look comes from global styles */
.qr-link { text-decoration:none; color:inherit; }
</style>
