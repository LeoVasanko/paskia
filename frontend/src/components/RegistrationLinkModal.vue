<template>
  <div v-if="!inline" class="dialog-overlay" @keydown.esc.prevent="$emit('close')">
    <div class="device-dialog" role="dialog" aria-modal="true" aria-labelledby="regTitle">
      <div class="reg-header-row">
        <h2 id="regTitle" class="reg-title">
          📱 <span v-if="userName">Registration for {{ userName }}</span><span v-else>Device Registration Link</span>
        </h2>
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
          <p class="reg-help">
            <span v-if="userName">The user should open this link on the device where they want to register.</span>
            <span v-else>Open or scan this link on the device you wish to register to your account.</span>
            <br><small>{{ expirationMessage }}</small>
          </p>
        </div>
      </div>
      <div class="reg-actions">
        <button class="btn-secondary" @click="$emit('close')">Close</button>
        <button class="btn-primary" :disabled="!url" @click="copy">Copy Link</button>
      </div>
    </div>
  </div>
  <div v-else class="registration-inline-wrapper">
    <div class="registration-inline-block section-block">
      <div class="section-header">
        <h2 class="inline-heading">📱 <span v-if="userName">Registration for {{ userName }}</span><span v-else>Device Registration Link</span></h2>
      </div>
      <div class="section-body">
        <div class="device-link-section">
          <div class="qr-container">
            <a v-if="url" :href="url" @click.prevent="copy" class="qr-link">
              <canvas ref="qrCanvas" class="qr-code"></canvas>
              <p>{{ displayUrl }}</p>
            </a>
            <div v-else>
              <em>Generating link...</em>
            </div>
            <p class="reg-help">
              <span v-if="userName">The user should open this link on the device where they want to register.</span>
              <span v-else>Open this link on the device you wish to connect with.</span>
              <br><small>{{ expirationMessage }}</small>
            </p>
          </div>
        </div>
        <div class="button-row" style="margin-top:1rem;">
          <button class="btn-primary" :disabled="!url" @click="copy">Copy Link</button>
          <button v-if="showCloseInInline" class="btn-secondary" @click="$emit('close')">Close</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch, computed, nextTick } from 'vue'
import QRCode from 'qrcode/lib/browser'
import { formatDate } from '@/utils/helpers'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()

const props = defineProps({
  endpoint: { type: String, required: true },
  autoCopy: { type: Boolean, default: true },
  userName: { type: String, default: null },
  inline: { type: Boolean, default: false },
  showCloseInInline: { type: Boolean, default: false },
  prefixCopyWithUserName: { type: Boolean, default: false }
})

const emit = defineEmits(['close','generated','copied'])

const url = ref(null)
const expires = ref(null)
const qrCanvas = ref(null)

const displayUrl = computed(() => url.value ? url.value.replace(/^[^:]+:\/\//,'') : '')

const expirationMessage = computed(() => {
  const timeStr = formatDate(expires.value)
  return `⚠️ Expires ${timeStr.startsWith('In ') ? timeStr.substring(3) : timeStr} and can only be used once.`
})

async function fetchLink() {
  try {
    const res = await fetch(props.endpoint, { method: 'POST' })
    if (res.status === 401) {
      authStore.authRequired = true
      emit('close')
      return
    }
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
  let text = url.value
  if (props.prefixCopyWithUserName && props.userName) {
    text = `${props.userName} ${text}`
  }
  try {
    await navigator.clipboard.writeText(text)
    emit('copied', text)
    if (!props.inline) emit('close')
  } catch (_) {
    /* ignore */
  }
}

onMounted(fetchLink)
watch(url, () => drawQR(), { flush: 'post' })

</script>
<style scoped>
.icon-btn { background:none; border:none; cursor:pointer; font-size:1rem; opacity:.6; }
.icon-btn:hover { opacity:1; }
/* Minimal extra styling; main look comes from global styles */
.qr-link { text-decoration:none; color:inherit; }
.reg-header-row { display:flex; justify-content:space-between; align-items:center; gap:.75rem; margin-bottom:.75rem; }
.reg-title { margin:0; font-size:1.25rem; font-weight:600; }
.device-dialog { background: var(--color-surface); padding: 1.25rem 1.25rem 1rem; border-radius: var(--radius-md); max-width:480px; width:100%; box-shadow:0 6px 28px rgba(0,0,0,.25); }
.qr-container { display:flex; flex-direction:column; align-items:center; gap:.5rem; }
.qr-code { display:block; }
.reg-help { margin-top:.5rem; margin-bottom:.75rem; font-size:.85rem; line-height:1.25rem; text-align:center; }
.reg-actions { display:flex; justify-content:flex-end; gap:.5rem; margin-top:.25rem; }
.registration-inline-block .qr-container { align-items:flex-start; }
.registration-inline-block .reg-help { text-align:left; }
</style>
