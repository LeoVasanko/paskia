<template>
  <div class="dialog-overlay" @keydown.esc.prevent="$emit('close')">
    <div class="device-dialog" role="dialog" aria-modal="true" aria-labelledby="regTitle">
      <div class="reg-header-row">
        <h2 id="regTitle" class="reg-title">
          📱 <span v-if="userName">Registration for {{ userName }}</span><span v-else>Add Another Device</span>
        </h2>
        <button class="icon-btn" @click="$emit('close')" aria-label="Close">❌</button>
      </div>

      <div class="device-link-section">
        <!-- Loading state -->
        <div v-if="loading" class="loading-state">
          <div class="spinner-small"></div>
          <span>Generating registration link...</span>
        </div>

        <!-- Error state -->
        <div v-else-if="error" class="error-state">
          <p class="error-message">{{ error }}</p>
          <button class="btn-secondary" @click="generateLink">Retry</button>
        </div>

        <!-- Success state with QR code and link -->
        <template v-else-if="linkUrl">
          <p class="reg-help">
            Scan this QR code on the new device, or copy the link and open it there.
          </p>

          <QRCodeDisplay
            :url="linkUrl"
            :show-link="true"
            @copied="onCopied"
          />

          <p class="expiry-note" v-if="expiresAt">
            This link expires {{ formatDate(expiresAt).toLowerCase() }}.
          </p>
        </template>
      </div>

      <div class="reg-actions">
        <button class="btn-secondary" @click="$emit('close')">Close</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import QRCodeDisplay from '@/components/QRCodeDisplay.vue'
import { apiJson } from '@/utils/api'
import { formatDate } from '@/utils/helpers'

const props = defineProps({
  endpoint: { type: String, required: true },
  userName: { type: String, default: '' }
})

const emit = defineEmits(['close', 'copied'])

const loading = ref(true)
const error = ref(null)
const linkUrl = ref(null)
const expiresAt = ref(null)

async function generateLink() {
  loading.value = true
  error.value = null
  linkUrl.value = null
  expiresAt.value = null

  try {
    const data = await apiJson(props.endpoint, { method: 'POST' })
    if (data.url) {
      linkUrl.value = data.url
      expiresAt.value = data.expires ? new Date(data.expires) : null
    } else {
      error.value = data.detail || 'Failed to generate link'
    }
  } catch (err) {
    error.value = err.message || 'Failed to generate link'
  } finally {
    loading.value = false
  }
}

function onCopied() {
  emit('copied')
}

onMounted(() => {
  generateLink()
})
</script>

<style scoped>
.icon-btn { background: none; border: none; cursor: pointer; font-size: 1rem; opacity: .6; }
.icon-btn:hover { opacity: 1; }
.reg-header-row { display: flex; justify-content: space-between; align-items: center; gap: .75rem; margin-bottom: .75rem; }
.reg-title { margin: 0; font-size: 1.25rem; font-weight: 600; }
.device-dialog { background: var(--color-surface); padding: 1.25rem 1.25rem 1rem; border-radius: var(--radius-md); max-width: 480px; width: 100%; box-shadow: 0 6px 28px rgba(0,0,0,.25); }
.reg-help { margin: .5rem 0 .75rem; font-size: .85rem; line-height: 1.4; text-align: center; color: var(--color-text-muted); }
.reg-actions { display: flex; justify-content: flex-end; gap: .5rem; margin-top: 1rem; }
.loading-state { display: flex; align-items: center; justify-content: center; gap: .5rem; padding: 2rem 0; color: var(--color-text-muted); }
.error-state { text-align: center; padding: 1rem 0; }
.error-message { color: var(--color-danger-text); margin-bottom: 1rem; }
.expiry-note { font-size: .75rem; color: var(--color-text-muted); text-align: center; margin-top: .75rem; }
</style>
