<template>
  <div v-if="linkUrl" class="dialog-overlay" @click="$emit('close')">
    <div ref="dialog" class="modal-panel" @keydown="handleDialogKeydown" @click.stop>
      <div class="device-dialog" role="dialog" aria-modal="true" aria-labelledby="regTitle">
      <div class="reg-header-row">
        <h2 id="regTitle" class="reg-title">
          📱 <span v-if="userName">{{ tokenType === 'account recovery' ? 'Recovery' : 'Registration' }} for {{ userName }}</span><span v-else>Add Another Device</span>
        </h2>
        <button class="icon-btn" @click="$emit('close')" aria-label="Close" tabindex="-1">✕</button>
      </div>

      <div class="device-link-section">
        <p class="reg-help">
          {{ helpText }}
        </p>

        <QRCodeDisplay
          :url="linkUrl"
          :show-link="true"
          @copied="onCopied"
          @keydown="handleQRKeydown"
        />

        <p class="expiry-note" v-if="expiresAt">
          This link expires {{ formatDate(expiresAt).toLowerCase() }}.
        </p>
      </div>

      <div class="reg-actions" ref="actionsRow" @keydown="handleActionsKeydown">
        <button class="btn-secondary" @click="$emit('close')">Close</button>
      </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import QRCodeDisplay from '@/components/QRCodeDisplay.vue'
import { apiJson, holdGlobalBackdrop, releaseGlobalBackdrop } from 'paskia'
import { formatDate } from '@/utils/helpers'
import { getDirection } from '@/utils/keynav'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  endpoint: { type: String, required: true },
  userName: { type: String, default: '' }
})

const emit = defineEmits(['close', 'copied'])

const authStore = useAuthStore()
const dialog = ref(null)
const linkUrl = ref(null)
const expiresAt = ref(null)
const tokenType = ref(null)
const actionsRow = ref(null)
// Store the element that had focus before modal opened
const previouslyFocusedElement = ref(null)

// Determine if this is an admin action for another user
const isAdminAction = computed(() => !!props.userName)

// Compute the help text based on token type and context
const helpText = computed(() => {
  if (!isAdminAction.value) {
    // User adding their own device
    return 'Scan this QR code on the new device, or copy the link and open it there.'
  }
  // Admin action for another user
  return `Send this link to ${props.userName}, or have them scan the QR code.`
})

async function generateLink() {
  try {
    const data = await apiJson(props.endpoint, { method: 'POST' })
    if (data.url) {
      linkUrl.value = data.url
      expiresAt.value = data.expires ? new Date(data.expires) : null
      tokenType.value = data.token_type || null

      holdGlobalBackdrop()

      // Focus primary button (or first button if no primary) after content renders
      await nextTick()
      const actions = actionsRow.value
      const target = actions?.querySelector('.btn-primary') || actions?.querySelector('button')
      target?.focus()
    } else {
      emit('close')
    }
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to generate link', 'error')
    emit('close')
  }
}

function onCopied() {
  emit('copied')
}

const handleDialogKeydown = (event) => {
  // ESC to close
  if (event.key === 'Escape') {
    event.preventDefault()
    emit('close')
    return
  }
  // Handle other key navigation
  const direction = getDirection(event)
  if (!direction) return

  if (direction === 'down' || direction === 'up') {
    // Let the individual handlers manage navigation
    return
  }
}

const handleQRKeydown = (event) => {
  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  // Navigation constrained within modal: QR link <-> Close button
  if (direction === 'down' || direction === 'up') {
    // Toggle between QR link and close button
    actionsRow.value?.querySelector('button')?.focus()
  }
  // Left/right do nothing on QR code
}

const handleActionsKeydown = (event) => {
  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  // Navigation constrained within modal: Close button <-> QR link
  if (direction === 'up' || direction === 'down') {
    // Toggle between close button and QR link
    document.querySelector('.qr-link')?.focus()
  }
  // Left/right do nothing (only one button)
}

onMounted(() => {
  // Save currently focused element before modal takes focus
  previouslyFocusedElement.value = document.activeElement
  generateLink()
})

onUnmounted(() => {
  if (linkUrl.value) releaseGlobalBackdrop()
  // Restore focus when modal closes
  const prev = previouslyFocusedElement.value
  if (prev && document.body.contains(prev) && !prev.disabled) {
    prev.focus()
  }
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
.expiry-note { font-size: .75rem; color: var(--color-text-muted); text-align: center; margin-top: .75rem; }
</style>
