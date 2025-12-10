<template>
  <div class="qr-display">
    <div class="qr-section">
      <a :href="url" @click.prevent="copyLink" class="qr-link" title="Click to copy link" tabindex="0" @keydown.enter.prevent="copyLink">
        <canvas ref="qrCanvas" class="qr-code"></canvas>
        <div v-if="showLink && url" class="link-text">{{ displayUrl }}</div>
      </a>
    </div>

  </div>
</template>

<script setup>
import { ref, watch, nextTick, computed } from 'vue'
import QRCode from 'qrcode/lib/browser'

const props = defineProps({
  url: { type: String, required: true },
  showLink: { type: Boolean, default: false }
})

const emit = defineEmits(['copied'])

const qrCanvas = ref(null)

const displayUrl = computed(() => {
  if (!props.url) return ''
  return props.url.replace(/^https?:\/\//, '')
})

function drawQR() {
  if (!props.url || !qrCanvas.value) {
    return
  }

  try {
    // Clear the canvas first
    const ctx = qrCanvas.value.getContext('2d')
    ctx.clearRect(0, 0, qrCanvas.value.width, qrCanvas.value.height)

    // Generate QR code synchronously
    QRCode.toCanvas(qrCanvas.value, props.url, {
      scale: 6,
      margin: 0,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      }
    })

    // Remove any inline styles added by QRCode library immediately
    qrCanvas.value.removeAttribute('style')
  } catch (err) {
    console.error('QR code generation failed:', err)
  }
}

async function copyLink() {
  if (!props.url) return
  try {
    await navigator.clipboard.writeText(props.url)
    emit('copied')
  } catch (err) {
    console.error('Failed to copy link:', err)
  }
}

// Watch for URL changes
watch(() => props.url, () => {
  drawQR()
}, { immediate: true })

// Watch for canvas ref becoming available
watch(qrCanvas, () => {
  if (qrCanvas.value && props.url) {
    drawQR()
  }
}, { immediate: true })
</script>

<style scoped>
.qr-display {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
}

.qr-section {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
}

.qr-link {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-decoration: none;
  color: inherit;
  border-radius: var(--radius-sm, 6px);
  overflow: hidden;
}

.qr-code {
  display: block;
  width: 200px;
  height: 200px;
  max-width: 100%;
  object-fit: contain;
  border-radius: var(--radius-sm, 6px);
  background: #ffffff;
  cursor: pointer;
}

.link-text {
  padding: 0.5rem;
  font-size: 0.75rem;
  color: var(--color-text-muted);
  font-family: monospace;
  word-break: break-all;
  line-height: 1.2;
  transition: color 0.2s ease;
}

.qr-link:hover .link-text {
  color: var(--color-text);
}
</style>
