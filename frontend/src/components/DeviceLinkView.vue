<template>
  <section class="view-root view-device-link">
    <div class="view-content view-content--narrow">
      <header class="view-header">
        <h1>📱 Add Another Device</h1>
        <p class="view-lede">Generate a one-time link to set up passkeys on a new device.</p>
      </header>
      <section class="section-block">
        <div class="section-body">
          <div class="device-link-section">
            <div class="qr-container">
              <a :href="url" class="qr-link" @click="copyLink">
                <canvas ref="qrCanvas" class="qr-code"></canvas>
                <p v-if="url">
                  {{ url.replace(/^[^:]+:\/\//, '') }}
                </p>
                <p v-else>
                  <em>Generating link...</em>
                </p>
              </a>
              <p>
                <strong>Scan and visit the URL on another device.</strong><br>
                <small>⚠️ Expires in 24 hours and can only be used once.</small>
              </p>
            </div>
          </div>
          <div class="button-row">
            <button @click="authStore.currentView = 'profile'" class="btn-secondary">
              Back to Profile
            </button>
          </div>
        </div>
      </section>
    </div>
  </section>
</template>

<script setup>
import { ref, onMounted, nextTick } from 'vue'
import { useAuthStore } from '@/stores/auth'
import QRCode from 'qrcode/lib/browser'

const authStore = useAuthStore()
const url = ref(null)
const qrCanvas = ref(null)

const copyLink = async (event) => {
  event.preventDefault()
  if (url.value) {
    await navigator.clipboard.writeText(url.value)
    authStore.showMessage('Link copied to clipboard!')
    authStore.currentView = 'profile'
  }
}

async function drawQr() {
  if (!url.value || !qrCanvas.value) return
  await nextTick()
  QRCode.toCanvas(qrCanvas.value, url.value, { scale: 8 }, (error) => {
    if (error) console.error('Failed to generate QR code:', error)
  })
}

onMounted(async () => {
  try {
    const response = await fetch('/auth/api/create-link', { method: 'POST' })
    const result = await response.json()
    if (result.detail) throw new Error(result.detail)

    url.value = result.url
    await drawQr()
  } catch (error) {
    authStore.showMessage(`Failed to create device link: ${error.message}`, 'error')
    authStore.currentView = 'profile'
  }
})

</script>

<style scoped>
.view-content--narrow {
  max-width: 540px;
}

.view-lede {
  margin: 0;
  color: var(--color-text-muted);
}

.qr-link {
  text-decoration: none;
  color: var(--color-text);
}

.button-row {
  justify-content: flex-start;
}

@media (max-width: 720px) {
  .button-row {
    flex-direction: column;
  }

  .button-row button {
    width: 100%;
  }
}
</style>
