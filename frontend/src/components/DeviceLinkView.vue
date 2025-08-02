<template>
  <div class="container">
    <div class="view active">
      <h1>📱 Add Device</h1>

      <div class="device-link-section">
        <h2>Device Addition Link</h2>
        <div class="qr-container">
          <canvas id="qrCode" class="qr-code"></canvas>
          <p v-if="url">
            <a :href="url" id="deviceLinkText" @click="copyLink">
              {{ url.replace(/^[^:]+:\/\//, '') }}
            </a>
          </p>
        </div>

        <p>
          <strong>Scan and visit the URL on another device.</strong><br>
          <small>⚠️ Expires in 24 hours and can only be used once.</small>
        </p>
      </div>

      <button @click="authStore.currentView = 'profile'" class="btn-secondary">
        Back to Profile
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import QRCode from 'qrcode/lib/browser'

const authStore = useAuthStore()
const url = ref(null)

const copyLink = async (event) => {
  event.preventDefault()
  if (url.value) {
    await navigator.clipboard.writeText(url.value)
    authStore.showMessage('Link copied to clipboard!')
    authStore.currentView = 'profile'
  }
}

onMounted(async () => {
  try {
    const response = await fetch('/auth/create-link', { method: 'POST' })
    const result = await response.json()
    if (result.error) throw new Error(result.error)

    url.value = result.url

    // Generate QR code
    const qrCodeElement = document.getElementById('qrCode')
    if (qrCodeElement) {
      QRCode.toCanvas(qrCodeElement, url.value, error => {
        if (error) console.error('Failed to generate QR code:', error)
      })
    }
  } catch (error) {
    console.error('Failed to create link:', error)
  }
})
</script>
