<template>
  <div class="container">
    <div class="view active">
      <h1>🔑 Add Device Credential</h1>
      <button
        class="btn-primary"
        :disabled="authStore.isLoading"
        @click="register"
      >
        {{ authStore.isLoading ? 'Registering...' : 'Register Passkey' }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { useAuthStore } from '@/stores/auth'
import { registerCredential } from '@/utils/passkey'
import { ref, onMounted } from 'vue'

const authStore = useAuthStore()
const hasDeviceSession = ref(false)

// Check existing session on app load
onMounted(async () => {
  try {
    // Check if we have a device addition session
    const response = await fetch('/auth/device-session-check')
    const data = await response.json()

    if (data.device_addition_session) {
      hasDeviceSession.value = true
    } else {
      authStore.showMessage('No device addition session found.', 'error')
      authStore.currentView = 'login'
    }
  } catch (error) {
    authStore.showMessage('Failed to check device addition session.', 'error')
    authStore.currentView = 'login'
  }
})

function register() {
  if (!hasDeviceSession.value) {
    authStore.showMessage('No valid device addition session', 'error')
    return
  }

  authStore.isLoading = true
  authStore.showMessage('Starting registration...', 'info')
  registerCredential().finally(() => {
    authStore.isLoading = false
  }).then(() => {
    authStore.showMessage('Passkey registered successfully!', 'success', 2000)
    authStore.currentView = 'profile'
  }).catch((error) => {
    console.error('Registration error:', error)
    if (error.name === "NotAllowedError") {
      authStore.showMessage('Registration cancelled', 'error')
    } else {
      authStore.showMessage(`Registration failed: ${error.message}`, 'error')
    }
  })
}
</script>
