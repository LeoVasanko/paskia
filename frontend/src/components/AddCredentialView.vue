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
import { ref, computed } from 'vue'

const authStore = useAuthStore()
const hasDeviceSession = computed(() => !!authStore.currentUser)

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
