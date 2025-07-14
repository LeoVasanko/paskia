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
import { registerWithToken } from '@/utils/passkey'
import { ref, onMounted } from 'vue'
import { getCookie } from '@/utils/helpers'

const authStore = useAuthStore()
const token = ref(null)

// Check existing session on app load
onMounted(() => {
  // Check for 'auth-token' cookie
  token.value = getCookie('auth-token')
  if (!token.value) {
    authStore.showMessage('No registration token cookie found.', 'error')
    authStore.currentView = 'login'
    return
  }
  // Delete the cookie
  document.cookie = 'auth-token=; Max-Age=0; path=/'
})

function register() {
  authStore.isLoading = true
  authStore.showMessage('Starting registration...', 'info')
  registerWithToken(token.value).finally(() => {
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
