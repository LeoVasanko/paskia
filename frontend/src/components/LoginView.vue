<template>
  <div class="container">
    <div class="view active">
      <h1>🔐 Passkey Login</h1>
      <form @submit.prevent="handleLogin">
        <button
          type="submit"
          class="btn-primary"
          :disabled="authStore.isLoading"
        >
          {{ authStore.isLoading ? 'Authenticating...' : 'Login with Your Device' }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()

const handleLogin = async () => {
  try {
    console.log('Login button clicked')
    authStore.showMessage('Starting authentication...', 'info')
    await authStore.authenticate()
    authStore.showMessage('Authentication successful!', 'success', 2000)
    if (authStore.restrictedMode) {
      // In restricted mode after successful auth show permission denied (no profile outside /auth/)
      authStore.currentView = 'permission-denied'
    } else if (location.pathname.startsWith('/auth/')) {
      authStore.currentView = 'profile'
    } else {
      location.reload()
    }
  } catch (error) {
    authStore.showMessage(error.message, 'error')
  }
}
</script>
