<template>
  <div class="container">
    <div class="view active">
  <h1>🔐 {{ (authStore.settings?.rp_name || 'Passkey') + ' Login' }}</h1>
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
import { computed } from 'vue'

const authStore = useAuthStore()

const handleLogin = async () => {
  try {
    console.log('Login button clicked')
    authStore.showMessage('Starting authentication...', 'info')
    await authStore.authenticate()
    authStore.showMessage('Authentication successful!', 'success', 2000)
    if (authStore.restrictedMode) {
      // Restricted mode: reload so the app re-mounts and selectView() applies (will become permission denied)
      location.reload()
    } else if (location.pathname === '/auth/') {
      authStore.currentView = 'profile'
    } else {
      location.reload()
    }
  } catch (error) {
    authStore.showMessage(error.message, 'error')
  }
}
</script>
