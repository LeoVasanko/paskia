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
      <p class="toggle-link">
        <a href="#" @click.prevent="authStore.currentView = 'register'">
          Don't have an account? Register here
        </a>
      </p>
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
    authStore.currentView = 'profile'
  } catch (error) {
    authStore.showMessage(`Authentication failed: ${error.message}`, 'error')
  }
}
</script>
