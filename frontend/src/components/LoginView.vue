<template>
  <div class="dialog-backdrop">
    <div class="dialog-container">
      <div class="dialog-content dialog-content--narrow">
        <header class="view-header">
          <h1>🔐 {{ (authStore.settings?.rp_name || location.origin)}}</h1>
          <p class="view-lede">User authentication is required for access.</p>
        </header>
        <section class="section-block">
          <form class="section-body" @submit.prevent="handleLogin">
            <button
              type="submit"
              class="btn-primary"
              :disabled="authStore.isLoading"
            >
              {{ authStore.isLoading ? 'Authenticating...' : 'Login with Your Device' }}
            </button>
          </form>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()

const handleLogin = async () => {
  try {
    authStore.showMessage('Starting authentication...', 'info')
    await authStore.authenticate()
    authStore.showMessage('Authentication successful!', 'success', 2000)
    authStore.currentView = 'profile'
  } catch (error) {
    authStore.showMessage(error.message, 'error')
  }
}
</script>

<style scoped>
.view-lede {
  margin: 0;
  color: var(--color-text-muted);
}

.section-body {
  gap: 1.5rem;
}

@media (max-width: 720px) {
  button {
    width: 100%;
  }
}
</style>
