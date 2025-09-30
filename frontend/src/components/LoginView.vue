<template>
  <section class="view-root view-login">
    <div class="view-content view-content--narrow">
      <header class="view-header">
        <h1>🔐 {{ (authStore.settings?.rp_name || 'Passkey') + ' Login' }}</h1>
        <p class="view-lede">Sign in securely with a device you trust.</p>
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
  </section>
</template>

<script setup>
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()

const handleLogin = async () => {
  try {
    authStore.showMessage('Starting authentication...', 'info')
    await authStore.authenticate()
    authStore.showMessage('Authentication successful!', 'success', 2000)
    if (authStore.restrictedMode) {
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

<style scoped>
.view-content--narrow {
  max-width: 420px;
}

.view-lede {
  margin: 0;
  color: var(--color-text-muted);
}

.view-login .section-body {
  gap: 1.5rem;
}

@media (max-width: 720px) {
  button {
    width: 100%;
  }
}
</style>
