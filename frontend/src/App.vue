<template>
  <div class="app-shell">
    <StatusMessage />
    <main class="app-main">
      <!-- Only render views after authentication status is determined -->
      <template v-if="initialized">
        <LoginView v-if="store.currentView === 'login'" />
        <ProfileView v-if="store.currentView === 'profile'" />
        <DeviceLinkView v-if="store.currentView === 'device-link'" />
        <ResetView v-if="store.currentView === 'reset'" />
        <PermissionDeniedView v-if="store.currentView === 'permission-denied'" />
      </template>
      <!-- Show loading state while determining auth status -->
      <div v-else class="loading-container">
        <div class="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    </main>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import StatusMessage from '@/components/StatusMessage.vue'
import LoginView from '@/components/LoginView.vue'
import ProfileView from '@/components/ProfileView.vue'
import DeviceLinkView from '@/components/DeviceLinkView.vue'
import ResetView from '@/components/ResetView.vue'
import PermissionDeniedView from '@/components/PermissionDeniedView.vue'

const store = useAuthStore()
const initialized = ref(false)

onMounted(async () => {
  // Detect restricted mode:
  // We only allow full functionality on the exact /auth/ (or /auth) path.
  // Any other path (including /, /foo, /auth/admin, etc.) is treated as restricted
  // so the app will only show login or permission denied views.
  const path = location.pathname
  if (!(path === '/auth/' || path === '/auth')) {
    store.setRestrictedMode(true)
  }
  // Load branding / settings first (non-blocking for auth flow)
  await store.loadSettings()
  // Was an error message passed in the URL hash?
  const message = location.hash.substring(1)
  if (message) {
    store.showMessage(decodeURIComponent(message), 'error')
    history.replaceState(null, '', location.pathname)
  }
  // Capture reset token from query parameter and then remove it
  const params = new URLSearchParams(location.search)
  const reset = params.get('reset')
  if (reset) {
    store.resetToken = reset
    // Remove query param to avoid lingering in history / clipboard
    const targetPath = '/auth/'
    const currentPath = location.pathname.endsWith('/') ? location.pathname : location.pathname + '/'
    history.replaceState(null, '', currentPath.startsWith('/auth') ? '/auth/' : targetPath)
  }
  try {
    await store.loadUserInfo()
    initialized.value = true
    store.selectView()
  } catch (error) {
    console.log('Failed to load user info:', error)
    store.currentView = 'login'
    initialized.value = true
    store.selectView()
  }
})
</script>

<style scoped>
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100vh;
  gap: 1rem;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 4px solid var(--color-border);
  border-top: 4px solid var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.loading-container p {
  color: var(--color-text-muted);
  margin: 0;
}
</style>
