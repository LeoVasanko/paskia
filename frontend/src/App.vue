<template>
  <div class="app-shell">
    <StatusMessage />
    <main class="app-main">
      <ProfileView v-if="authenticated" />
      <div v-else-if="loading" class="loading-container">
        <div class="loading-spinner"></div>
        <p>{{ loadingMessage }}</p>
      </div>
      <div v-else-if="showBackMessage" class="message-container">
        <div class="message-content">
          <h2>🔒 Authentication Required</h2>
          <p>You need to authenticate to access this page.</p>
          <div class="button-row">
            <button class="btn-primary" @click="reloadPage">Reload Page</button>
          </div>
        </div>
      </div>
    </main>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import StatusMessage from '@/components/StatusMessage.vue'
import ProfileView from '@/components/ProfileView.vue'

const store = useAuthStore()
const loading = ref(true)
const loadingMessage = ref('Loading...')
const authenticated = ref(false)
const showBackMessage = ref(false)
let validationTimer = null
let authIframe = null

// Watch for auth required flag from store
watch(() => store.authRequired, (required) => {
  if (required) {
    authenticated.value = false
    loading.value = true
    stopSessionValidation()
    showAuthIframe()
    store.clearAuthRequired()
  }
})

async function tryLoadUserInfo() {
  try {
    await store.loadUserInfo()
    authenticated.value = true
    loading.value = false
    startSessionValidation()
    return true
  } catch (error) {
    // User info load failed - likely 401
    return false
  }
}

function showAuthIframe() {
  // Remove existing iframe if any
  hideAuthIframe()

  // Create new iframe for authentication
  authIframe = document.createElement('iframe')
  authIframe.id = 'auth-iframe'
  authIframe.title = 'Authentication'
  authIframe.src = '/auth/restricted-api/?mode=login'
  document.body.appendChild(authIframe)
  loadingMessage.value = 'Authentication required...'
}

function hideAuthIframe() {
  if (authIframe) {
    authIframe.remove()
    authIframe = null
  }
}

function reloadPage() {
  window.location.reload()
}

function handleAuthMessage(event) {
  const data = event.data
  if (!data?.type) return

  switch (data.type) {
    case 'auth-success':
      // Authentication successful - reload user info
      hideAuthIframe()
      loading.value = true
      loadingMessage.value = 'Loading user profile...'
      store.clearAuthRequired()
      tryLoadUserInfo()
      break

    case 'auth-error':
      // Authentication failed - keep iframe open so user can retry
      if (data.cancelled) {
        console.log('Authentication cancelled by user')
      } else {
        store.showMessage(data.message || 'Authentication failed', 'error', 5000)
      }
      break

    case 'auth-cancelled':
      // Legacy support - treat as auth-error with cancelled flag
      console.log('Authentication cancelled')
      break

    case 'auth-back':
      // User clicked Back - show message with reload option
      hideAuthIframe()
      loading.value = false
      showBackMessage.value = true
      break

    case 'auth-close-request':
      // Legacy support - treat as back
      hideAuthIframe()
      break
  }
}

async function validateSession() {
  try {
    const response = await fetch('/auth/api/validate', {
      method: 'POST',
      credentials: 'include'
    })

    if (response.status === 401) {
      // Session expired - need to re-authenticate
      console.log('Session expired, requiring re-authentication')
      authenticated.value = false
      loading.value = true
      stopSessionValidation()
      showAuthIframe()
    }
    // If successful, session was renewed automatically
  } catch (error) {
    console.error('Session validation error:', error)
    // Don't treat network errors as session expiry
  }
}

function startSessionValidation() {
  // Validate session every 2 minutes
  stopSessionValidation()
  validationTimer = setInterval(validateSession, 2 * 60 * 1000)
}

function stopSessionValidation() {
  if (validationTimer) {
    clearInterval(validationTimer)
    validationTimer = null
  }
}

onMounted(async () => {
  // Listen for postMessage from auth iframe
  window.addEventListener('message', handleAuthMessage)

  // Load settings
  await store.loadSettings()
  if (store.settings?.rp_name) document.title = store.settings.rp_name

  // Try to load user info
  const success = await tryLoadUserInfo()

  if (!success) {
    // Need authentication - show login iframe
    showAuthIframe()
  }
})

onUnmounted(() => {
  window.removeEventListener('message', handleAuthMessage)
  stopSessionValidation()
  hideAuthIframe()
})
</script>

<style scoped>
.loading-container { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; gap: 1rem; }
.loading-spinner { width: 40px; height: 40px; border: 4px solid var(--color-border); border-top: 4px solid var(--color-primary); border-radius: 50%; animation: spin 1s linear infinite; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
.loading-container p { color: var(--color-text-muted); margin: 0; }

.message-container { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; padding: 2rem; }
.message-content { text-align: center; max-width: 480px; }
.message-content h2 { margin: 0 0 1rem; color: var(--color-heading); }
.message-content p { color: var(--color-text-muted); margin: 0 0 1.5rem; }
.message-content .button-row { display: flex; gap: 0.75rem; justify-content: center; }
</style>
