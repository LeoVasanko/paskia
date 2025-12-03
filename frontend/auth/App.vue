<template>
  <div class="app-shell">
    <StatusMessage />
    <main class="app-main">
      <ProfileView v-if="authenticated" />
      <LoadingView v-else-if="loading" :message="loadingMessage" />
      <AuthRequiredMessage v-else-if="showBackMessage" @reload="reloadPage" />
    </main>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import StatusMessage from '@/components/StatusMessage.vue'
import ProfileView from '@/components/ProfileView.vue'
import LoadingView from '@/components/LoadingView.vue'
import AuthRequiredMessage from '@/components/AccessDenied.vue'

const store = useAuthStore()
const loading = ref(true)
const loadingMessage = ref('Loading...')
const authenticated = ref(false)
const showBackMessage = ref(false)
let validationTimer = null
let authIframe = null

async function tryLoadUserInfo() {
  try {
    await store.loadUserInfo()
    authenticated.value = true
    loading.value = false
    startSessionValidation()
    return true
  } catch (error) {
    // User info load failed - apiFetch will show iframe if needed
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
  authIframe.src = '/auth/restricted/?mode=login'
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
      store.showMessage('Authentication cancelled', 'info', 3000)
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
</style>
