<template>
  <div class="app-shell">
    <StatusMessage />
    <main class="app-main">
      <HostProfileView v-if="authenticated && isHostMode" :initializing="loading" />
      <ProfileView v-else-if="authenticated" />
      <LoadingView v-else-if="loading" :message="loadingMessage" />
      <AuthRequiredMessage v-else-if="showBackMessage" @reload="reloadPage" />
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { apiJson, getAuthIframeUrl } from '@/utils/api'
import StatusMessage from '@/components/StatusMessage.vue'
import ProfileView from '@/components/ProfileView.vue'
import HostProfileView from '@/components/HostProfileView.vue'
import LoadingView from '@/components/LoadingView.vue'
import AuthRequiredMessage from '@/components/AccessDenied.vue'

const store = useAuthStore()
const loading = ref(true)
const loadingMessage = ref('Loading...')
const authenticated = ref(false)
const showBackMessage = ref(false)

/**
 * Normalize a host string for comparison (lowercase, strip default ports).
 */
function normalizeHost(raw) {
  if (!raw) return null
  const trimmed = raw.trim().toLowerCase()
  if (!trimmed) return null
  // Remove default ports
  return trimmed.replace(/:80$/, '').replace(/:443$/, '')
}

/**
 * Host mode is active when an auth_host is configured AND the current host differs from it.
 * In host mode, we show a limited profile view with logout and link to full profile.
 */
const isHostMode = computed(() => {
  const authHost = store.settings?.auth_host
  if (!authHost) return false
  const currentHost = normalizeHost(window.location.host)
  const configuredHost = normalizeHost(authHost)
  return currentHost !== configuredHost
})
let validationTimer = null
let authIframe = null

async function loadUserInfo() {
  try {
    store.userInfo = await apiJson('/auth/api/user-info', { method: 'POST' })
    authenticated.value = true
    loading.value = false
    startSessionValidation()
    return true
  } catch (e) {
    return false
  }
}

async function showAuthIframe() {
  // Remove existing iframe if any
  hideAuthIframe()

  // Create new iframe for authentication using src URL
  const url = await getAuthIframeUrl('login')
  authIframe = document.createElement('iframe')
  authIframe.id = 'auth-iframe'
  authIframe.title = 'Authentication'
  authIframe.allow = 'publickey-credentials-get; publickey-credentials-create'
  authIframe.src = url
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
      loadUserInfo()
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
    await apiJson('/auth/api/validate', {
      method: 'POST',
      credentials: 'include'
    })
    // If successful, session was renewed automatically
  } catch (error) {
    if (error.status === 401) {
      // Session expired - need to re-authenticate
      console.log('Session expired, requiring re-authentication')
      authenticated.value = false
      loading.value = true
      stopSessionValidation()
      showAuthIframe()
    } else {
      console.error('Session validation error:', error)
      // Don't treat network errors as session expiry
    }
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

  // Set appropriate page title based on mode
  const rpName = store.settings?.rp_name
  if (rpName) {
    // In host mode, show "account summary" style title
    // Settings are loaded but isHostMode depends on them, so check here
    const authHost = store.settings?.auth_host
    const inHostMode = authHost && normalizeHost(window.location.host) !== normalizeHost(authHost)
    document.title = inHostMode ? `${rpName} · Account summary` : rpName
  }

  // Try to load user info
  const success = await loadUserInfo()

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
