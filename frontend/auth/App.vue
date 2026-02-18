<template>
  <div class="app-shell">
    <StatusMessage />
    <main class="app-main">
      <HostProfileView v-if="viewState === 'profile' && isHostMode" />
      <ProfileView v-else-if="viewState === 'profile'" />
      <LoadingView v-else-if="viewState === 'loading'" :message="loadingMessage" />
      <AccessDenied v-else-if="viewState === 'terminal'" />
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { apiJson, SessionValidator, createAuthIframe, removeAuthIframe } from 'paskia'
import { getAuthIframeUrl } from '@/utils/api'
import StatusMessage from '@/components/StatusMessage.vue'
import ProfileView from '@/components/ProfileView.vue'
import HostProfileView from '@/components/HostProfileView.vue'
import LoadingView from '@/components/LoadingView.vue'
import AccessDenied from '@/components/AccessDenied.vue'

const store = useAuthStore()
const viewState = ref('loading')  // 'loading' | 'profile' | 'terminal'
const loadingMessage = ref('Loading...')

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

function terminateSession() {
  store.userInfo = null
  viewState.value = 'terminal'
}

const userUuidGetter = () => store.ctx?.user.uuid
const sessionValidator = new SessionValidator(userUuidGetter, terminateSession)

onMounted(() => sessionValidator.start())
onUnmounted(() => sessionValidator.stop())

async function loadUserInfo() {
  try {
    const [validateData, userInfoData] = await Promise.all([
      apiJson('/auth/api/validate', { method: 'POST' }),
      apiJson('/auth/api/user-info', { method: 'GET' })
    ])
    store.userInfo = userInfoData
    store.ctx = validateData.ctx
    // Verify that the user UUIDs match between user-info and validate responses
    if (store.userInfo.user.uuid !== store.ctx.user.uuid) {
      console.error('User UUID mismatch between user-info and validate responses')
      window.location.reload()
      return false
    }
    viewState.value = 'profile'
    return true
  } catch {
    store.userInfo = null
    store.ctx = null
    return false
  }
}

async function showAuthIframe() {
  const url = await getAuthIframeUrl('login')
  createAuthIframe(url)
  loadingMessage.value = 'Authentication required...'
}

function handleAuthMessage(event) {
  const data = event.data
  if (!data?.type) return

  switch (data.type) {
    case 'auth-success':
      // Authentication successful - reload user info
      removeAuthIframe()
      viewState.value = 'loading'
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
      // User clicked Back - show terminal state
      removeAuthIframe()
      terminateSession()
      break

    case 'auth-close-request':
      // Legacy support - treat as back
      removeAuthIframe()
      break
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
  removeAuthIframe()
})
</script>
