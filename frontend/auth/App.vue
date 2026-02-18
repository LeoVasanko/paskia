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
import { apiJson, SessionValidator } from 'paskia'
import { updateThemeFromSession } from '@/utils/theme'
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

function onSessionLost(e) {
  store.userInfo = null
  store.ctx = null
  if (e?.name === 'AuthCancelledError') {
    viewState.value = 'terminal'
  } else {
    store.showMessage(e?.message || 'Session lost', 'error', 5000)
    viewState.value = 'terminal'
  }
}

const userUuidGetter = () => store.ctx?.user.uuid
const sessionValidator = new SessionValidator(userUuidGetter, onSessionLost)

onMounted(() => sessionValidator.start())
onUnmounted(() => sessionValidator.stop())

async function loadUserInfo() {
  viewState.value = 'loading'
  loadingMessage.value = 'Loading...'
  try {
    // apiJson handles 401/403 with auth.iframe automatically:
    // shows overlay iframe, waits for auth, retries the request.
    const [validateData, userInfoData] = await Promise.all([
      apiJson('/auth/api/validate', { method: 'POST' }),
      apiJson('/auth/api/user-info', { method: 'GET' })
    ])
    store.userInfo = userInfoData
    store.ctx = validateData.ctx
    updateThemeFromSession(store.userInfo)
    // Verify that the user UUIDs match between user-info and validate responses
    if (store.userInfo.user.uuid !== store.ctx.user.uuid) {
      console.error('User UUID mismatch between user-info and validate responses')
      window.location.reload()
      return
    }
    viewState.value = 'profile'
  } catch (e) {
    onSessionLost(e)
  }
}

onMounted(async () => {
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

  // Load user info (apiJson handles auth iframe if needed)
  await loadUserInfo()
})
</script>
