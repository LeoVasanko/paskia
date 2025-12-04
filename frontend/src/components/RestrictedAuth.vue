<template>
  <div class="app-shell">
    <div v-if="status.show" class="global-status" style="display: block;">
      <div :class="['status', status.type]">
        {{ status.message }}
      </div>
    </div>

    <main class="view-root">
      <div v-if="!initializing" class="surface surface--tight">
        <header class="view-header center">
          <h1>{{ headingTitle }}</h1>
          <p v-if="isAuthenticated" class="user-line">👤 {{ userDisplayName }}</p>
          <p class="view-lede">{{ headerMessage }}</p>
        </header>

        <section class="section-block">
          <div class="section-body center">
            <div class="button-row center">
              <slot name="actions"
                :loading="loading"
                :can-authenticate="canAuthenticate"
                :is-authenticated="isAuthenticated"
                :authenticate="authenticateUser"
                :logout="logoutUser"
                :mode="mode">
                <!-- Default actions -->
                <button class="btn-secondary" :disabled="loading" @click="$emit('back')">Back</button>
                <button v-if="canAuthenticate" class="btn-primary" :disabled="loading" @click="authenticateUser">
                  {{ loading ? (mode === 'reauth' ? 'Verifying…' : 'Signing in…') : (mode === 'reauth' ? 'Verify' : 'Login') }}
                </button>
                <button v-if="isAuthenticated && mode !== 'reauth'" class="btn-danger" :disabled="loading" @click="logoutUser">Logout</button>
                <button v-if="isAuthenticated && mode !== 'reauth'" class="btn-primary" :disabled="loading" @click="openProfile">Profile</button>
              </slot>
            </div>
          </div>
        </section>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import passkey from '@/utils/passkey'
import { getSettings } from '@/utils/settings'
import { fetchJson, getUserFriendlyErrorMessage } from '@/utils/api'

const props = defineProps({
  mode: {
    type: String,
    default: 'login',
    validator: (value) => ['login', 'reauth', 'forbidden'].includes(value)
  }
})

const emit = defineEmits(['authenticated', 'forbidden', 'logout', 'back', 'home', 'auth-error'])

const status = reactive({ show: false, message: '', type: 'info' })
const initializing = ref(true)
const loading = ref(false)
const settings = ref(null)
const userInfo = ref(null)
const currentView = ref('initial') // 'initial', 'login', 'forbidden'
let statusTimer = null

const isAuthenticated = computed(() => !!userInfo.value?.authenticated)

const canAuthenticate = computed(() => {
  if (initializing.value) return false
  // In reauth mode, allow authentication even if already authenticated
  if (props.mode === 'reauth') return true
  // In forbidden view (authenticated but lacking permissions), don't allow authentication
  if (currentView.value === 'forbidden') return false
  // In login view or initial state, allow authentication
  return true
})

const headingTitle = computed(() => {
  if (props.mode === 'reauth') {
    return `🔐 Additional Authentication`
  }
  if (currentView.value === 'forbidden') return '🚫 Forbidden'
  return `🔐 ${settings.value?.rp_name || location.origin}`
})

const headerMessage = computed(() => {
  if (props.mode === 'reauth') {
    return 'Please verify your identity to continue with this action.'
  }
  if (currentView.value === 'forbidden') {
    return 'You lack the required permissions.'
  }
  return 'Please sign in with your passkey.'
})

const userDisplayName = computed(() => userInfo.value?.user?.user_name || 'User')

function showMessage(message, type = 'info', duration = 3000) {
  status.show = true
  status.message = message
  status.type = type
  if (statusTimer) clearTimeout(statusTimer)
  if (duration > 0) statusTimer = setTimeout(() => { status.show = false }, duration)
}

async function fetchSettings() {
  try {
    const data = await getSettings()
    settings.value = data
    if (data?.rp_name) {
      const titleSuffix = props.mode === 'reauth'
        ? 'Verify Identity'
        : (isAuthenticated.value ? 'Forbidden' : 'Sign In')
      document.title = `${data.rp_name} · ${titleSuffix}`
    }
  } catch (error) {
    console.warn('Unable to load settings', error)
  }
}

async function fetchUserInfo() {
  try {
    userInfo.value = await fetchJson('/auth/api/user-info', { method: 'POST' })
    // Determine view based on authentication status
    if (isAuthenticated.value && props.mode !== 'reauth') {
      currentView.value = 'forbidden'
      emit('forbidden', userInfo.value)
    } else {
      currentView.value = 'login'
    }
  } catch (error) {
    console.error('Failed to load user info', error)
    // For 401/403 just go to login, for other errors show message
    if (error.status !== 401 && error.status !== 403) {
      showMessage(getUserFriendlyErrorMessage(error), 'error', 4000)
    }
    userInfo.value = null
    currentView.value = 'login'
  }
}

async function authenticateUser() {
  if (!canAuthenticate.value || loading.value) return
  loading.value = true
  showMessage('Starting authentication…', 'info')
  let result
  try { result = await passkey.authenticate() } catch (error) {
    loading.value = false
    const message = error?.message || 'Passkey authentication cancelled'
    const cancelled = message === 'Passkey authentication cancelled'
    showMessage(message, cancelled ? 'info' : 'error', 4000)
    emit('auth-error', { message, cancelled })
    return
  }
  try { await setSessionCookie(result) } catch (error) {
    loading.value = false
    const message = error?.message || 'Failed to establish session'
    showMessage(message, 'error', 4000)
    emit('auth-error', { message, cancelled: false })
    return
  }
  loading.value = false
  emit('authenticated', result)
}

async function logoutUser() {
  if (loading.value) return
  loading.value = true
  try {
    await fetchJson('/auth/api/logout', { method: 'POST' })
    userInfo.value = null
    // Switch to login view after logout
    currentView.value = 'login'
    showMessage('Logged out. You can sign in with a different account.', 'info', 3000)
  } catch (error) {
    showMessage(getUserFriendlyErrorMessage(error), 'error', 4000)
  }
  finally { loading.value = false }
  emit('logout')
}

function openProfile() {
  // Open profile in a new window with a specific name to reuse the same tab
  const profileWindow = window.open('/auth/', 'passkey_auth_profile')
  if (profileWindow) profileWindow.focus()
}

async function setSessionCookie(result) {
  if (!result?.session_token) {
    console.error('setSessionCookie called with missing session_token:', result)
    throw new Error('Authentication response missing session_token')
  }
  return await fetchJson('/auth/api/set-session', {
    method: 'POST', headers: { Authorization: `Bearer ${result.session_token}` }
  })
}

onMounted(async () => {
  await fetchSettings()
  await fetchUserInfo()
  initializing.value = false
})

defineExpose({
  showMessage,
  isAuthenticated,
  userInfo
})
</script>

<style scoped>
.button-row.center { display: flex; justify-content: center; gap: 0.75rem; }
.user-line { margin: 0.5rem 0 0; font-weight: 500; color: var(--color-text); }
/* Vertically center the restricted "dialog" surface in the viewport */
main.view-root { min-height: 100vh; align-items: center; justify-content: center; padding: 2rem 1rem; }
.surface.surface--tight {
  max-width: 520px;
  margin: 0 auto;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 1.75rem;
}
</style>
