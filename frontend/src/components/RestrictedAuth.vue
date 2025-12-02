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
                <button v-if="isAuthenticated && mode !== 'reauth'" class="btn-primary" :disabled="loading" @click="$emit('home')">Profile</button>
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

const props = defineProps({
  mode: {
    type: String,
    default: 'login',
    validator: (value) => ['login', 'reauth'].includes(value)
  }
})

const emit = defineEmits(['authenticated', 'forbidden', 'logout', 'back', 'home', 'auth-error'])

const status = reactive({ show: false, message: '', type: 'info' })
const initializing = ref(true)
const loading = ref(false)
const settings = ref(null)
const userInfo = ref(null)
let statusTimer = null

const isAuthenticated = computed(() => !!userInfo.value?.authenticated)

const canAuthenticate = computed(() => {
  if (initializing.value) return false
  // In reauth mode, allow authentication even if already authenticated
  if (props.mode === 'reauth') return true
  // In login mode, only allow if not authenticated
  return !isAuthenticated.value
})

const headingTitle = computed(() => {
  if (props.mode === 'reauth') {
    return `🔐 Additional Verification Required`
  }
  if (!isAuthenticated.value) return `🔐 ${settings.value?.rp_name || location.origin}`
  return '🚫 Forbidden'
})

const headerMessage = computed(() => {
  if (props.mode === 'reauth') {
    return 'Please verify your identity to continue with this action.'
  }
  if (!isAuthenticated.value) return 'Please sign in to access this page.'
  return 'You lack the permissions required to access this page.'
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
    const res = await fetch('/auth/api/user-info', { method: 'POST' })
    if (!res.ok) return
    userInfo.value = await res.json()
    // In login mode, if the user is authenticated but still here, they lack permissions.
    // In reauth mode, being authenticated is expected - we just need re-verification.
    if (isAuthenticated.value && props.mode !== 'reauth') emit('forbidden', userInfo.value)
  } catch (error) {
    console.error('Failed to load user info', error)
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
    showMessage(cancelled ? message : `Authentication failed: ${message}`, cancelled ? 'info' : 'error', 4000)
    emit('auth-error', { message, cancelled })
    return
  }
  try { await setSessionCookie(result.session_token) } catch (error) {
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
  try { await fetch('/auth/api/logout', { method: 'POST' }) } catch (_) { /* ignore */ }
  finally { loading.value = false }
  emit('logout')
}

async function setSessionCookie(sessionToken) {
  const response = await fetch('/auth/api/set-session', {
    method: 'POST', headers: { Authorization: `Bearer ${sessionToken}` }
  })
  const payload = await safeParseJson(response)
  if (!response.ok || payload?.detail) throw new Error(payload?.detail || 'Session could not be established.')
  return payload
}

async function safeParseJson(response) { try { return await response.json() } catch (_) { return null } }

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
