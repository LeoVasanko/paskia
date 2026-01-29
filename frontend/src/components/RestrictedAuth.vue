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
          <p class="view-lede" v-html="headerMessage"></p>
        </header>

        <section class="section-block">
          <div class="section-body center">
            <!-- Local passkey authentication view -->
            <div v-if="authView === 'local'" class="auth-view">
              <div class="button-row center" ref="buttonRow">
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

            <!-- Remote authentication view (request new remote auth) -->
            <div v-else-if="authView === 'remote'" class="auth-view">
              <RemoteAuthRequest
                :active="authView === 'remote'"
                @authenticated="handleRemoteAuthenticated"
                @register="handleRemoteRegistration"
                @cancelled="switchToLocal"
                @error="handleRemoteAuthError"
              />
            </div>
          </div>
        </section>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import passkey from '@/utils/passkey'
import { getSettings, uiBasePath } from '@/utils/settings'
import { fetchJson, getUserFriendlyErrorMessage } from 'paskia'
import RemoteAuthRequest from '@/components/RemoteAuthRequest.vue'
import { focusDialogButton } from '@/utils/keynav'

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
const session = ref(null)
const currentView = ref('initial') // 'initial', 'login', 'forbidden'
const authView = ref('local') // 'local' or 'remote'
const buttonRow = ref(null)
let statusTimer = null

const isAuthenticated = computed(() => !!session.value)

const canAuthenticate = computed(() => {
  if (initializing.value) return false
  if (props.mode === 'reauth') return true
  if (currentView.value === 'forbidden') return false
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
  if (authView.value === 'remote') {
    return 'Confirm from your other device. Or <a href="#" class="inline-link" data-action="local">this device</a>.'
  }
  if (canAuthenticate.value && props.mode !== 'reauth') {
    return 'Please sign in with your passkey. Or use <a href="#" class="inline-link" data-action="remote">another device</a>.'
  }
  return 'Please sign in with your passkey.'
})

const userDisplayName = computed(() => session.value?.ctx.user.display_name || 'User')

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

async function validateSession() {
  try {
    session.value = await fetchJson('/auth/api/validate', { method: 'POST' })
    if (isAuthenticated.value && props.mode !== 'reauth') {
      currentView.value = 'forbidden'
      emit('forbidden', session.value)
    } else {
      currentView.value = 'login'
    }
  } catch (error) {
    session.value = null
    currentView.value = 'login'
    if (error.status !== 401 && error.status !== 403) {
      showMessage(getUserFriendlyErrorMessage(error), 'error', 4000)
    }
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
    session.value = null
    currentView.value = 'login'
    showMessage('Logged out. You can sign in with a different account.', 'info', 3000)
  } catch (error) {
    showMessage(getUserFriendlyErrorMessage(error), 'error', 4000)
  }
  finally { loading.value = false }
  emit('logout')
}

function openProfile() {
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

function switchToRemote() {
  authView.value = 'remote'
}

function switchToLocal() {
  authView.value = 'local'
}

async function handleRemoteAuthenticated(result) {
  showMessage('Authenticated from another device!', 'success', 2000)
  try {
    await setSessionCookie(result)
  } catch (error) {
    const message = error?.message || 'Failed to establish session'
    showMessage(message, 'error', 4000)
    emit('auth-error', { message, cancelled: false })
    return
  }
  emit('authenticated', result)
}

function handleRemoteRegistration(token) {
  showMessage('Registration approved! Redirecting...', 'success', 2000)
  const basePath = uiBasePath() || '/auth/'
  window.location.href = `${basePath}${token}`
}

function handleRemoteAuthError(errorMsg) {
  // Error is already shown in the RemoteAuth component, don't show toast
}

function handleHeaderLinkClick(event) {
  const target = event.target
  if (target.tagName === 'A' && target.classList.contains('inline-link')) {
    event.preventDefault()
    const action = target.dataset.action
    if (action === 'remote') {
      switchToRemote()
    } else if (action === 'local') {
      switchToLocal()
    }
  }
}

// Autofocus primary button when the view becomes ready
watch(initializing, (newVal) => {
  if (!newVal) {
    nextTick(() => focusDialogButton(buttonRow.value))
  }
})

onMounted(async () => {
  await fetchSettings()
  await validateSession()
  initializing.value = false

  // Add click handler for inline links
  document.addEventListener('click', handleHeaderLinkClick)
})

onUnmounted(() => {
  document.removeEventListener('click', handleHeaderLinkClick)
})

defineExpose({
  showMessage,
  isAuthenticated,
  session
})
</script>

<style scoped>
.button-row.center { display: flex; justify-content: center; gap: 0.75rem; flex-wrap: wrap; }
.user-line { margin: 0.5rem 0 0; font-weight: 500; color: var(--color-text); }
main.view-root { min-height: 100vh; align-items: center; justify-content: center; padding: 2rem 1rem; }
.surface.surface--tight {
  max-width: 520px;
  margin: 0 auto;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 1.75rem;
}

.auth-view {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
  width: 100%;
}

.view-lede :deep(.inline-link) {
  color: var(--color-primary);
  text-decoration: none;
  transition: opacity 0.15s;
  font-weight: 400;
}

.view-lede :deep(.inline-link:hover) {
  opacity: 0.8;
  text-decoration: underline;
}
</style>
