<template>
  <div class="app-shell">
    <div v-if="status.show" class="global-status" style="display: block;">
      <div :class="['status', status.type]">
        {{ status.message }}
      </div>
    </div>

    <main class="view-root">
      <div class="view-content">
        <div v-if="!initializing" class="surface surface--tight">
          <header class="view-header center">
            <h1>{{ headingTitle }}</h1>
            <p v-if="isAuthenticated" class="user-line">👤 {{ userDisplayName }}</p>
            <p class="view-lede">{{ headerMessage }}</p>
          </header>

          <section class="section-block">
            <div class="section-body center">
              <div class="button-row center">
                <button class="btn-secondary" :disabled="loading" @click="backNav">Back</button>
                <button v-if="canAuthenticate" class="btn-primary" :disabled="loading" @click="authenticateUser">
                  {{ loading ? 'Signing in…' : 'Login' }}
                </button>
                <button v-if="isAuthenticated" class="btn-danger" :disabled="loading" @click="logoutUser">Logout</button>
                <button v-if="isAuthenticated" class="btn-primary" :disabled="loading" @click="returnHome">Profile</button>
              </div>
            </div>
          </section>
        </div>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import passkey from '@/utils/passkey'
import { getSettings, uiBasePath } from '@/utils/settings'

const status = reactive({ show: false, message: '', type: 'info' })
const initializing = ref(true)
const loading = ref(false)
const settings = ref(null)
const userInfo = ref(null)
let statusTimer = null

const isAuthenticated = computed(() => !!userInfo.value?.authenticated)
const canAuthenticate = computed(() => !initializing.value && !isAuthenticated.value)
const basePath = computed(() => uiBasePath())

const headingTitle = computed(() => {
  if (!isAuthenticated.value) return `🔐 ${settings.value?.rp_name || location.origin}`
  return '🚫 Forbidden'
})

const headerMessage = computed(() => {
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
    if (data?.rp_name) document.title = isAuthenticated.value ? `${data.rp_name} · Forbidden` : `${data.rp_name} · Sign In`
  } catch (error) {
    console.warn('Unable to load settings', error)
  }
}

async function fetchUserInfo() {
  try {
    const res = await fetch('/auth/api/user-info', { method: 'POST' })
    console.log("fetchUserInfo response:", res); // Debug log
    if (!res.ok) {
      const payload = await safeParseJson(res)
      showMessage(payload.detail || 'Unable to load user session info.', 'error', 2000)
      return
    }
    userInfo.value = await res.json()
    // If the user is authenticated but still here, they lack permissions.
    if (isAuthenticated.value) showMessage('Permission Denied', 'error', 2000)
  } catch (error) {
    console.error('Failed to load user info', error)
    showMessage('Could not contact the authentication server', 'error', 2000)
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
    return
  }
  try { await setSessionCookie(result.session_token) } catch (error) {
    loading.value = false
    const message = error?.message || 'Failed to establish session'
    showMessage(message, 'error', 4000)
    return
  }
  location.reload()
}

async function logoutUser() {
  if (loading.value) return
  loading.value = true
  try { await fetch('/auth/api/logout', { method: 'POST' }) } catch (_) { /* ignore */ }
  finally { loading.value = false; window.location.reload() }
}

async function setSessionCookie(sessionToken) {
  const response = await fetch('/auth/api/set-session', {
    method: 'POST', headers: { Authorization: `Bearer ${sessionToken}` }
  })
  const payload = await safeParseJson(response)
  if (!response.ok || payload?.detail) throw new Error(payload?.detail || 'Session could not be established.')
  return payload
}

function returnHome() {
  const target = basePath.value || '/auth/'
  if (window.location.pathname !== target) history.replaceState(null, '', target)
  window.location.href = target
}

function backNav() {
  try {
    if (history.length > 1) {
      history.back()
      return
    }
  } catch (_) { /* ignore */ }
  returnHome()
}

async function safeParseJson(response) { try { return await response.json() } catch (_) { return null } }

onMounted(async () => {
  await fetchSettings()
  await fetchUserInfo()
  initializing.value = false
})
</script>

<style scoped>
.button-row.center { display: flex; justify-content: center; gap: 0.75rem; }
.user-line { margin: 0.5rem 0 0; font-weight: 500; color: var(--color-text); }
/* Vertically center the restricted "dialog" surface in the viewport */
main.view-root { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem 1rem; }
main.view-root .view-content { width: 100%; }
.surface.surface--tight {
  max-width: 520px;
  margin: 0 auto;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 1.75rem;
}
</style>
