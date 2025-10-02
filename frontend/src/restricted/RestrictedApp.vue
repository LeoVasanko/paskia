<template>
  <div class="app-shell">
    <div v-if="status.show" class="global-status" style="display: block;">
      <div :class="['status', status.type]">
        {{ status.message }}
      </div>
    </div>

    <main class="view-root">
      <div class="view-content">
        <div class="surface surface--tight" style="max-width: 520px; margin: 0 auto; width: 100%;">
          <header class="view-header" style="text-align: center;">
            <h1>🚫 Access Restricted</h1>
            <p class="view-lede">{{ headerMessage }}</p>
          </header>

          <section class="section-block" v-if="initializing">
            <div class="section-body center">
              <p>Checking your session…</p>
            </div>
          </section>

          <section class="section-block" v-else>
            <div class="section-body center" style="gap: 1.75rem;">
              <p>{{ detailText }}</p>

              <div class="button-row center" style="justify-content: center;">
                <button v-if="canAuthenticate" class="btn-primary" :disabled="loading" @click="authenticateUser">
                  {{ loading ? 'Signing in…' : 'Sign in with Passkey' }}
                </button>
                <button class="btn-secondary" :disabled="loading" @click="returnHome">
                  Go back to Auth Home
                </button>
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

const status = reactive({
  show: false,
  message: '',
  type: 'info'
})

const initializing = ref(true)
const loading = ref(false)
const settings = ref(null)
const userInfo = ref(null)
const fallbackDetail = ref('')
let statusTimer = null

const isAuthenticated = computed(() => !!userInfo.value?.authenticated)
const canAuthenticate = computed(() => !initializing.value && !isAuthenticated.value)
const uiBasePath = computed(() => {
  const base = settings.value?.ui_base_path || '/auth/'
  if (base === '/') return '/'
  return base.endsWith('/') ? base : `${base}/`
})

const headerMessage = computed(() => {
  if (initializing.value) return 'Checking your access permissions…'
  if (isAuthenticated.value) {
    return 'Your account is signed in, but this resource needs extra permissions.'
  }
  return 'Sign in to continue to the requested resource.'
})

const detailText = computed(() => {
  if (isAuthenticated.value) {
    return fallbackDetail.value || 'You do not have the required permissions to view this page.'
  }
  return fallbackDetail.value || 'Use your registered passkey to sign in securely.'
})

function showMessage(message, type = 'info', duration = 3000) {
  status.show = true
  status.message = message
  status.type = type
  if (statusTimer) clearTimeout(statusTimer)
  if (duration > 0) {
    statusTimer = setTimeout(() => {
      status.show = false
    }, duration)
  }
}

async function fetchSettings() {
  try {
    const res = await fetch('/auth/api/settings')
    if (!res.ok) return
    const data = await res.json()
    settings.value = data
    if (data?.rp_name) {
      document.title = `${data.rp_name} · Access Restricted`
    }
  } catch (error) {
    console.warn('Unable to load settings', error)
  }
}

async function fetchUserInfo() {
  try {
    const res = await fetch('/auth/api/user-info', { method: 'POST' })
    if (!res.ok) {
      const payload = await safeParseJson(res)
      fallbackDetail.value = payload?.detail || 'Please sign in to continue.'
      return
    }
    userInfo.value = await res.json()
  } catch (error) {
    console.error('Failed to load user info', error)
    fallbackDetail.value = 'We were unable to verify your session. Try again shortly.'
  }
}

async function authenticateUser() {
  if (!canAuthenticate.value || loading.value) return
  loading.value = true
  showMessage('Starting authentication…', 'info')

  let result
  try {
    result = await passkey.authenticate()
  } catch (error) {
    loading.value = false
    const message = error?.message || 'Passkey authentication cancelled'
    const cancelled = message === 'Passkey authentication cancelled'
    showMessage(cancelled ? message : `Authentication failed: ${message}`, cancelled ? 'info' : 'error', 4000)
    return
  }

  try {
    await setSessionCookie(result.session_token)
  } catch (error) {
    loading.value = false
    const message = error?.message || 'Failed to establish session'
    showMessage(message, 'error', 4000)
    return
  }

  showMessage('Signed in successfully!', 'success', 2000)
  setTimeout(() => {
    loading.value = false
    window.location.reload()
  }, 800)
}

async function setSessionCookie(sessionToken) {
  const response = await fetch('/auth/api/set-session', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${sessionToken}`
    }
  })
  const payload = await safeParseJson(response)
  if (!response.ok || payload?.detail) {
    const detail = payload?.detail || 'Session could not be established.'
    throw new Error(detail)
  }
  return payload
}

function returnHome() {
  const target = uiBasePath.value || '/auth/'
  if (window.location.pathname !== target) {
    history.replaceState(null, '', target)
  }
  window.location.href = target
}

async function safeParseJson(response) {
  try {
    return await response.json()
  } catch (error) {
    return null
  }
}

onMounted(async () => {
  await fetchSettings()
  await fetchUserInfo()
  if (!canAuthenticate.value && !isAuthenticated.value && !fallbackDetail.value) {
    fallbackDetail.value = 'Please try signing in again.'
  }
  initializing.value = false
})
</script>

<style scoped>
.center {
  text-align: center;
}

.button-row.center {
  display: flex;
  justify-content: center;
  gap: 0.75rem;
}
</style>
