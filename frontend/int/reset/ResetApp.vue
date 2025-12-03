<template>
  <div class="app-shell">
    <div v-if="status.show" class="global-status" style="display: block;">
      <div :class="['status', status.type]">
        {{ status.message }}
      </div>
    </div>

    <main class="view-root">
      <div class="surface surface--tight" style="max-width: 560px; margin: 0 auto; width: 100%;">
        <header class="view-header" style="text-align: center;">
          <h1>🔑 Registration</h1>
          <p class="view-lede">
            {{ subtitleMessage }}
          </p>
        </header>

        <section class="section-block" v-if="initializing">
          <div class="section-body center">
            <p>Loading reset details…</p>
          </div>
        </section>

        <section class="section-block" v-else-if="!canRegister">
          <div class="section-body center">
            <p>{{ errorMessage }}</p>
            <div class="button-row center" style="justify-content: center;">
              <button class="btn-secondary" @click="goHome">Return to sign-in</button>
            </div>
          </div>
        </section>

        <section class="section-block" v-else>
          <div class="section-body">
            <label class="name-edit">
              <span>👤 Name</span>
              <input
                type="text"
                v-model="displayName"
                :disabled="loading"
                maxlength="64"
                @keyup.enter="registerPasskey"
              />
            </label>
            <button
              class="btn-primary"
              :disabled="loading"
              @click="registerPasskey"
            >
              {{ loading ? 'Registering…' : 'Register Passkey' }}
            </button>
          </div>
        </section>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import passkey from '@/utils/passkey'
import { getSettings, uiBasePath } from '@/utils/settings'
import { apiJson, ApiError, getUserFriendlyErrorMessage } from '@/utils/api'

const status = reactive({
  show: false,
  message: '',
  type: 'info'
})

const initializing = ref(true)
const loading = ref(false)
const token = ref('')
const settings = ref(null)
const userInfo = ref(null)
const displayName = ref('')
const errorMessage = ref('')
let statusTimer = null

const sessionDescriptor = computed(() => userInfo.value?.session_type || 'your enrollment')
const subtitleMessage = computed(() => {
  if (initializing.value) return 'Preparing your secure enrollment…'
  if (!canRegister.value) return 'This reset link is no longer valid.'
  return `Finish up ${sessionDescriptor.value}. You may edit the name below if needed, and it will be saved to your passkey.`
})

const basePath = computed(() => uiBasePath())

const canRegister = computed(() => !!(token.value && userInfo.value))

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
    const data = await getSettings()
    settings.value = data
    if (data?.rp_name) document.title = `${data.rp_name} · Passkey Setup`
  } catch (error) {
    console.warn('Unable to load settings', error)
  }
}

async function fetchUserInfo() {
  if (!token.value) return
  try {
    userInfo.value = await apiJson(`/auth/api/user-info?reset=${encodeURIComponent(token.value)}`, {
      method: 'POST'
    })
    displayName.value = userInfo.value?.user?.user_name || ''
  } catch (error) {
    console.error('Failed to load user info', error)
    const message = error instanceof ApiError
      ? (error.data?.detail || 'Reset link is invalid or expired.')
      : getUserFriendlyErrorMessage(error)
    errorMessage.value = message
    showMessage(message, 'error', 0)
  }
}

async function registerPasskey() {
  if (!canRegister.value || loading.value) return
  loading.value = true
  showMessage('Starting passkey registration…', 'info')

  let result
  try {
    const nameValue = displayName.value.trim() || null
    result = await passkey.register(token.value, nameValue)
  } catch (error) {
    loading.value = false
    const message = error?.message || 'Passkey registration cancelled'
    const cancelled = message === 'Passkey registration cancelled'
    showMessage(cancelled ? message : `Registration failed: ${message}`, cancelled ? 'info' : 'error', 4000)
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

  showMessage('Passkey registered successfully!', 'success', 2000)
  setTimeout(() => {
    loading.value = false
    redirectHome()
  }, 800)
}

async function setSessionCookie(sessionToken) {
  return await apiJson('/auth/api/set-session', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${sessionToken}`
    }
  })
}
}

function redirectHome() {
  const target = uiBasePath.value || '/auth/'
  if (window.location.pathname !== target) {
    history.replaceState(null, '', target)
  }
  window.location.reload()
}

function goHome() {
  redirectHome()
}

function extractTokenFromPath() {
  const segments = window.location.pathname.split('/').filter(Boolean)
  if (!segments.length) return ''
  const candidate = segments[segments.length - 1]
  const prefix = segments.slice(0, -1)
  if (prefix.length > 1) return ''
  if (prefix.length === 1 && prefix[0] !== 'auth') return ''
  if (!candidate.includes('.')) return ''
  return candidate
}

onMounted(async () => {
  token.value = extractTokenFromPath()
  await fetchSettings()
  if (!token.value) {
    const message = 'Reset link is missing or malformed.'
    errorMessage.value = message
    showMessage(message, 'error', 0)
    initializing.value = false
    return
  }
  await fetchUserInfo()
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
}

.section-body {
  gap: 1.25rem;
}

.name-edit span {
  color: var(--color-text-muted);
  font-size: 0.9rem;
}
</style>
