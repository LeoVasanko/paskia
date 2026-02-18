<template>
  <div class="app-shell">
    <div v-if="status.show" class="global-status show">
      <div :class="['status', status.type]">
        {{ status.message }}
      </div>
    </div>

    <main class="view-root">
      <div class="surface surface--tight reset-container">
        <header class="view-header reset-header">
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
            <div class="button-row button-row--center">
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
import { apiJson, ApiError, getUserFriendlyErrorMessage } from 'paskia'

const status = reactive({
  show: false,
  message: '',
  type: 'info'
})

const initializing = ref(true)
const loading = ref(false)
const token = ref('')
const settings = ref(null)
const tokenInfo = ref(null)
const displayName = ref('')
const errorMessage = ref('')
let statusTimer = null

const sessionDescriptor = computed(() => tokenInfo.value?.token_type || 'your enrollment')
const subtitleMessage = computed(() => {
  if (initializing.value) return 'Preparing your secure enrollment…'
  if (!canRegister.value) return 'This authentication link is no longer valid.'
  return `Finish up ${sessionDescriptor.value}. You may edit the name below if needed, and it will be saved to your passkey.`
})

const basePath = computed(() => uiBasePath())

const canRegister = computed(() => !!(token.value && tokenInfo.value))

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

async function fetchTokenInfo() {
  if (!token.value) return
  try {
    tokenInfo.value = await apiJson('/auth/api/token-info', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token.value}` },
    })
    displayName.value = tokenInfo.value.display_name
  } catch (error) {
    console.error('Failed to load token info', error)
    const message = error instanceof ApiError
      ? (error.data?.detail || 'The authentication link is invalid or expired.')
      : getUserFriendlyErrorMessage(error)
    errorMessage.value = message
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
    await exchangeCode(result)
  } catch (error) {
    loading.value = false
    const message = error?.message || 'Failed to establish session'
    showMessage(message, 'error', 4000)
    return
  }

  showMessage('Passkey registered successfully!', 'success', 800)
  setTimeout(() => { loading.value = false; goHome() }, 800)
}

async function exchangeCode(result) {
  if (!result?.exchange_code) {
    throw new Error('Registration response missing exchange_code')
  }
  return await apiJson('/auth/api/set-session', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${result.exchange_code}` }
  })
}

function goHome() {
  const target = uiBasePath.value || '/auth/'
  if (window.location.pathname !== target) {
    history.replaceState(null, '', target)
  }
  window.location.reload()
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
  await fetchTokenInfo()
  initializing.value = false
})
</script>

<style scoped>
.reset-container {
  max-width: 560px;
  margin: 0 auto;
  width: 100%;
}

.reset-header {
  text-align: center;
}

.section-body {
  gap: 1.25rem;
}

.name-edit span {
  color: var(--color-text-muted);
  font-size: 0.9rem;
}
</style>
