<template>
  <template v-if="authMode === 'profile'">
    <!--
      Profile mode: render nothing until the session check completes (avoids
      a load-time flash of the wrong view). Without a session, the login flow
      runs in place of the profile; on success auth-success is posted and the
      host resolves profile() with 'login'.
    -->
    <RestrictedAuth
      v-if="profileState === 'login'"
      mode="login"
      @authenticated="handleAuthenticated"
      @back="handleBack"
    />
    <HostProfileView
      v-else-if="profileState === 'ready'"
      :ctx="profileCtx"
      :user-info="profileInfo"
      :settings="profileSettings"
      @back="handleBack"
      @logout="handleLogout"
    />
    <div v-else class="view-root profile-pending">
      <div class="surface surface--tight">
        <p class="view-lede">{{ profileState === 'error' ? 'Could not load your account.' : 'Loading your account…' }}</p>
        <div class="button-row">
          <button type="button" class="btn-secondary" @click="handleBack">Back</button>
        </div>
      </div>
    </div>
  </template>
  <RestrictedAuth
    v-else
    :mode="authMode"
    :remote-auth-token="remoteAuthToken"
    :oidc-query-string="oidcQueryString"
    @authenticated="handleAuthenticated"
    @back="handleBack"
  />
</template>

<script setup>
import { onMounted, ref } from 'vue'
import RestrictedAuth from '@/components/RestrictedAuth.vue'
import HostProfileView from '@/components/HostProfileView.vue'
import { fetchJson, settings as paskiaSettings } from 'paskia'
import { getSettings } from '@/utils/settings'
import { updateThemeFromSession } from '@/utils/theme'

// Check if this is a remote auth URL: /auth/{token}
// The token is a 5-word passphrase like "word1.word2.word3.word4.word5"
const remoteAuthToken = ref(null)

// For OIDC flow, pass the raw query string to preserve exact param values
const oidcQueryString = window.location.search.includes('client_id=') ? window.location.search : null

function extractRemoteToken() {
  const path = window.location.pathname
  // Match /auth/{token} where token is a passphrase with dots
  const match = path.match(/\/auth\/([^/]+)$/)
  if (match) {
    const token = match[1]
    // Validate it looks like a 5-word passphrase
    const parts = token.split('.')
    if (parts.length === 5 && parts.every(p => p.length > 0)) {
      return token
    }
  }
  return null
}

// Parse URL hash fragment
const hashParams = new URLSearchParams(window.location.hash.slice(1))

// Determine auth mode based on URL path
// - /auth/restricted/oidc: OIDC flow, no session dependency
// - /auth/restricted/iframe: iframe embedding, mode from hash params
// - Other paths: forward auth, mode from hash params
let authMode
if (window.location.pathname === '/auth/restricted/oidc') {
  authMode = 'oidc'
} else {
  // Both iframe and forward auth use hash params for mode (forbidden/login/reauth/profile)
  authMode = ['reauth', 'forbidden', 'profile'].includes(hashParams.get('mode')) ? hashParams.get('mode') : 'login'
}

// Profile mode state: 'loading' | 'login' | 'ready' | 'error'
const profileState = ref('loading')
const profileCtx = ref(null)
const profileInfo = ref(null)
const profileSettings = ref(null)

async function loadProfile() {
  try {
    const [validateData, infoData, settingsData] = await Promise.all([
      fetchJson('/auth/api/validate', { method: 'POST', timeout: paskiaSettings.auth_ms }),
      fetchJson('/auth/api/user-info', { method: 'GET', timeout: paskiaSettings.auth_ms }),
      getSettings()
    ])
    profileCtx.value = validateData.ctx
    profileInfo.value = infoData
    profileSettings.value = settingsData
    updateThemeFromSession(validateData.ctx)
    profileState.value = 'ready'
  } catch (error) {
    // No/expired session: run the login flow in place of the profile
    profileState.value = error.status === 401 || error.status === 403 ? 'login' : 'error'
  }
}

function postToParent(message) {
  if (window.parent && window.parent !== window) {
    window.parent.postMessage(message, '*')
  }
}

function handleAuthenticated(result) {
  if (result.redirect_url) {
    // OIDC flow: redirect to client with auth code
    window.location.href = result.redirect_url
    return
  }
  postToParent({
    type: 'auth-success',
    authenticated: true,
    exchangeCode: result.exchange_code
  })
}

function handleBack() {
  postToParent({
    type: 'auth-back'
  })
}

function handleLogout() {
  postToParent({
    type: 'auth-logout'
  })
}

onMounted(() => {
  // Check for remote auth token in URL
  remoteAuthToken.value = extractRemoteToken()

  if (authMode === 'profile') loadProfile()

  postToParent({
    type: 'auth-ready'
  })

  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      handleBack()
    }
  })
})
</script>

<style scoped>
.view-root.profile-pending { min-height: 100vh; align-items: center; justify-content: center; padding: 2rem 1rem; }
.profile-pending .surface {
  max-width: 520px;
  margin: 0 auto;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 1.75rem;
}
</style>
