<template>
  <RestrictedAuth
    :mode="authMode"
    :remote-auth-token="remoteAuthToken"
    @authenticated="handleAuthenticated"
    @back="handleBack"
  />
</template>

<script setup>
import { onMounted, ref } from 'vue'
import RestrictedAuth from '@/components/RestrictedAuth.vue'

// Check if this is a remote auth URL: /auth/{token}
// The token is a 5-word passphrase like "word1.word2.word3.word4.word5"
const remoteAuthToken = ref(null)

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
const authMode = ['reauth', 'forbidden'].includes(hashParams.get('mode')) ? hashParams.get('mode') : 'login'

function postToParent(message) {
  if (window.parent && window.parent !== window) {
    window.parent.postMessage(message, '*')
  }
}

function handleAuthenticated(result) {
  postToParent({
    type: 'auth-success',
    authenticated: true,
    sessionToken: result.session_token
  })
}

function handleBack() {
  postToParent({
    type: 'auth-back'
  })
}

onMounted(() => {
  // Check for remote auth token in URL
  remoteAuthToken.value = extractRemoteToken()

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
