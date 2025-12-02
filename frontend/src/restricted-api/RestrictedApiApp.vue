<template>
  <RestrictedAuth
    :mode="authMode"
    @authenticated="handleAuthenticated"
    @forbidden="handleForbidden"
    @logout="handleLogout"
    @auth-error="handleAuthError"
  >
    <template #actions="{ loading, canAuthenticate, isAuthenticated, authenticate, logout, mode }">
      <button v-if="canAuthenticate" class="btn-primary" :disabled="loading" @click="authenticate">
        {{ loading ? (mode === 'reauth' ? 'Verifying…' : 'Signing in…') : (mode === 'reauth' ? 'Verify' : 'Login') }}
      </button>
      <button v-if="isAuthenticated && mode !== 'reauth'" class="btn-danger" :disabled="loading" @click="logout">Logout</button>
      <button class="btn-secondary" :disabled="loading" @click="handleCancel">Cancel</button>
    </template>
  </RestrictedAuth>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import RestrictedAuth from '@/components/RestrictedAuth.vue'

// Detect mode from URL parameters or postMessage
const authMode = computed(() => {
  const params = new URLSearchParams(window.location.search)
  return params.get('mode') === 'reauth' ? 'reauth' : 'login'
})

// postMessage communication with parent window
function postToParent(message) {
  if (window.parent && window.parent !== window) {
    window.parent.postMessage(message, '*')
  }
}

function handleAuthenticated(result) {
  // Notify parent that authentication was successful
  postToParent({
    type: 'auth-success',
    authenticated: true,
    sessionToken: result.session_token
  })
}

function handleForbidden(userInfo) {
  // Notify parent that user is authenticated but lacks permissions
  postToParent({
    type: 'auth-forbidden',
    authenticated: true,
    userInfo
  })
}

function handleLogout() {
  // Notify parent that logout occurred
  postToParent({
    type: 'auth-logout'
  })
}

function handleAuthError({ message, cancelled }) {
  // Notify parent that authentication failed or was cancelled
  postToParent({
    type: 'auth-error',
    message: message || 'Authentication failed',
    cancelled
  })

  // If it was a cancellation, attempt to close
  if (cancelled) {
    tryClose()
  }
}

function handleCancel() {
  console.log('[RestrictedApiApp] Cancel clicked')
  // Notify parent that the operation was cancelled/incomplete
  postToParent({
    type: 'auth-cancelled',
    message: 'Authentication cancelled'
  })

  // Attempt to close the iframe
  tryClose()
}

function tryClose() {
  console.log('[RestrictedApiApp] tryClose called')
  // Signal to parent that we'd like to be removed
  // Parent can listen for this and remove the iframe element
  postToParent({
    type: 'auth-close-request'
  })

  // Try to close (doesn't work for iframes but harmless to try)
  try {
    window.close()
  } catch (_) { /* ignore */ }
}

onMounted(() => {
  // Notify parent that the iframe is ready
  postToParent({
    type: 'auth-ready'
  })

  // Listen for messages from parent
  window.addEventListener('message', (event) => {
    // In production, you should validate event.origin
    if (event.data?.type === 'auth-check') {
      // Parent is requesting current auth status - could add this functionality
      // by exposing more state from RestrictedAuth component
    }
  })

  // Handle Escape key to cancel
  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      handleCancel()
    }
  })
})
</script>
