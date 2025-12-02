<template>
  <RestrictedAuth
    :mode="authMode"
    @authenticated="handleAuthenticated"
    @forbidden="handleForbidden"
    @logout="handleLogout"
    @back="handleBack"
  />
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

function handleBack() {
  console.log('[RestrictedApiApp] Back clicked')
  // Notify parent that user wants to go back
  postToParent({
    type: 'auth-back'
  })
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

  // Handle Escape key to trigger back navigation
  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      handleBack()
    }
  })
})
</script>
