<template>
  <RestrictedAuth
    :mode="authMode"
    @authenticated="handleAuthenticated"
    @back="handleBack"
  />
</template>

<script setup>
import { computed, onMounted } from 'vue'
import RestrictedAuth from '@/components/RestrictedAuth.vue'

// Detect mode from URL hash fragment
const authMode = computed(() => {
  const params = new URLSearchParams(window.location.hash.slice(1))
  const mode = params.get('mode')
  if (mode === 'reauth') return 'reauth'
  if (mode === 'forbidden') return 'forbidden'
  return 'login'
})

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
