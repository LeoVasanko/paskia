<template>
  <RestrictedAuth
    :mode="authMode"
    @authenticated="handleAuthenticated"
    @logout="handleLogout"
    @back="backNav"
    @home="returnHome"
  />
</template>

<script setup>
import { computed, onMounted } from 'vue'
import RestrictedAuth from '@/components/RestrictedAuth.vue'
import { uiBasePath } from '@/utils/settings'

const basePath = computed(() => uiBasePath())

// Detect mode from URL parameters
const authMode = computed(() => {
  const params = new URLSearchParams(window.location.search)
  return params.get('mode') === 'reauth' ? 'reauth' : 'login'
})

function handleAuthenticated() {
  location.reload()
}

function handleLogout() {
  window.location.reload()
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

onMounted(() => {
  // Handle Escape key to trigger back navigation
  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      backNav()
    }
  })
})
</script>
