<template>
  <RestrictedAuth
    :mode="authMode"
    @authenticated="handleAuthenticated"
    @logout="handleLogout"
    @back="goBack"
    @home="returnHome"
  />
</template>

<script setup>
import { computed, onMounted } from 'vue'
import RestrictedAuth from '@/components/RestrictedAuth.vue'
import { uiBasePath } from '@/utils/settings'
import { goBack } from '@/utils/helpers'

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

onMounted(() => {
  // Handle Escape key to trigger back navigation
  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') goBack()
  })
})
</script>
