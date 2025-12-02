<template>
  <RestrictedAuth
    :mode="authMode"
    @authenticated="handleAuthenticated"
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

// Detect mode from data attribute on html tag only
// (RestrictedApi uses URL query, RestrictedForward uses data injected by server)
const authMode = computed(() => {
  const htmlElement = document.documentElement
  const dataMode = htmlElement.getAttribute('data-mode')
  if (dataMode === 'reauth') return 'reauth'
  if (dataMode === 'forbidden') return 'forbidden'
  return 'login'
})

function handleAuthenticated() {
  // Reload page to re-trigger forward auth validation
  location.reload()
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
