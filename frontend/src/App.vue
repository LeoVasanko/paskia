<template>
  <div>
    <StatusMessage />
    <LoginView v-if="store.currentView === 'login'" />
    <ProfileView v-if="store.currentView === 'profile'" />
    <DeviceLinkView v-if="store.currentView === 'device-link'" />
    <ResetView v-if="store.currentView === 'reset'" />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import StatusMessage from '@/components/StatusMessage.vue'
import LoginView from '@/components/LoginView.vue'
import ProfileView from '@/components/ProfileView.vue'
import DeviceLinkView from '@/components/DeviceLinkView.vue'
import ResetView from '@/components/ResetView.vue'

const store = useAuthStore()

onMounted(async () => {
  // Was an error message passed in the URL?
  const message = location.hash.substring(1)
  if (message) {
    store.showMessage(decodeURIComponent(message), 'error')
    history.replaceState(null, '', location.pathname)
  }
  try {
    await store.loadUserInfo()
  } catch (error) {
    console.log('Failed to load user info:', error)
    store.currentView = 'login'
  }
  store.selectView()
})
</script>
