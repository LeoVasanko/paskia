<template>
  <div>
    <StatusMessage />
    <LoginView v-if="store.currentView === 'login'" />
    <RegisterView v-if="store.currentView === 'register'" />
    <ProfileView v-if="store.currentView === 'profile'" />
    <DeviceLinkView v-if="store.currentView === 'device-link'" />
    <AddCredentialView v-if="store.currentView === 'add-credential'" />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import StatusMessage from '@/components/StatusMessage.vue'
import LoginView from '@/components/LoginView.vue'
import RegisterView from '@/components/RegisterView.vue'
import ProfileView from '@/components/ProfileView.vue'
import DeviceLinkView from '@/components/DeviceLinkView.vue'
import AddCredentialView from '@/components/AddCredentialView.vue'

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
  if (store.currentCredentials.length) {
    // User is logged in, go to profile
      store.currentView = 'profile'
  } else if (store.currentUser) {
    // User is logged in via reset link, allow adding a credential
    store.currentView = 'add-credential'
  } else {
    // User is not logged in, show login
    store.currentView = 'login'
  }
})
</script>
