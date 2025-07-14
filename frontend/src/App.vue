<template>
  <div>
    <StatusMessage />
    <LoginView v-if="store.currentView === 'login'" />
    <RegisterView v-if="store.currentView === 'register'" />
    <ProfileView v-if="store.currentView === 'profile'" />
    <DeviceLinkView v-if="store.currentView === 'device-link'" />
    <AddDeviceCredentialView v-if="store.currentView === 'add-device-credential'" />
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import StatusMessage from '@/components/StatusMessage.vue'
import LoginView from '@/components/LoginView.vue'
import RegisterView from '@/components/RegisterView.vue'
import ProfileView from '@/components/ProfileView.vue'
import DeviceLinkView from '@/components/DeviceLinkView.vue'
import AddDeviceCredentialView from '@/components/AddDeviceCredentialView.vue'
import { getCookie } from './utils/helpers'

const store = useAuthStore()
let isLoggedIn

onMounted(async () => {
  if (getCookie('auth-token')) {
    store.currentView = 'add-device-credential'
    return
  }
  isLoggedIn = await store.validateStoredToken()
  if (isLoggedIn) {
    // User is logged in, load their data and go to profile
    try {
      await store.loadUserInfo()
      store.currentView = 'profile'
    } catch (error) {
      console.error('Failed to load user info:', error)
      store.currentView = 'login'
    }
  } else {
    // User is not logged in, show login
    store.currentView = 'login'
  }
})
</script>
