<template>
  <div class="app-shell">
    <StatusMessage />
    <main class="app-main">
      <template v-if="initialized">
        <LoginView v-if="store.currentView === 'login'" />
        <ProfileView v-if="store.currentView === 'profile'" />
      </template>
      <div v-else class="loading-container">
        <div class="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    </main>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import StatusMessage from '@/components/StatusMessage.vue'
import LoginView from '@/components/LoginView.vue'
import ProfileView from '@/components/ProfileView.vue'
const store = useAuthStore()
const initialized = ref(false)

onMounted(async () => {
  await store.loadSettings()
  const message = location.hash.substring(1)
  if (message) {
    store.showMessage(decodeURIComponent(message), 'error')
    history.replaceState(null, '', location.pathname)
  }
  try {
    await store.loadUserInfo()
  } catch (error) {
    console.log('Failed to load user info:', error)
  } finally {
    initialized.value = true
    store.selectView()
  }
})
</script>

<style scoped>
.loading-container { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; gap: 1rem; }
.loading-spinner { width: 40px; height: 40px; border: 4px solid var(--color-border); border-top: 4px solid var(--color-primary); border-radius: 50%; animation: spin 1s linear infinite; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
.loading-container p { color: var(--color-text-muted); margin: 0; }
</style>
