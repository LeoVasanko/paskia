<template>
  <div class="app-shell">
    <StatusMessage />
    <main class="app-main">
      <ProfileView v-if="initialized" />
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
import ProfileView from '@/components/ProfileView.vue'
const store = useAuthStore()
const initialized = ref(false)

onMounted(async () => {
  await store.loadSettings()
  if (store.settings?.rp_name) document.title = store.settings.rp_name
  try { await store.loadUserInfo() } catch (_) { /* user info load errors ignored */ }
  initialized.value = true
})
</script>

<style scoped>
.loading-container { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; gap: 1rem; }
.loading-spinner { width: 40px; height: 40px; border: 4px solid var(--color-border); border-top: 4px solid var(--color-primary); border-radius: 50%; animation: spin 1s linear infinite; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
.loading-container p { color: var(--color-text-muted); margin: 0; }
</style>
