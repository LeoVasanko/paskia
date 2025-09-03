<template>
  <div class="container">
    <div class="view active">
      <h1>🚫 Forbidden</h1>
      <div v-if="authStore.userInfo?.authenticated" class="user-header">
        <span class="user-emoji" aria-hidden="true">{{ userEmoji }}</span>
        <span class="user-name">{{ displayName }}</span>
      </div>
      <p>You lack the permissions required for this page.</p>
      <div class="actions">
        <button class="btn-secondary" @click="back">Back</button>
        <button class="btn-primary" @click="goAuth">Account</button>
        <button class="btn-danger" @click="logout">Logout</button>
      </div>
    </div>
  </div>
</template>
<script setup>
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()

const userEmoji = '👤' // Placeholder / could be extended later if backend provides one
const displayName = authStore.userInfo?.user?.user_name || 'User'

function goAuth() {
  location.href = '/auth/'
}
function back() {
  if (history.length > 1) history.back()
  else authStore.currentView = 'login'
}
async function logout() {
  await authStore.logout()
}
</script>
<style scoped>
.user-header { display:flex; align-items:center; gap:.5rem; font-size:1.1rem; margin-bottom:.75rem; }
.user-emoji { font-size:1.5rem; line-height:1; }
.user-name { font-weight:600; }
.actions { margin-top:1.5rem; display:flex; gap:.5rem; flex-wrap:nowrap; }
.hint { font-size:.9rem; opacity:.85; }
</style>
