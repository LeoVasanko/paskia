<template>
  <div class="dialog-backdrop">
    <div class="dialog-container">
      <div class="dialog-content dialog-content--wide">
        <header class="view-header">
          <h1>🚫 Forbidden</h1>
        </header>
        <section class="section-block">
          <div class="section-body">
            <div v-if="authStore.userInfo?.authenticated" class="user-header">
              <span class="user-emoji" aria-hidden="true">{{ userEmoji }}</span>
              <span class="user-name">{{ displayName }}</span>
            </div>
            <p>You lack the permissions required for this page.</p>
            <div class="button-row">
              <button class="btn-secondary" @click="back">Back</button>
              <button class="btn-primary" @click="goAuth">Account</button>
              <button class="btn-danger" @click="logout">Logout</button>
            </div>
            <p class="hint">If you believe this is an error, contact your administrator.</p>
          </div>
        </section>
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
.view-lede {
  margin: 0;
  color: var(--color-text-muted);
}

.user-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1.1rem;
}

.user-emoji {
  font-size: 1.5rem;
  line-height: 1;
}

.user-name {
  font-weight: 600;
  color: var(--color-heading);
}

.button-row {
  width: 100%;
  justify-content: stretch;
}

.button-row button {
  flex: 1 1 0;
}

.hint {
  font-size: 0.9rem;
  color: var(--color-text-muted);
  margin: 0;
}

@media (max-width: 720px) {
  .button-row {
    flex-direction: column;
  }

  .button-row button {
    width: 100%;
    flex: 1 1 auto;
  }
}
</style>
