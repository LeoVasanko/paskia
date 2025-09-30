<template>
  <div class="dialog-backdrop">
    <div class="dialog-container">
      <div class="dialog-content">
        <header class="view-header">
          <h1>🔑 Add New Credential</h1>
          <p class="view-lede">
            Finish setting up your passkey to complete {{ authStore.userInfo?.session_type }}.
          </p>
        </header>
        <section class="section-block">
          <div class="section-body">
            <label class="name-edit">
              <span>👤 Name</span>
              <input
                type="text"
                v-model="user_name"
                :placeholder="authStore.userInfo?.user?.user_name || 'Your name'"
                :disabled="authStore.isLoading"
                maxlength="64"
                @keyup.enter="register"
              />
            </label>
            <p>Proceed to complete {{ authStore.userInfo?.session_type }}:</p>
            <button
              class="btn-primary"
              :disabled="authStore.isLoading"
              @click="register"
            >
              {{ authStore.isLoading ? 'Registering…' : 'Register Passkey' }}
            </button>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
import { useAuthStore } from '@/stores/auth'
import passkey from '@/utils/passkey'
import { ref } from 'vue'

const authStore = useAuthStore()
const user_name = ref('')

async function register() {
  authStore.isLoading = true
  authStore.showMessage('Starting registration...', 'info')

  try {
    const result = await passkey.register(authStore.resetToken, user_name.value)
    console.log('Result', result)
    await authStore.setSessionCookie(result.session_token)
    authStore.resetToken = null
    authStore.showMessage('Passkey registered successfully!', 'success', 2000)
    await authStore.loadUserInfo()
    authStore.selectView()
  } catch (error) {
    authStore.showMessage(`Registration failed: ${error.message}`, 'error')
  } finally {
    authStore.isLoading = false
  }
}
</script>

<style scoped>
.view-lede {
  margin: 0;
  color: var(--color-text-muted);
}

.name-edit {
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
  font-weight: 600;
}

.name-edit span {
  color: var(--color-text-muted);
  font-size: 0.9rem;
}

.section-body {
  gap: 1.5rem;
}

@media (max-width: 720px) {
  button {
    width: 100%;
  }
}
</style>
