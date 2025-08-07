<template>
  <div class="container">
    <div class="view active">
      <h1>🔑 Add New Credential</h1>
      <h3>👤 {{ authStore.userInfo?.user?.user_name }}</h3>
      <!-- TODO: allow editing name <input type="text" v-model="user_name" required :disabled="authStore.isLoading"> -->
      <p>Proceed to complete {{authStore.userInfo?.session_type}}:</p>
      <button
        class="btn-primary"
        :disabled="authStore.isLoading"
        @click="register"
      >
        {{ authStore.isLoading ? 'Registering...' : 'Register Passkey' }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { useAuthStore } from '@/stores/auth'
import passkey from '@/utils/passkey'

const authStore = useAuthStore()

async function register() {
  authStore.isLoading = true
  authStore.showMessage('Starting registration...', 'info')

  try {
    const result = await passkey.register()
    console.log("Result", result)
    await authStore.setSessionCookie(result.session_token)

    authStore.showMessage('Passkey registered successfully!', 'success', 2000)
    authStore.loadUserInfo().then(authStore.selectView)
  } catch (error) {
    authStore.showMessage(`Registration failed: ${error.message}`, 'error')
  } finally {
    authStore.isLoading = false
  }
}
</script>
