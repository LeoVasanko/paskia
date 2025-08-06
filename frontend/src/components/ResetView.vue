<template>
  <div class="container">
    <div class="view active">
      <h1>🔑 Add New Credential</h1>
      <h3>👤 {{ authStore.userInfo?.user?.user_name }}</h3>
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
import { registerCredential } from '@/utils/passkey'

const authStore = useAuthStore()

async function register() {
  authStore.isLoading = true
  authStore.showMessage('Starting registration...', 'info')

  try {
    // TODO: For reset sessions, might use registerWithToken() in the future
    const result = await registerCredential()
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
