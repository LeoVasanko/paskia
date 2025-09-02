<template>
  <div class="container">
    <div class="view active">
      <h1>🔑 Add New Credential</h1>
      <label class="name-edit">
        <span>👤 Name:</span>
        <input
          type="text"
          v-model="user_name"
          :placeholder="authStore.userInfo?.user?.user_name || 'Your name'"
          :disabled="authStore.isLoading"
          maxlength="64"
          @keyup.enter="register"
        />
      </label>
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
import { ref, watchEffect } from 'vue'

const authStore = useAuthStore()
const user_name = ref('')

// Initialize local name from store (once loaded)
watchEffect(() => {
  if (!user_name.value && authStore.userInfo?.user?.user_name) {
    user_name.value = authStore.userInfo.user.user_name
  }
})

async function register() {
  authStore.isLoading = true
  authStore.showMessage('Starting registration...', 'info')

  try {
  const trimmed = (user_name.value || '').trim()
  const nameToSend = trimmed.length ? trimmed : null
  const result = await passkey.register(authStore.resetToken, nameToSend)
  console.log("Result", result)
  await authStore.setSessionCookie(result.session_token)
  // resetToken cleared by setSessionCookie; ensure again
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
