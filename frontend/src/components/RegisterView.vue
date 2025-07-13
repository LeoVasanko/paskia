<template>
  <div class="container">
    <div class="view active">
      <h1>🔐 Create Account</h1>
      <form @submit.prevent="handleRegister">
        <input
          type="text"
          v-model="user_name"
          placeholder="Enter username"
          required
          :disabled="authStore.isLoading"
        >
        <button
          type="submit"
          class="btn-primary"
          :disabled="authStore.isLoading || !user_name.trim()"
        >
          {{ authStore.isLoading ? 'Registering...' : 'Register Passkey' }}
        </button>
      </form>
      <p class="toggle-link">
        <a href="#" @click.prevent="authStore.currentView = 'login'">
          Already have an account? Login here
        </a>
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const user_name = ref('')

const handleRegister = async () => {
  if (!user_name.value.trim()) return

  try {
    authStore.showMessage('Starting registration...', 'info')
    await authStore.register(user_name.value.trim())
    authStore.showMessage('Passkey registered successfully!', 'success', 2000)

    setTimeout(() => {
      authStore.currentView = 'profile'
    }, 1500)
  } catch (error) {
    console.error('Registration error:', error)
    if (error.name === "NotAllowedError") {
      authStore.showMessage('Registration cancelled', 'error')
    } else {
      authStore.showMessage(`Registration failed: ${error.message}`, 'error')
    }
  }
}
</script>
