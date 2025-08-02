<template>
  <div class="container">
    <div class="view active">
      <h1>👋 Welcome!</h1>
      <div v-if="authStore.currentUser" class="user-info">
        <h3>👤 {{ authStore.currentUser.user_name }}</h3>
        <span><strong>Visits:</strong></span>
        <span>{{ authStore.currentUser.visits || 0 }}</span>
        <span><strong>Registered:</strong></span>
        <span>{{ formatDate(authStore.currentUser.created_at) }}</span>
        <span><strong>Last seen:</strong></span>
        <span>{{ formatDate(authStore.currentUser.last_seen) }}</span>
      </div>

      <h2>Your Passkeys</h2>
      <div class="credential-list">
        <div v-if="authStore.isLoading">
          <p>Loading credentials...</p>
        </div>
        <div v-else-if="authStore.currentCredentials.length === 0">
          <p>No passkeys found.</p>
        </div>
        <div v-else>
          <div
            v-for="credential in authStore.currentCredentials"
            :key="credential.credential_uuid"
            :class="['credential-item', { 'current-session': credential.is_current_session }]"
          >
            <div class="credential-header">
              <div class="credential-icon">
                <img
                  v-if="getCredentialAuthIcon(credential)"
                  :src="getCredentialAuthIcon(credential)"
                  :alt="getCredentialAuthName(credential)"
                  class="auth-icon"
                  width="32"
                  height="32"
                >
                <span v-else class="auth-emoji">🔑</span>
              </div>
              <div class="credential-info">
                <h4>{{ getCredentialAuthName(credential) }}</h4>
              </div>
              <div class="credential-dates">
                <span class="date-label">Created:</span>
                <span class="date-value">{{ formatDate(credential.created_at) }}</span>
                <span class="date-label">Last used:</span>
                <span class="date-value">{{ formatDate(credential.last_used) }}</span>
              </div>
              <div class="credential-actions">
                <button
                  @click="deleteCredential(credential.credential_uuid)"
                  class="btn-delete-credential"
                  :disabled="credential.is_current_session"
                  :title="credential.is_current_session ? 'Cannot delete current session credential' : ''"
                >
                  🗑️
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="button-group" style="display: flex; gap: 10px;">
        <button @click="addNewCredential" class="btn-primary">
          Add New Passkey
        </button>
        <button @click="authStore.currentView = 'device-link'" class="btn-primary">
          Add Another Device
        </button>
      </div>
      <button @click="logout" class="btn-danger" style="width: 100%;">
        Logout
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/helpers'
import { registerCredential } from '@/utils/passkey'

const authStore = useAuthStore()
const updateInterval = ref(null)

onMounted(async () => {
  try {
    await authStore.loadUserInfo()
  } catch (error) {
    authStore.showMessage(`Failed to load user info: ${error.message}`, 'error')
    authStore.currentView = 'login'
    return
  }

  updateInterval.value = setInterval(() => {
    // Trigger Vue reactivity to update formatDate fields
    authStore.currentUser = { ...authStore.currentUser }
    authStore.currentCredentials = [...authStore.currentCredentials]
  }, 60000) // Update every minute
})

onUnmounted(() => {
  if (updateInterval.value) {
    clearInterval(updateInterval.value)
  }
})

const getCredentialAuthName = (credential) => {
  const authInfo = authStore.aaguidInfo[credential.aaguid]
  return authInfo ? authInfo.name : 'Unknown Authenticator'
}

const getCredentialAuthIcon = (credential) => {
  const authInfo = authStore.aaguidInfo[credential.aaguid]
  if (!authInfo) return null

  const isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
  const iconKey = isDarkMode ? 'icon_dark' : 'icon_light'
  return authInfo[iconKey] || null
}

const addNewCredential = async () => {
  try {
    authStore.isLoading = true
    authStore.showMessage('Adding new passkey...', 'info')
    const result = await registerCredential()
    await authStore.loadUserInfo()
    authStore.showMessage('New passkey added successfully!', 'success', 3000)
  } catch (error) {
    console.error('Failed to add new passkey:', error)
    authStore.showMessage(`Failed to add passkey: ${error.message}`, 'error')
  } finally {
    authStore.isLoading = false
  }
}

const deleteCredential = async (credentialId) => {
  if (!confirm('Are you sure you want to delete this passkey?')) return

  try {
    await authStore.deleteCredential(credentialId)
    authStore.showMessage('Passkey deleted successfully!', 'success', 3000)
  } catch (error) {
    authStore.showMessage(`Failed to delete passkey: ${error.message}`, 'error')
  }
}

const logout = async () => {
  await authStore.logout()
  authStore.currentView = 'login'
}
</script>

<style scoped>
.user-info {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 10px;
}
.user-info h3 {
  grid-column: span 2;
}
.user-info span {
  text-align: left;
}
</style>
