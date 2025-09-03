<template>
  <div class="container">
    <div class="view active">
  <h1>👋 Welcome! <a v-if="isAdmin" href="/auth/admin/" class="admin-link" title="Admin Console">Admin</a></h1>
      <UserBasicInfo
        v-if="authStore.userInfo?.user"
        :name="authStore.userInfo.user.user_name"
        :visits="authStore.userInfo.user.visits || 0"
        :created-at="authStore.userInfo.user.created_at"
        :last-seen="authStore.userInfo.user.last_seen"
        :loading="authStore.isLoading"
  update-endpoint="/auth/api/user/display-name"
        @saved="authStore.loadUserInfo()"
      />

      <h2>Your Passkeys</h2>
      <div class="credential-list">
        <div v-if="authStore.isLoading">
          <p>Loading credentials...</p>
        </div>
        <div v-else-if="authStore.userInfo?.credentials?.length === 0">
          <p>No passkeys found.</p>
        </div>
        <div v-else>
          <div
            v-for="credential in authStore.userInfo?.credentials || []"
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
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/helpers'
import passkey from '@/utils/passkey'
import UserBasicInfo from '@/components/UserBasicInfo.vue'

const authStore = useAuthStore()
const updateInterval = ref(null)

onMounted(() => {
  updateInterval.value = setInterval(() => {
    // Trigger Vue reactivity to update formatDate fields
    if (authStore.userInfo) {
      authStore.userInfo = { ...authStore.userInfo }
    }
  }, 60000) // Update every minute
})

onUnmounted(() => {
  if (updateInterval.value) {
    clearInterval(updateInterval.value)
  }
})

const getCredentialAuthName = (credential) => {
  const authInfo = authStore.userInfo?.aaguid_info?.[credential.aaguid]
  return authInfo ? authInfo.name : 'Unknown Authenticator'
}

const getCredentialAuthIcon = (credential) => {
  const authInfo = authStore.userInfo?.aaguid_info?.[credential.aaguid]
  if (!authInfo) return null

  const isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
  const iconKey = isDarkMode ? 'icon_dark' : 'icon_light'
  return authInfo[iconKey] || null
}

const addNewCredential = async () => {
  try {
    authStore.isLoading = true
    authStore.showMessage('Adding new passkey...', 'info')
    await passkey.register()
    await authStore.loadUserInfo()
    authStore.showMessage('New passkey added successfully!', 'success', 3000)
  } catch (error) {
    console.error('Failed to add new passkey:', error)
    authStore.showMessage(error.message, 'error')
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

const isAdmin = computed(() => !!(authStore.userInfo?.is_global_admin || authStore.userInfo?.is_org_admin))
</script>

<style scoped>
/* Removed inline user info styles; now provided by UserBasicInfo component */
.admin-link {
  font-size: 0.6em;
  margin-left: 0.75rem;
  text-decoration: none;
  background: var(--color-background-soft, #eee);
  padding: 0.2em 0.6em;
  border-radius: 999px;
  border: 1px solid var(--color-border, #ccc);
  vertical-align: middle;
  line-height: 1.2;
}
.admin-link:hover {
  background: var(--color-background-mute, #ddd);
}
</style>
