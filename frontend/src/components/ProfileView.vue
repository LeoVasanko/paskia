<template>
  <div class="container">
    <div class="view active">
  <h1>👋 Welcome! <a v-if="isAdmin" href="/auth/admin/" class="admin-link" title="Admin Console">Admin</a></h1>
      <div v-if="authStore.userInfo?.user" class="user-info">
        <h3 class="user-name-heading">
          <span class="icon">👤</span>
          <span v-if="!editingName" class="user-name-row">
            <span class="display-name" :title="authStore.userInfo.user.user_name">{{ authStore.userInfo.user.user_name }}</span>
            <button class="mini-btn" @click="startEdit" title="Edit name">✏️</button>
          </span>
          <span v-else class="user-name-row editing">
            <input
              v-model="newName"
              class="name-input"
              :placeholder="authStore.userInfo.user.user_name"
              :disabled="authStore.isLoading"
              maxlength="64"
              @keyup.enter="saveName"
            />
            <button class="mini-btn" @click="saveName" :disabled="authStore.isLoading" title="Save name">💾</button>
            <button class="mini-btn" @click="cancelEdit" :disabled="authStore.isLoading" title="Cancel">✖</button>
          </span>
        </h3>
        <span><strong>Visits:</strong></span>
        <span>{{ authStore.userInfo.user.visits || 0 }}</span>
        <span><strong>Registered:</strong></span>
        <span>{{ formatDate(authStore.userInfo.user.created_at) }}</span>
        <span><strong>Last seen:</strong></span>
        <span>{{ formatDate(authStore.userInfo.user.last_seen) }}</span>
      </div>

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

// Name editing state & actions
const editingName = ref(false)
const newName = ref('')
function startEdit() { editingName.value = true; newName.value = '' }
function cancelEdit() { editingName.value = false }
async function saveName() {
  try {
    authStore.isLoading = true
  const res = await fetch('/auth/user/display-name', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: newName.value }) })
    const data = await res.json(); if (!res.ok || data.detail) throw new Error(data.detail || 'Update failed')
    await authStore.loadUserInfo()
    editingName.value = false
    authStore.showMessage('Name updated', 'success', 1500)
  } catch (e) { authStore.showMessage(e.message || 'Failed to update name', 'error') }
  finally { authStore.isLoading = false }
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
.user-name-heading {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-wrap: wrap;
  margin: 0 0 0.25rem 0;
}
.user-name-row {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  max-width: 100%;
}
.user-name-row.editing { flex: 1 1 auto; }
.icon { flex: 0 0 auto; }
.display-name {
  font-weight: 600;
  font-size: 1.05em;
  line-height: 1.2;
  max-width: 14ch;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.name-input {
  width: auto;
  flex: 1 1 140px;
  min-width: 120px;
  padding: 6px 8px;
  font-size: 0.9em;
  border: 1px solid #a9c5d6;
  border-radius: 6px;
}
.user-name-heading .name-input { width: auto; }
.name-input:focus { outline: 2px solid #667eea55; border-color: #667eea; }
.mini-btn {
  width: auto;
  padding: 4px 6px;
  margin: 0;
  font-size: 0.75em;
  line-height: 1;
  background: #eef5fa;
  border: 1px solid #b7d2e3;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.2s, transform 0.15s;
}
.mini-btn:hover:not(:disabled) { background: #dcecf6; }
.mini-btn:active:not(:disabled) { transform: translateY(1px); }
.mini-btn:disabled { opacity: 0.5; cursor: not-allowed; }
@media (max-width: 480px) {
  .user-name-heading { flex-direction: column; align-items: flex-start; }
  .user-name-row.editing { width: 100%; }
  .display-name { max-width: 100%; }
}
</style>

<style scoped>
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
