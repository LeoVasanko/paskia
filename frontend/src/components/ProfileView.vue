<template>
  <section class="view-root" data-view="profile">
    <header class="view-header">
      <h1>User Profile</h1>
      <Breadcrumbs :entries="breadcrumbEntries" />
      <p class="view-lede">Account dashboard for managing credentials and authenticating with other devices.</p>
    </header>

    <section class="section-block">
      <UserBasicInfo
        v-if="authStore.userInfo?.user"
        :name="authStore.userInfo.user.user_name"
        :visits="authStore.userInfo.user.visits || 0"
        :created-at="authStore.userInfo.user.created_at"
        :last-seen="authStore.userInfo.user.last_seen"
        :loading="authStore.isLoading"
        update-endpoint="/auth/api/user/display-name"
        @saved="authStore.loadUserInfo()"
        @edit-name="openNameDialog"
      >
        <div class="remote-auth-inline">
          <label v-if="!showDeviceInfo" class="remote-auth-label">Code words from remote device:</label>
          <RemoteAuth
            ref="pairingEntry"
            title=""
            description=""
            placeholder="word word word"
            @completed="handlePairingCompleted"
            @error="handlePairingError"
            @device-info-visible="showDeviceInfo = $event"
          />
        </div>
      </UserBasicInfo>
    </section>

    <section class="section-block">
      <div class="section-header">
        <h2>Your Passkeys</h2>
        <p class="section-description">Keep at least one trusted passkey so you can always sign in.</p>
      </div>
      <div class="section-body">
        <CredentialList
          :credentials="authStore.userInfo?.credentials || []"
          :aaguid-info="authStore.userInfo?.aaguid_info || {}"
          :loading="authStore.isLoading"
          :hovered-credential-uuid="hoveredCredentialUuid"
          :hovered-session-credential-uuid="hoveredSession?.credential_uuid"
          allow-delete
          @delete="handleDelete"
          @credential-hover="hoveredCredentialUuid = $event"
        />
        <div class="button-row">
          <button @click="addNewCredential" class="btn-primary">Add New Passkey</button>
          <button @click="showRegLink = true" class="btn-secondary">Add Another Device</button>
        </div>
      </div>
    </section>

    <SessionList
      :sessions="sessions"
      :terminating-sessions="terminatingSessions"
      :hovered-credential-uuid="hoveredCredentialUuid"
      @terminate="terminateSession"
      @session-hover="hoveredSession = $event"
      section-description="Review where you're signed in and end any sessions you no longer recognize."
    />

    <Modal v-if="showNameDialog" @close="showNameDialog = false">
      <h3>Edit Display Name</h3>
      <form @submit.prevent="saveName" class="modal-form">
        <NameEditForm
          label="Display Name"
          v-model="newName"
          :busy="saving"
          @cancel="showNameDialog = false"
        />
      </form>
    </Modal>

    <section class="section-block">
      <div class="button-row">
        <button
          type="button"
          class="btn-secondary"
          @click="goBack"
        >
          Back
        </button>
        <button v-if="!hasMultipleSessions" @click="logoutEverywhere" class="btn-danger" :disabled="authStore.isLoading">Logout</button>
        <template v-else>
          <button @click="logout" class="btn-danger" :disabled="authStore.isLoading">Logout</button>
          <button @click="logoutEverywhere" class="btn-danger" :disabled="authStore.isLoading">All</button>
        </template>
      </div>
      <p class="logout-note" v-if="!hasMultipleSessions"><strong>Logout</strong> from {{ currentSessionHost }}.</p>
      <p class="logout-note" v-else><strong>Logout</strong> this session on {{ currentSessionHost }}, or <strong>All</strong> sessions across all sites and devices for {{ rpName }}. You'll need to log in again with your passkey afterwards.</p>
    </section>
    <RegistrationLinkModal
      v-if="showRegLink"
      endpoint="/auth/api/user/create-link"
      @close="showRegLink = false"
    />
  </section>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import Breadcrumbs from '@/components/Breadcrumbs.vue'
import CredentialList from '@/components/CredentialList.vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import Modal from '@/components/Modal.vue'
import NameEditForm from '@/components/NameEditForm.vue'
import SessionList from '@/components/SessionList.vue'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'
import RemoteAuth from '@/components/RemoteAuthPermit.vue'
import { useAuthStore } from '@/stores/auth'
import { adminUiPath, makeUiHref } from '@/utils/settings'
import passkey from '@/utils/passkey'
import { goBack } from '@/utils/helpers'
import { apiJson } from '@/utils/api'

const authStore = useAuthStore()
const updateInterval = ref(null)
const showNameDialog = ref(false)
const showRegLink = ref(false)
const newName = ref('')
const saving = ref(false)
const hoveredCredentialUuid = ref(null)
const hoveredSession = ref(null)
const showDeviceInfo = ref(false)
const pairingEntry = ref(null)

watch(showNameDialog, (newVal) => { if (newVal) newName.value = authStore.userInfo?.user?.user_name || '' })

onMounted(() => {
  updateInterval.value = setInterval(() => { if (authStore.userInfo) authStore.userInfo = { ...authStore.userInfo } }, 60000)
})

onUnmounted(() => { if (updateInterval.value) clearInterval(updateInterval.value) })

const addNewCredential = async () => {
  try {
    await passkey.register(null, null, () => {
      authStore.showMessage('Adding new passkey...', 'info')
    })
    await authStore.loadUserInfo()
    authStore.showMessage('New passkey added successfully!', 'success', 3000)
  } catch (error) {
    console.error('Failed to add new passkey:', error)
    authStore.showMessage(error.message, 'error')
  }
}

const handlePairingCompleted = () => {
  authStore.showMessage('The other device is now signed in!', 'success', 4000)
  // Reset the form after a delay
  setTimeout(() => pairingEntry.value?.reset(), 3000)
}

const handlePairingError = (message) => {
  // Error is already shown in the component, optionally show global message for severe errors
  if (!message.includes('cancelled')) {
    authStore.showMessage(message, 'error', 4000)
  }
}

const handleDelete = async (credential) => {
  const credentialId = credential?.credential_uuid
  if (!credentialId) return
  if (!confirm('Are you sure you want to delete this passkey?')) return
  try {
    await authStore.deleteCredential(credentialId)
    authStore.showMessage('Passkey deleted successfully!', 'success', 3000)
  } catch (error) { authStore.showMessage(`Failed to delete passkey: ${error.message}`, 'error') }
}

const rpName = computed(() => authStore.settings?.rp_name || 'this service')
const sessions = computed(() => authStore.userInfo?.sessions || [])
const currentSessionHost = computed(() => {
  const currentSession = sessions.value.find(session => session.is_current)
  return currentSession?.host || 'this host'
})
const terminatingSessions = ref({})

const terminateSession = async (session) => {
  const sessionId = session?.id
  if (!sessionId) return
  terminatingSessions.value = { ...terminatingSessions.value, [sessionId]: true }
  try { await authStore.terminateSession(sessionId) }
  catch (error) { authStore.showMessage(error.message || 'Failed to terminate session', 'error', 5000) }
  finally {
    const next = { ...terminatingSessions.value }
    delete next[sessionId]
    terminatingSessions.value = next
  }
}

const logoutEverywhere = async () => { await authStore.logoutEverywhere() }
const logout = async () => { await authStore.logout() }
const openNameDialog = () => { newName.value = authStore.userInfo?.user?.user_name || ''; showNameDialog.value = true }
const isAdmin = computed(() => !!(authStore.userInfo?.is_global_admin || authStore.userInfo?.is_org_admin))
const hasMultipleSessions = computed(() => sessions.value.length > 1)
const breadcrumbEntries = computed(() => { const entries = [{ label: 'Auth', href: makeUiHref() }]; if (isAdmin.value) entries.push({ label: 'Admin', href: adminUiPath() }); return entries })

const saveName = async () => {
  const name = newName.value.trim()
  if (!name) { authStore.showMessage('Name cannot be empty', 'error'); return }
  try {
    saving.value = true
    await apiJson('/auth/api/user/display-name', { method: 'PUT', body: { display_name: name } })
    showNameDialog.value = false
    await authStore.loadUserInfo()
    authStore.showMessage('Name updated successfully!', 'success', 3000)
  } catch (e) { authStore.showMessage(e.message || 'Failed to update name', 'error') }
  finally { saving.value = false }
}
</script>

<style scoped>
.view-lede { margin: 0; color: var(--color-text-muted); font-size: 1rem; }
.section-header { display: flex; flex-direction: column; gap: 0.4rem; }
.section-description { margin: 0; color: var(--color-text-muted); }
.empty-state { margin: 0; color: var(--color-text-muted); text-align: center; padding: 1rem 0; }
.logout-note { margin: 0.75rem 0 0; color: var(--color-text-muted); font-size: 0.875rem; }
.remote-auth-inline { display: flex; flex-direction: column; gap: 0.5rem; }
.remote-auth-label { display: block; margin: 0; font-size: 0.875rem; color: var(--color-text-muted); font-weight: 500; }
</style>
