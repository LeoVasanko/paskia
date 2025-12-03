<template>
  <section class="view-root" data-view="profile">
    <header class="view-header">
      <h1>👋 Welcome!</h1>
      <Breadcrumbs :entries="breadcrumbEntries" />
      <p class="view-lede">Manage your account details and passkeys.</p>
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
      />
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
          allow-delete
          @delete="handleDelete"
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
      @terminate="terminateSession"
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
      <div class="button-row logout-row" :class="{ single: !hasMultipleSessions }">
        <button
          type="button"
          class="btn-secondary"
          @click="goBack"
        >
          Back
        </button>
        <button v-if="!hasMultipleSessions" @click="logoutEverywhere" class="btn-danger logout-button" :disabled="authStore.isLoading">Logout</button>
        <template v-else>
          <button @click="logout" class="btn-danger logout-button" :disabled="authStore.isLoading">Logout</button>
          <button @click="logoutEverywhere" class="btn-danger logout-button" :disabled="authStore.isLoading">All</button>
        </template>
      </div>
      <p class="logout-note" v-if="!hasMultipleSessions"><strong>Logout</strong> from {{ currentSessionHost }}.</p>
      <p class="logout-note" v-else><strong>Logout</strong> this session on {{ currentSessionHost }}, or <strong>All</strong> sessions across all sites and devices for {{ rpName }}. You'll need to log in again with your passkey afterwards.</p>
    </section>
    <RegistrationLinkModal
      v-if="showRegLink"
              :endpoint="'/auth/api/user/create-link'"
      :auto-copy="false"
      :prefix-copy-with-user-name="false"
      @close="showRegLink = false"
      @copied="showRegLink = false; authStore.showMessage('Link copied to clipboard!', 'success', 2500)"
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
import { useAuthStore } from '@/stores/auth'
import { adminUiPath, makeUiHref } from '@/utils/settings'
import passkey from '@/utils/passkey'
import { goBack } from '@/utils/helpers'
import { apiFetch } from '@/utils/api'

const authStore = useAuthStore()
const updateInterval = ref(null)
const showNameDialog = ref(false)
const showRegLink = ref(false)
const newName = ref('')
const saving = ref(false)

watch(showNameDialog, (newVal) => { if (newVal) newName.value = authStore.userInfo?.user?.user_name || '' })

onMounted(() => {
  updateInterval.value = setInterval(() => { if (authStore.userInfo) authStore.userInfo = { ...authStore.userInfo } }, 60000)
})

onUnmounted(() => { if (updateInterval.value) clearInterval(updateInterval.value) })

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
  } finally { authStore.isLoading = false }
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
    const res = await apiFetch('/auth/api/user/display-name', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name }) })
    const data = await res.json()
    if (!res.ok || data.detail) throw new Error(data.detail || 'Update failed')
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
.logout-button { align-self: flex-start; }
.logout-row { gap: 1rem; }
.logout-row.single { justify-content: flex-start; }
.logout-note { margin: 0.75rem 0 0; color: var(--color-text-muted); font-size: 0.875rem; }
@media (max-width: 720px) { .logout-button { width: 100%; } }
</style>
