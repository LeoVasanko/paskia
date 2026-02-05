<template>
  <section class="view-root" data-view="profile">
    <div class="theme-toggle">
      <ThemeSelector />
    </div>
    <header class="view-header">
      <h1>User Profile</h1>
      <Breadcrumbs ref="breadcrumbs" :entries="breadcrumbEntries" @keydown="handleBreadcrumbKeydown" />
      <p class="view-lede">Account dashboard for managing credentials and authenticating with other devices.</p>
    </header>

    <section class="section-block" ref="userInfoSection">
      <UserBasicInfo
        v-if="authStore.userInfo?.ctx"
        ref="userBasicInfo"
        :name="authStore.userInfo.ctx.user.display_name"
        :visits="authStore.userInfo.visits"
        :created-at="authStore.userInfo.created_at"
        :last-seen="authStore.userInfo.last_seen"
        :loading="authStore.isLoading"
        update-endpoint="/auth/api/user/display-name"
        @saved="authStore.loadUserInfo()"
        @edit-name="openNameDialog"
        @keydown="handleUserInfoKeydown"
      >
        <div class="remote-auth-inline">
          <label v-if="!showDeviceInfo" class="remote-auth-label">Code words:</label>
          <RemoteAuthPermit
            ref="pairingEntry"
            title=""
            description=""
            @completed="handlePairingCompleted"
            @error="handlePairingError"
            @device-info-visible="showDeviceInfo = $event"
          />
        </div>
        <p class="remote-auth-description">Provided by another device requesting remote auth.</p>
      </UserBasicInfo>
    </section>

    <section class="section-block">
      <div class="section-header">
        <h2>Your Passkeys</h2>
        <p class="section-description">Ideally have at least two passkeys in case you lose one. More than one user can be registered on the same device, giving you a choice at login. <a href="https://bitwarden.com/pricing/" target="_blank" rel="noopener noreferrer">Bitwarden</a> can sync one passkey to all your devices. Other secure options include <b>local passkeys</b>, as well as hardware keys such as <a href="https://www.yubico.com" target="_blank" rel="noopener noreferrer">YubiKey</a>. Cloud sync via Google, Microsoft or iCloud is discouraged.</p>
      </div>
      <div class="section-body">
        <CredentialList
          ref="credentialList"
          :credentials="authStore.userInfo?.credentials || []"
          :aaguid-info="authStore.userInfo?.aaguid_info || {}"
          :loading="authStore.isLoading"
          :hovered-credential-uuid="hoveredCredentialUuid"
          :hovered-session-credential-uuid="hoveredSession?.credential"
          :navigation-disabled="hasActiveModal"
          allow-delete
          @delete="handleDelete"
          @credential-hover="hoveredCredentialUuid = $event"
          @navigate-out="handleCredentialNavigateOut"
        />
        <div class="button-row" ref="credentialButtons">
          <button @click="addNewCredential" class="btn-primary" @keydown="handleCredentialButtonKeydown">Register New</button>
          <button @click="showRegLink = true" class="btn-secondary" @keydown="handleCredentialButtonKeydown">Another Device</button>
        </div>
      </div>
    </section>

    <SessionList
      ref="sessionList"
      :sessions="sessions"
      :terminating-sessions="terminatingSessions"
      :hovered-credential-uuid="hoveredCredentialUuid"
      :navigation-disabled="hasActiveModal"
      @terminate="terminateSession"
      @session-hover="hoveredSession = $event"
      @navigate-out="handleSessionNavigateOut"
      section-description="You are currently signed in to the following sessions. If you don't recognize something, consider deleting not only the session but the associated passkey you suspect is compromised, as only this terminates all linked sessions and prevents logging in again."
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
      <div class="button-row" ref="logoutButtons">
        <button
          type="button"
          class="btn-secondary"
          @click="goBack"
          @keydown="handleLogoutButtonKeydown"
        >
          Back
        </button>
        <button v-if="!hasMultipleSessions" @click="logoutEverywhere" class="btn-danger" :disabled="authStore.isLoading" @keydown="handleLogoutButtonKeydown">Logout</button>
        <template v-else>
          <button @click="logout" class="btn-danger" :disabled="authStore.isLoading" @keydown="handleLogoutButtonKeydown">Logout</button>
          <button @click="logoutEverywhere" class="btn-danger" :disabled="authStore.isLoading" @keydown="handleLogoutButtonKeydown">All</button>
        </template>
      </div>
      <p class="logout-note" v-if="!hasMultipleSessions"><strong>Logout</strong> from {{ currentSessionHost }}.</p>
      <p class="logout-note" v-else><strong>Logout</strong> this session on {{ currentSessionHost }}, or <strong>All</strong> sessions across all sites and devices for {{ rpName }}. You'll need to log in again with your passkey afterwards.</p>
    </section>
    <RegistrationLinkModal
      v-if="showRegLink"
      endpoint="/auth/api/user/create-link"
      @close="showRegLink = false"
      @copied="onLinkCopied"
    />
  </section>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import Breadcrumbs from '@/components/Breadcrumbs.vue'
import CredentialList from '@/components/CredentialList.vue'
import ThemeSelector from '@/components/ThemeSelector.vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import Modal from '@/components/Modal.vue'
import NameEditForm from '@/components/NameEditForm.vue'
import SessionList from '@/components/SessionList.vue'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'
import RemoteAuthPermit from '@/components/RemoteAuthPermit.vue'
import { useAuthStore } from '@/stores/auth'
import { adminUiPath, makeUiHref } from '@/utils/settings'
import passkey from '@/utils/passkey'
import { goBack } from '@/utils/helpers'
import { apiJson } from 'paskia'
import { navigateButtonRow, focusPreferred, focusAtIndex, getDirection } from '@/utils/keynav'

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
const credentialList = ref(null)
const credentialButtons = ref(null)
const sessionList = ref(null)
const logoutButtons = ref(null)
const breadcrumbs = ref(null)
const userBasicInfo = ref(null)
const userInfoSection = ref(null)

// Check if any modal/dialog is open (blocks arrow key navigation)
const hasActiveModal = computed(() => showNameDialog.value || showRegLink.value)

watch(showNameDialog, (newVal) => { if (newVal) newName.value = authStore.userInfo?.ctx.user.display_name ?? '' })

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

const onLinkCopied = () => {
  authStore.showMessage('📋 Link copied! Send it to your other device.')
  showRegLink.value = false
}

// Helper to focus preferred button in a row (primary first, or first button)
const focusPreferredButton = (container) => {
  focusPreferred(container, { primarySelector: '.btn-primary', itemSelector: 'button' })
}

// Navigation between components
const handleBreadcrumbKeydown = (event) => {
  if (hasActiveModal.value) return  // Block navigation when modal is open

  const direction = getDirection(event)
  if (!direction) return

  // Left/right handled internally by Breadcrumbs component
  if (direction === 'down') {
    event.preventDefault()
    // Move to user info section - always focus edit button first
    focusPreferred(userInfoSection.value, { primarySelector: '.mini-btn', itemSelector: '.mini-btn, .pairing-input' })
  }
  // ArrowUp at the top does nothing
}

const handleUserInfoKeydown = (event) => {
  if (hasActiveModal.value) return  // Block navigation when modal is open

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()
  const itemSelector = '.mini-btn, .pairing-input'

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(userInfoSection.value, event.target, direction, { itemSelector })
  } else if (direction === 'up') {
    // Move to breadcrumbs - focus current page crumb
    breadcrumbs.value?.focusCurrent?.()
  } else if (direction === 'down') {
    // Move to credential list
    credentialList.value?.$el?.focus()
  }
}

const handleCredentialNavigateOut = (direction) => {
  if (hasActiveModal.value) return  // Block navigation when modal is open

  if (direction === 'down' || direction === 'right') {
    // Focus preferred button in credential section
    focusPreferredButton(credentialButtons.value)
  } else if (direction === 'up' || direction === 'left') {
    // Focus user info section - always focus edit button first
    focusPreferred(userInfoSection.value, { primarySelector: '.mini-btn', itemSelector: '.mini-btn, .pairing-input' })
  }
}

const handleCredentialButtonKeydown = (event) => {
  if (hasActiveModal.value) return  // Block navigation when modal is open

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(credentialButtons.value, event.target, direction, { itemSelector: 'button' })
  } else if (direction === 'up') {
    // Move back to credential list
    focusAtIndex(credentialList.value?.$el, 0, { itemSelector: '.credential-item' })
  } else if (direction === 'down') {
    // Move to session list
    focusAtIndex(sessionList.value?.$el, 0, { itemSelector: '.session-group' })
  }
}

const handleSessionNavigateOut = (direction) => {
  if (hasActiveModal.value) return  // Block navigation when modal is open

  if (direction === 'up') {
    // Focus preferred button in credential section
    focusPreferredButton(credentialButtons.value)
  } else if (direction === 'down') {
    // Focus preferred button in logout section
    focusPreferredButton(logoutButtons.value)
  }
}

const handleLogoutButtonKeydown = (event) => {
  if (hasActiveModal.value) return  // Block navigation when modal is open

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(logoutButtons.value, event.target, direction, { itemSelector: 'button' })
  } else if (direction === 'up') {
    // Move back to session list - focus last group
    focusAtIndex(sessionList.value?.$el, -1, { itemSelector: '.session-group' })
  }
  // ArrowDown at the bottom does nothing
}

const handleDelete = async (credential) => {
  const credentialId = credential?.credential
  if (!credentialId) return
  try {
    await authStore.deleteCredential(credentialId)
    authStore.showMessage('Passkey deleted! You should also remove it from your password manager or device.', 'success', 3000)
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
const openNameDialog = () => { newName.value = authStore.userInfo?.ctx.user.display_name ?? ''; showNameDialog.value = true }
const isAdmin = computed(() => {
  const perms = authStore.userInfo?.ctx.permissions
  return perms.includes('auth:admin') || perms.includes('auth:org:admin')
})
const hasMultipleSessions = computed(() => sessions.value.length > 1)
const breadcrumbEntries = computed(() => { const entries = [{ label: 'Auth', href: makeUiHref() }]; if (isAdmin.value) entries.push({ label: 'Admin', href: adminUiPath() }); return entries })

const saveName = async () => {
  const name = newName.value.trim()
  if (!name) { authStore.showMessage('Name cannot be empty', 'error'); return }
  try {
    saving.value = true
    await apiJson('/auth/api/user/display-name', { method: 'PATCH', body: { display_name: name } })
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
.empty-state { margin: 0; color: var(--color-text-muted); text-align: center; padding: 1rem 0; }
.logout-note { margin: 0.75rem 0 0; color: var(--color-text-muted); font-size: 0.875rem; }
.remote-auth-inline { display: flex; flex-direction: column; gap: 0.5rem; }
.remote-auth-label { display: block; margin: 0; font-size: 0.875rem; color: var(--color-text-muted); font-weight: 500; }
.remote-auth-description { font-size: 0.75rem; color: var(--color-text-muted); }
.theme-toggle { position: absolute; top: var(--layout-padding); right: var(--layout-padding); }
</style>
