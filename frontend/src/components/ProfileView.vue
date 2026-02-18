<template>
  <section class="view-root view-root--profile" data-view="profile">
    <div class="view-header-wrapper">
      <div class="theme-toggle">
        <ThemeSelector />
      </div>
      <header class="view-header">
        <Breadcrumbs ref="breadcrumbs" :entries="breadcrumbEntries" @keydown="handleBreadcrumbKeydown" />
        <p class="view-lede">Account dashboard to manage your profile and authentications.</p>
      </header>
    </div>

    <section class="section-block section-block--constrained" ref="userInfoSection">
      <UserBasicInfo
        v-if="authStore.userInfo?.user"
        ref="userBasicInfo"
        :name="authStore.userInfo.user.display_name"
        :email="authStore.userInfo.user.email"
        :preferred_username="authStore.userInfo.user.preferred_username"
        :telephone="authStore.userInfo.user.telephone"
        :visits="authStore.userInfo.user.visits"
        :created-at="authStore.userInfo.user.created_at"
        :last-seen="authStore.userInfo.user.last_seen"
        :loading="authStore.isLoading"
        :org-display-name="authStore.userInfo.org.display_name"
        :role-name="authStore.userInfo.role.display_name"
        update-endpoint="/auth/api/user/info"
        @saved="authStore.loadUserInfo()"
        @edit="openEditDialog"
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
        <p class="remote-auth-description">Login from another device</p>
      </UserBasicInfo>
    </section>

    <section :class="['section-block', { 'section-block--constrained': !useWideLayout }]">
      <div class="section-header">
        <h2>Your Passkeys</h2>
        <p class="section-description">Ideally have at least two passkeys in case you lose one. More than one user can be registered on the same device, giving you a choice at login. <a href="https://bitwarden.com/pricing/" target="_blank" rel="noopener noreferrer">Bitwarden</a> can sync one passkey to all your devices. Other secure options include <b>local passkeys</b>, as well as hardware keys such as <a href="https://www.yubico.com" target="_blank" rel="noopener noreferrer">YubiKey</a>. Cloud sync via Google, Microsoft or iCloud is discouraged.</p>
      </div>
      <div class="section-body">
        <CredentialList
          ref="credentialList"
          :credentials="credentials"
          :aaguid-info="authStore.userInfo.aaguid_info"
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
      :section-class="useWideLayout ? '' : 'section-block--constrained'"
      @terminate="terminateSession"
      @session-hover="hoveredSession = $event"
      @navigate-out="handleSessionNavigateOut"
      section-description="You are currently signed in to the following sessions. If you don't recognize something, consider deleting not only the session but the associated passkey you suspect is compromised, as only this terminates all linked sessions and prevents logging in again."
    />

    <section :class="['section-block', { 'section-block--constrained': !useWideLayout }]">
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
      <div class="logout-footer">
        <p class="logout-note" v-if="!hasMultipleSessions"><strong>Logout</strong> from {{ currentSessionHost }}.</p>
        <p class="logout-note" v-else><strong>Logout</strong> this session on {{ currentSessionHost }}, or <strong>All</strong> sessions across all sites and devices for {{ rpName }}.</p>
        <a class="paskia-version" href="https://git.zi.fi/leovasanko/paskia" target="_blank" rel="noopener noreferrer">Paskia {{ paskiaVersion }}</a>
      </div>
    </section>

    <Modal v-if="showEditDialog" @close="showEditDialog = false">
      <h3>Edit Profile</h3>
      <form @submit.prevent="saveProfile" class="modal-form">
        <div class="profile-edit-form">
          <label for="edit-display-name">Display Name
            <input id="edit-display-name" type="text" v-model="editName" :disabled="saving" required />
          </label>
          <label for="edit-email">Email
            <input id="edit-email" type="email" v-model="editEmail" :disabled="saving" />
          </label>
          <label for="edit-username">Preferred Username
            <input id="edit-username" type="text" v-model="editUsername" :disabled="saving" placeholder="username" />
          </label>
          <label for="edit-telephone">Telephone
            <input id="edit-telephone" type="tel" v-model="editTelephone" :disabled="saving" />
          </label>
          <div v-if="editError" class="error small">{{ editError }}</div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showEditDialog = false" :disabled="saving">Cancel</button>
            <button type="submit" class="btn-primary" :disabled="saving" data-nav-primary>Save</button>
          </div>
        </div>
      </form>
    </Modal>

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
const showEditDialog = ref(false)
const showRegLink = ref(false)
const editName = ref('')
const editEmail = ref('')
const editUsername = ref('')
const editTelephone = ref('')
const saving = ref(false)
const editError = ref('')
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
const hasActiveModal = computed(() => showEditDialog.value || showRegLink.value)

watch(showEditDialog, (open) => {
  if (!open) return
  const user = authStore.userInfo.user
  editName.value = user.display_name ?? ''
  editEmail.value = user.email ?? ''
  editUsername.value = user.preferred_username ?? ''
  editTelephone.value = user.telephone ?? ''
  editError.value = ''
})

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
const paskiaVersion = computed(() => authStore.settings?.version || '')
const sessions = computed(() => authStore.userInfo.sessions)
const currentSessionHost = computed(() => {
  const currentSession = Object.values(sessions.value).find(session => session.is_current)
  return currentSession?.host || 'this host'
})
const terminatingSessions = ref({})

const terminateSession = async (session) => {
  const sessionKey = session?.key
  if (!sessionKey) return
  terminatingSessions.value = { ...terminatingSessions.value, [sessionKey]: true }
  try { await authStore.terminateSession(sessionKey) }
  catch (error) { authStore.showMessage(error.message || 'Failed to terminate session', 'error', 5000) }
  finally {
    const next = { ...terminatingSessions.value }
    delete next[sessionKey]
    terminatingSessions.value = next
  }
}

const logoutEverywhere = async () => { await authStore.logoutEverywhere() }
const logout = async () => { await authStore.logout() }
const openEditDialog = () => { showEditDialog.value = true }
const isAdmin = computed(() => {
  const perms = Object.values(authStore.userInfo.permissions).map(p => p.scope)
  return perms.includes('auth:admin') || perms.includes('auth:org:admin')
})
const hasMultipleSessions = computed(() => Object.keys(sessions.value).length > 1)
const credentials = computed(() =>
  Object.entries(authStore.userInfo.credentials).map(([uuid, c]) => ({ ...c, credential: uuid }))
)
const useWideLayout = computed(() => {
  // Check if any single site has more than 8 sessions
  const groups = {}
  for (const session of Object.values(sessions.value)) {
    const host = session.host || ''
    if (!groups[host]) groups[host] = []
    groups[host].push(session)
  }
  const hasLargeSessionGroup = Object.values(groups).some(group => group.length > 8)

  // Check if passkeys exceed 8
  const hasManyCredentials = credentials.value.length > 8

  return hasLargeSessionGroup || hasManyCredentials
})
const breadcrumbEntries = computed(() => { const entries = [{ label: 'My Profile', href: makeUiHref() }]; if (isAdmin.value) entries.push({ label: 'Admin', href: adminUiPath() }); return entries })

const saveProfile = async () => {
  const name = editName.value.trim()
  if (!name) { editError.value = 'Name cannot be empty'; return }
  const user = authStore.userInfo.user
  const emailVal = editEmail.value.trim() || null
  const usernameVal = editUsername.value.trim() || null
  const telephoneVal = editTelephone.value.trim() || null
  try {
    editError.value = ''
    saving.value = true
    const body = {}
    if (name !== user.display_name) body.display_name = name
    if (emailVal !== (user.email || null)) body.email = emailVal
    if (usernameVal !== (user.preferred_username || null)) body.preferred_username = usernameVal
    if (telephoneVal !== (user.telephone || null)) body.telephone = telephoneVal
    if (Object.keys(body).length) {
      await apiJson('/auth/api/user/info', { method: 'PATCH', body })
      await authStore.loadUserInfo()
      authStore.showMessage('Profile updated!', 'success', 3000)
    }
    showEditDialog.value = false
  } catch (e) {
    editError.value = e.message || 'Failed to update profile'
  } finally { saving.value = false }
}
</script>

<style scoped>
.section-header { display: flex; flex-direction: column; gap: 0.4rem; }
.empty-state { margin: 0; color: var(--color-text-muted); text-align: center; padding: 1rem 0; }
.logout-note { margin: 0; color: var(--color-text-muted); }
.logout-footer { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; margin-top: 0.75rem; }
.paskia-version { color: var(--color-text-muted); text-decoration: none; white-space: nowrap; font-weight: 700; }
.paskia-version:hover { color: var(--color-link-hover); }
.remote-auth-inline { display: flex; flex-direction: column; gap: 0.5rem; }
.remote-auth-label { display: block; margin: 0; font-size: 0.875rem; color: var(--color-text-muted); font-weight: 500; }
.remote-auth-description { font-size: 0.75rem; color: var(--color-text-muted); }
.theme-toggle { position: absolute; top: var(--layout-padding); right: var(--layout-padding); }
.profile-edit-form { display: flex; flex-direction: column; gap: var(--space-md); }
</style>
