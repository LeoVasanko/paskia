<script setup>
import { ref, computed } from 'vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import CredentialList from '@/components/CredentialList.vue'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'
import SessionList from '@/components/SessionList.vue'
import { useAuthStore } from '@/stores/auth'
import { apiJson } from 'paskia'
import { getDirection, navigateButtonRow, focusPreferred, focusAtIndex } from '@/utils/keynav'

const props = defineProps({
  selectedUser: Object,
  userDetail: Object,
  selectedOrg: Object,
  loading: Boolean,
  showRegModal: Boolean,
  navigationDisabled: { type: Boolean, default: false }
})

const emit = defineEmits(['generateUserRegistrationLink', 'goOverview', 'openOrg', 'onUserNameSaved', 'closeRegModal', 'editUserName', 'refreshUserDetail', 'navigateOut', 'deleteUser'])

const authStore = useAuthStore()
const hoveredCredentialUuid = ref(null)
const hoveredSession = ref(null)

// Template refs for navigation
const userInfoRef = ref(null)
const regActionsRef = ref(null)
const credentialListRef = ref(null)
const sessionListRef = ref(null)
const backButtonRef = ref(null)

// Check if any modal/dialog is open (blocks arrow key navigation)
const hasActiveModal = computed(() => props.showRegModal)

function onLinkCopied() {
  authStore.showMessage(`📋 Link copied! Send it to ${props.selectedUser.display_name}.`)
  emit('closeRegModal')
}

function handleEditName() {
  emit('editUserName', props.selectedUser)
}

async function handleDelete(credential) {
  try {
    const data = await apiJson(`/auth/api/admin/users/${props.selectedUser.uuid}/credentials/${credential.uuid}`, { method: 'DELETE' })
    if (data.status === 'ok') {
      emit('onUserNameSaved') // Reuse to refresh user detail
    } else {
      console.error('Failed to delete credential', data)
    }
  } catch (err) {
    console.error('Delete credential error', err)
  }
}

async function handleTerminateSession(session) {
  const credentialUuid = session?.credential
  if (!credentialUuid) return
  try {
    await apiJson(`/auth/api/admin/users/${props.selectedUser.uuid}/credentials/${credentialUuid}`, { method: 'DELETE' })
    emit('refreshUserDetail')
    authStore.showMessage('Credential deleted', 'success', 2500)
  } catch (err) {
    console.error('Delete credential error', err)
    authStore.showMessage(err.message || 'Failed to delete credential', 'error')
  }
}

async function handleDeleteUser() {
  emit('deleteUser')
}

// Handle user info section keynav
function handleUserInfoKeydown(event) {
  if (hasActiveModal.value || props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(userInfoRef.value, event.target, direction, { itemSelector: '.mini-btn' })
  } else if (direction === 'up') {
    emit('navigateOut', 'up')
  } else if (direction === 'down') {
    // Move to registration actions
    focusPreferred(regActionsRef.value, { itemSelector: 'button' })
  }
}

// Handle registration actions keynav
function handleRegActionsKeydown(event) {
  if (hasActiveModal.value || props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(regActionsRef.value, event.target, direction, { itemSelector: 'button' })
  } else if (direction === 'up') {
    // Move to user info edit button
    focusPreferred(userInfoRef.value, { itemSelector: '.mini-btn' })
  } else if (direction === 'down') {
    // Move to credential list
    credentialListRef.value?.$el?.focus()
  }
}

// Handle credential list navigate out
function handleCredentialNavigateOut(direction) {
  if (hasActiveModal.value || props.navigationDisabled) return

  if (direction === 'up') {
    focusPreferred(regActionsRef.value, { itemSelector: 'button' })
  } else if (direction === 'down') {
    // Move to session list
    focusAtIndex(sessionListRef.value?.$el, 0, { itemSelector: '.session-group' })
  }
}

// Handle session list navigate out
function handleSessionNavigateOut(direction) {
  if (hasActiveModal.value || props.navigationDisabled) return

  if (direction === 'up') {
    // Move to credential list
    credentialListRef.value?.$el?.focus()
  } else if (direction === 'down') {
    // Move to back button
    const backBtn = backButtonRef.value?.querySelector('button')
    if (backBtn) backBtn.focus()
  }
}

// Handle back button keynav
function handleBackButtonKeydown(event) {
  if (hasActiveModal.value || props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'up') {
    // Move to session list
    focusAtIndex(sessionListRef.value?.$el, -1, { itemSelector: '.session-group' })
  }
}

// Focus helper for external navigation
function focusFirstElement() {
  focusPreferred(userInfoRef.value, { itemSelector: '.mini-btn' })
}

defineExpose({ focusFirstElement })
</script>

<template>
  <div class="user-detail">
    <div ref="userInfoRef" @keydown="handleUserInfoKeydown">
      <UserBasicInfo
        v-if="userDetail && !userDetail.error"
        :name="userDetail.user.display_name"
        :visits="userDetail.user.visits"
        :created-at="userDetail.user.created_at"
        :last-seen="userDetail.user.last_seen"
        :loading="loading"
        :org-display-name="selectedOrg?.org?.display_name"
        :role-name="selectedUser?.role_display_name"
        :update-endpoint="`/auth/api/admin/users/${selectedUser.uuid}/display-name`"
        @saved="$emit('onUserNameSaved')"
        @edit-name="handleEditName"
      >
        <div class="admin-actions">
          <button
            class="btn-primary"
            @click="$emit('generateUserRegistrationLink', selectedUser)"
            :disabled="loading"
          >{{ Object.keys(userDetail?.credentials || {}).length ? 'Recovery Link' : 'Registration Link' }}</button>
          <button
            class="btn-danger"
            @click="handleDeleteUser"
            :disabled="loading"
            title="Delete this user"
          >Delete User</button>
        </div>
      </UserBasicInfo>
    </div>
    <div v-if="userDetail?.error" class="error small">{{ userDetail.error }}</div>
    <template v-if="userDetail && !userDetail.error">
      <section class="section-block" data-section="registered-passkeys">
        <div class="section-header">
          <h2>Registered Passkeys</h2>
        </div>
        <div class="section-body">
          <CredentialList
            ref="credentialListRef"
            :credentials="Object.entries(userDetail.credentials).map(([uuid, c]) => ({ ...c, uuid })).sort((a, b) => new Date(a.created_at) - new Date(b.created_at))"
            :aaguid-info="userDetail.aaguid_info"
            :allow-delete="true"
            :hovered-credential-uuid="hoveredCredentialUuid"
            :hovered-session-credential-uuid="hoveredSession?.credential || null"
            :navigation-disabled="hasActiveModal"
            @delete="handleDelete"
            @credential-hover="hoveredCredentialUuid = $event"
            @navigate-out="handleCredentialNavigateOut"
          />
        </div>
      </section>
      <SessionList
        ref="sessionListRef"
        :sessions="userDetail.sessions"
        :hovered-credential-uuid="hoveredCredentialUuid"
        :navigation-disabled="hasActiveModal"
        :empty-message="'This user has no active sessions.'"
        :section-description="'View and manage the active sessions for this user.'"
        @terminate="handleTerminateSession"
        @session-hover="hoveredSession = $event"
        @navigate-out="handleSessionNavigateOut"
      />
    </template>
    <div class="actions ancillary-actions" ref="backButtonRef" @keydown="handleBackButtonKeydown">
      <button v-if="selectedOrg" @click="$emit('openOrg', selectedOrg)" class="icon-btn" title="Back to Org">↩️</button>
    </div>
    <RegistrationLinkModal
      v-if="showRegModal"
      :endpoint="`/auth/api/admin/users/${selectedUser.uuid}/create-link`"
      :user-name="userDetail?.user.display_name || selectedUser.display_name"
      @close="$emit('closeRegModal')"
      @copied="onLinkCopied"
    />
  </div>
</template>

<style scoped>
.user-detail { display: flex; flex-direction: column; gap: var(--space-lg); }
.admin-actions { display: flex; gap: 0.5rem; }
.ancillary-actions { margin-top: -0.5rem; }
</style>
