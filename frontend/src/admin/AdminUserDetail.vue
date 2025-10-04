<script setup>
import { ref } from 'vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import CredentialList from '@/components/CredentialList.vue'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'
import SessionList from '@/components/SessionList.vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  selectedUser: Object,
  userDetail: Object,
  selectedOrg: Object,
  loading: Boolean,
  showRegModal: Boolean
})

const emit = defineEmits(['generateUserRegistrationLink', 'goOverview', 'openOrg', 'onUserNameSaved', 'closeRegModal', 'editUserName'])

const authStore = useAuthStore()

function onLinkCopied() {
  authStore.showMessage('Link copied to clipboard!')
}

function handleEditName() {
  emit('editUserName', props.selectedUser)
}

function handleDelete(credential) {
  fetch(`/auth/admin/orgs/${props.selectedUser.org_uuid}/users/${props.selectedUser.uuid}/credentials/${credential.credential_uuid}`, { method: 'DELETE' })
    .then(res => res.json())
    .then(data => {
      if (data.status === 'ok') {
        emit('onUserNameSaved') // Reuse to refresh user detail
      } else {
        console.error('Failed to delete credential', data)
      }
    })
    .catch(err => console.error('Delete credential error', err))
}

</script>

<template>
  <div class="user-detail">
    <UserBasicInfo
      v-if="userDetail && !userDetail.error"
      :name="userDetail.display_name || selectedUser.display_name"
      :visits="userDetail.visits"
      :created-at="userDetail.created_at"
      :last-seen="userDetail.last_seen"
      :loading="loading"
      :org-display-name="userDetail.org.display_name"
      :role-name="userDetail.role"
      :update-endpoint="`/auth/admin/orgs/${selectedUser.org_uuid}/users/${selectedUser.uuid}/display-name`"
      @saved="$emit('onUserNameSaved')"
      @edit-name="handleEditName"
    />
    <div v-else-if="userDetail?.error" class="error small">{{ userDetail.error }}</div>
    <template v-if="userDetail && !userDetail.error">
      <div class="registration-actions">
        <button
          class="btn-secondary reg-token-btn"
          @click="$emit('generateUserRegistrationLink', selectedUser)"
          :disabled="loading"
        >Generate Registration Token</button>
        <p class="matrix-hint muted">
          Generate a one-time registration link so this user can register or add another passkey.
          Copy the link from the dialog and send it to the user, or have the user scan the QR code on their device.
        </p>
      </div>
      <section class="section-block" data-section="registered-passkeys">
        <div class="section-header">
          <h2>Registered Passkeys</h2>
        </div>
        <div class="section-body">
          <CredentialList
            :credentials="userDetail.credentials"
            :aaguid-info="userDetail.aaguid_info"
            :allow-delete="true"
            @delete="handleDelete"
          />
        </div>
      </section>
      <SessionList
        :sessions="userDetail.sessions || []"
        :allow-terminate="false"
        :empty-message="'This user has no active sessions.'"
        :section-description="'View the active sessions for this user.'"
      />
    </template>
    <div class="actions ancillary-actions">
      <button v-if="selectedOrg" @click="$emit('openOrg', selectedOrg)" class="icon-btn" title="Back to Org">↩️</button>
    </div>
    <RegistrationLinkModal
      v-if="showRegModal"
      :endpoint="`/auth/admin/orgs/${selectedUser.org_uuid}/users/${selectedUser.uuid}/create-link`"
      :auto-copy="false"
      :user-name="userDetail?.display_name || selectedUser.display_name"
      @close="$emit('closeRegModal')"
      @copied="onLinkCopied"
    />
  </div>
</template>

<style scoped>
.user-detail { display: flex; flex-direction: column; gap: var(--space-lg); }
.actions { display: flex; flex-wrap: wrap; gap: var(--space-sm); align-items: center; }
.ancillary-actions { margin-top: -0.5rem; }
.reg-token-btn { align-self: flex-start; }
.registration-actions { display: flex; flex-direction: column; gap: 0.5rem; }
.icon-btn { background: none; border: none; color: var(--color-text-muted); padding: 0.2rem; border-radius: var(--radius-sm); cursor: pointer; transition: background 0.2s ease, color 0.2s ease; }
.icon-btn:hover { color: var(--color-heading); background: var(--color-surface-muted); }
.matrix-hint { font-size: 0.8rem; color: var(--color-text-muted); }
.error { color: var(--color-danger-text); }
.small { font-size: 0.9rem; }
.muted { color: var(--color-text-muted); }
</style>