<script setup>
import { ref } from 'vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import CredentialList from '@/components/CredentialList.vue'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'

const props = defineProps({
  selectedUser: Object,
  userDetail: Object,
  selectedOrg: Object,
  loading: Boolean,
  showRegModal: Boolean
})

const emit = defineEmits(['generateUserRegistrationLink', 'goOverview', 'openOrg', 'onUserNameSaved', 'closeRegModal'])

const showRegModal = ref(false)

function onLinkCopied() {
  // This could emit an event or show a message
}
</script>

<template>
  <div class="card surface user-detail">
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
    />
    <div v-else-if="userDetail?.error" class="error small">{{ userDetail.error }}</div>
    <template v-if="userDetail && !userDetail.error">
      <h3 class="cred-title">Registered Passkeys</h3>
      <CredentialList :credentials="userDetail.credentials" :aaguid-info="userDetail.aaguid_info" />
    </template>
    <div class="actions">
      <button @click="$emit('generateUserRegistrationLink', selectedUser)">Generate Registration Token</button>
      <button @click="$emit('goOverview')" class="icon-btn" title="Overview">🏠</button>
      <button v-if="selectedOrg" @click="$emit('openOrg', selectedOrg)" class="icon-btn" title="Back to Org">↩️</button>
    </div>
    <p class="matrix-hint muted">Use the token dialog to register a new credential for the member.</p>
    <RegistrationLinkModal
      v-if="showRegModal"
      :endpoint="`/auth/admin/orgs/${selectedUser.org_uuid}/users/${selectedUser.uuid}/create-link`"
      :auto-copy="false"
      @close="$emit('closeRegModal')"
      @copied="onLinkCopied"
    />
  </div>
</template>

<style scoped>
.card.surface { padding: var(--space-lg); }
.user-detail { display: flex; flex-direction: column; gap: var(--space-lg); }
.cred-title { font-size: 1.25rem; font-weight: 600; color: var(--color-heading); margin-bottom: var(--space-md); }
.actions { display: flex; flex-wrap: wrap; gap: var(--space-sm); align-items: center; }
.actions button { width: auto; }
.icon-btn { background: none; border: none; color: var(--color-text-muted); padding: 0.2rem; border-radius: var(--radius-sm); cursor: pointer; transition: background 0.2s ease, color 0.2s ease; }
.icon-btn:hover { color: var(--color-heading); background: var(--color-surface-muted); }
.matrix-hint { font-size: 0.8rem; color: var(--color-text-muted); }
.error { color: var(--color-danger-text); }
.small { font-size: 0.9rem; }
.muted { color: var(--color-text-muted); }
</style>