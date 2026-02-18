<script setup>
import { computed } from 'vue'
import Modal from '@/components/Modal.vue'
import NameEditForm from '@/components/NameEditForm.vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  dialog: Object,
  PERMISSION_ID_PATTERN: String,
  settings: Object
})

const emit = defineEmits(['submitDialog', 'closeDialog', 'resetOidcSecret', 'createPermissionForClient'])

const NAME_EDIT_TYPES = new Set(['org-update', 'role-update', 'user-update-name'])
const NO_SUBMIT_TYPES = new Set([])
const rpId = computed(() => props.settings?.rp_id || 'the configured domain')
const discoveryUrl = computed(() => `${window.location.origin}/.well-known/openid-configuration`)

// Copy-to-clipboard helper
const authStore = useAuthStore()
function copyText(value, label) {
  navigator.clipboard.writeText(value).then(() => {
    authStore.showMessage(`${label} copied to clipboard`, 'success', 1500)
  })
}
</script>

<template>
  <Modal v-if="dialog.type" @close="$emit('closeDialog')">
      <h3 class="modal-title">
        <template v-if="dialog.type==='org-create'">Create Organization</template>
        <template v-else-if="dialog.type==='org-update'">Rename Organization</template>
        <template v-else-if="dialog.type==='role-create'">Create Role</template>
        <template v-else-if="dialog.type==='role-update'">Edit Role</template>
        <template v-else-if="dialog.type==='user-create'">Add User To Role</template>
        <template v-else-if="dialog.type==='user-update-name'">Edit User Name</template>
        <template v-else-if="dialog.type==='perm-create' || dialog.type==='perm-display'">{{ dialog.type === 'perm-create' ? 'Create Permission' : 'Edit Permission' }}</template>
        <template v-else-if="dialog.type==='oidc-edit'">{{ dialog.data?.isNew ? 'New OIDC Client' : 'OIDC Client' }}</template>
        <template v-else-if="dialog.type==='confirm'">Confirm</template>
      </h3>
      <form @submit.prevent="$emit('submitDialog')" class="modal-form">
        <template v-if="dialog.type==='org-create'">
          <label>Name
            <input ref="nameInput" v-model="dialog.data.name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='org-update'">
          <NameEditForm
            label="Organization Name"
            v-model="dialog.data.name"
            :busy="dialog.busy"
            :error="dialog.error"
            @cancel="$emit('closeDialog')"
          />
        </template>
        <template v-else-if="dialog.type==='role-create'">
          <label>Role Name
            <input v-model="dialog.data.name" placeholder="Role name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='role-update'">
          <NameEditForm
            label="Role Name"
            v-model="dialog.data.name"
            :busy="dialog.busy"
            :error="dialog.error"
            @cancel="$emit('closeDialog')"
          />
        </template>
        <template v-else-if="dialog.type==='user-create'">
          <p class="small muted">Role: {{ dialog.data.role.display_name }}</p>
          <label>Display Name
            <input v-model="dialog.data.name" placeholder="User display name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='user-update-name'">
          <NameEditForm
            label="Display Name"
            v-model="dialog.data.name"
            :busy="dialog.busy"
            :error="dialog.error"
            @cancel="$emit('closeDialog')"
          />
        </template>
        <template v-else-if="dialog.type==='perm-create' || dialog.type==='perm-display'">
          <label>Display Name
            <input ref="displayNameInput" v-model="dialog.data.display_name" required />
          </label>
          <label>Permission Scope
            <input v-model="dialog.data.scope" required :pattern="PERMISSION_ID_PATTERN" title="Allowed: A-Za-z0-9:._~-" data-form-type="other" />
          </label>
          <p class="small muted">E.g. yourapp:reports. Changing the scope name may break deployed applications.</p>
          <label>Domain Scope
            <input v-model="dialog.data.domain" data-form-type="other" />
          </label>
          <p class="small muted">A domain ({{ rpId }} or subdomain) restricts this permission to that host. An OIDC client UUID sends it as a <em>groups</em> claim to that client.</p>
        </template>
        <template v-else-if="dialog.type==='confirm'">
          <p>{{ dialog.data.message }}</p>
        </template>
        <div v-if="dialog.error && !NAME_EDIT_TYPES.has(dialog.type)" class="error small">{{ dialog.error }}</div>
        <div v-if="!NAME_EDIT_TYPES.has(dialog.type) && !NO_SUBMIT_TYPES.has(dialog.type)" class="modal-actions">
          <button
            type="button"
            class="btn-secondary"
            @click="$emit('closeDialog')"
            :disabled="dialog.busy"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="btn-primary"
            :disabled="dialog.busy"
          >
            {{ dialog.type==='confirm' ? 'OK' : 'Save' }}
          </button>
        </div>
        <div v-else-if="NO_SUBMIT_TYPES.has(dialog.type)" class="modal-actions">
          <button
            type="button"
            class="btn-primary"
            @click="$emit('closeDialog')"
          >
            Close
          </button>
        </div>
      </form>
  </Modal>
</template>

<style scoped>
.optional { font-weight: normal; color: var(--color-text-muted); font-size: 0.85em; }
.oidc-divider { border: none; border-top: 1px solid var(--color-border); margin: var(--space-sm) 0; }
.oidc-dl { display: grid; grid-template-columns: auto 1fr; gap: 0.2rem 1rem; align-items: baseline; margin: 0; }
.oidc-dl dt { font-size: 0.85rem; color: var(--color-text-muted); white-space: nowrap; }
.oidc-dl dd { margin: 0; cursor: pointer; overflow: hidden; }
.oidc-dl output { font-family: var(--font-mono, monospace); font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
.oidc-reset-row { display: flex; align-items: center; gap: var(--space-sm); flex-wrap: wrap; }
.oidc-groups { cursor: default; }
.oidc-group { cursor: pointer; }
.oidc-group output { white-space: normal; word-break: break-all; }
</style>
