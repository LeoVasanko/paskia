<script setup>
import Modal from '@/components/Modal.vue'
import NameEditForm from '@/components/NameEditForm.vue'

const props = defineProps({
  dialog: Object,
  PERMISSION_ID_PATTERN: String
})

const emit = defineEmits(['submitDialog', 'closeDialog'])

const NAME_EDIT_TYPES = new Set(['org-update', 'role-update', 'user-update-name'])
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
        <template v-else-if="dialog.type==='perm-create' || dialog.type==='perm-display'">{{ dialog.type === 'perm-create' ? 'Create Permission' : 'Edit Permission Display' }}</template>
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
          <label>Permission ID
            <input v-model="dialog.data.id" :placeholder="dialog.type === 'perm-create' ? 'yourapp:login' : dialog.data.permission.id" required :pattern="PERMISSION_ID_PATTERN" title="Allowed: A-Za-z0-9:._~-" />
          </label>
          <p class="small muted">The permission ID is used for permission checks in the application. Changing it may break deployed applications that reference this permission.</p>
        </template>
        <template v-else-if="dialog.type==='confirm'">
          <p>{{ dialog.data.message }}</p>
        </template>
        <div v-if="dialog.error && !NAME_EDIT_TYPES.has(dialog.type)" class="error small">{{ dialog.error }}</div>
        <div v-if="!NAME_EDIT_TYPES.has(dialog.type)" class="modal-actions">
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
      </form>
  </Modal>
</template>

<style scoped>
.error { color: var(--color-danger-text); }
.small { font-size: 0.9rem; }
.muted { color: var(--color-text-muted); }
</style>
