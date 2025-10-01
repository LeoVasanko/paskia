<script setup>
const props = defineProps({
  dialog: Object,
  PERMISSION_ID_PATTERN: String
})

const emit = defineEmits(['submitDialog', 'closeDialog'])
</script>

<template>
  <div v-if="dialog.type" class="modal-overlay" @keydown.esc.prevent.stop="$emit('closeDialog')" tabindex="-1">
    <div class="modal" role="dialog" aria-modal="true">
      <h3 class="modal-title">
        <template v-if="dialog.type==='org-create'">Create Organization</template>
        <template v-else-if="dialog.type==='org-update'">Rename Organization</template>
        <template v-else-if="dialog.type==='role-create'">Create Role</template>
        <template v-else-if="dialog.type==='role-update'">Edit Role</template>
        <template v-else-if="dialog.type==='user-create'">Add User To Role</template>
        <template v-else-if="dialog.type==='perm-create'">Create Permission</template>
        <template v-else-if="dialog.type==='perm-display'">Edit Permission Display</template>
        <template v-else-if="dialog.type==='confirm'">Confirm</template>
      </h3>
      <form @submit.prevent="$emit('submitDialog')" class="modal-form">
        <template v-if="dialog.type==='org-create' || dialog.type==='org-update'">
          <label>Name
            <input v-model="dialog.data.name" :placeholder="dialog.type==='org-update'? dialog.data.org.display_name : 'Organization name'" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='role-create'">
          <label>Role Name
            <input v-model="dialog.data.name" placeholder="Role name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='role-update'">
          <label>Role Name
            <input v-model="dialog.data.name" :placeholder="dialog.data.role.display_name" required />
          </label>
          <label>Permissions (comma separated)
            <textarea v-model="dialog.data.perms" rows="2" placeholder="perm:a, perm:b"></textarea>
          </label>
        </template>
        <template v-else-if="dialog.type==='user-create'">
          <p class="small muted">Role: {{ dialog.data.role.display_name }}</p>
          <label>Display Name
            <input v-model="dialog.data.name" placeholder="User display name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='perm-create'">
          <label>Permission ID
            <input v-model="dialog.data.id" placeholder="permission id" required :pattern="PERMISSION_ID_PATTERN" title="Allowed: A-Za-z0-9:._~-" />
          </label>
          <label>Display Name
            <input v-model="dialog.data.name" placeholder="display name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='perm-display'">
          <label>Permission ID
            <input v-model="dialog.data.id" :placeholder="dialog.data.permission.id" required :pattern="PERMISSION_ID_PATTERN" title="Allowed: A-Za-z0-9:._~-" />
          </label>
          <label>Display Name
            <input v-model="dialog.data.display_name" :placeholder="dialog.data.permission.display_name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='confirm'">
          <p>{{ dialog.data.message }}</p>
        </template>
        <div v-if="dialog.error" class="error small">{{ dialog.error }}</div>
        <div class="modal-actions">
          <button type="submit" :disabled="dialog.busy">{{ dialog.type==='confirm' ? 'OK' : 'Save' }}</button>
          <button type="button" @click="$emit('closeDialog')" :disabled="dialog.busy">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</template>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(.1rem);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-xl);
  padding: var(--space-lg);
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-title {
  margin: 0 0 var(--space-md) 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--color-heading);
}

.modal-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}

.modal-form label {
  display: flex;
  flex-direction: column;
  gap: var(--space-xs);
  font-weight: 500;
}

.modal-form input,
.modal-form textarea {
  padding: var(--space-sm);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  background: var(--color-surface);
  color: var(--color-text);
}

.modal-form input:focus,
.modal-form textarea:focus {
  outline: none;
  border-color: var(--color-accent);
  box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.1);
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-sm);
  margin-top: var(--space-lg);
}

.error { color: var(--color-danger-text); }
.small { font-size: 0.9rem; }
.muted { color: var(--color-text-muted); }
</style>