<script setup>
// Dispatcher: renders the dialog component matching dialog.type. Each
// dialog component carries its own title and content.
import OrgCreateDialog from './dialogs/OrgCreateDialog.vue'
import OrgUpdateDialog from './dialogs/OrgUpdateDialog.vue'
import RoleCreateDialog from './dialogs/RoleCreateDialog.vue'
import RoleUpdateDialog from './dialogs/RoleUpdateDialog.vue'
import UserCreateDialog from './dialogs/UserCreateDialog.vue'
import UserUpdateNameDialog from './dialogs/UserUpdateNameDialog.vue'
import PermissionDialog from './dialogs/PermissionDialog.vue'
import DomainEditDialog from './dialogs/DomainEditDialog.vue'
import ConfirmDialog from './dialogs/ConfirmDialog.vue'

defineProps({
  dialog: Object,
  PERMISSION_ID_PATTERN: String
})

defineEmits(['submitDialog', 'closeDialog'])
</script>

<template>
  <OrgCreateDialog
    v-if="dialog.type === 'org-create'"
    :dialog="dialog"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
  <OrgUpdateDialog
    v-else-if="dialog.type === 'org-update'"
    :dialog="dialog"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
  <RoleCreateDialog
    v-else-if="dialog.type === 'role-create'"
    :dialog="dialog"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
  <RoleUpdateDialog
    v-else-if="dialog.type === 'role-update'"
    :dialog="dialog"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
  <UserCreateDialog
    v-else-if="dialog.type === 'user-create'"
    :dialog="dialog"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
  <UserUpdateNameDialog
    v-else-if="dialog.type === 'user-update-name'"
    :dialog="dialog"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
  <PermissionDialog
    v-else-if="dialog.type === 'perm-create' || dialog.type === 'perm-display'"
    :dialog="dialog"
    :permission-id-pattern="PERMISSION_ID_PATTERN"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
  <DomainEditDialog
    v-else-if="dialog.type === 'domain-edit'"
    :dialog="dialog"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
  <ConfirmDialog
    v-else-if="dialog.type === 'confirm'"
    :dialog="dialog"
    @submit="$emit('submitDialog')"
    @close="$emit('closeDialog')"
  />
</template>
