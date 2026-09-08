<script setup>
import AdminDialog from './AdminDialog.vue'

defineProps({
  dialog: { type: Object, required: true }
})

defineEmits(['submit', 'close'])
</script>

<template>
  <AdminDialog
    title="Create Role"
    :busy="dialog.busy"
    :error="dialog.error"
    @submit="$emit('submit')"
    @close="$emit('close')"
  >
    <label>Role Name
      <input v-model="dialog.data.name" placeholder="Role name" required />
    </label>
  </AdminDialog>
</template>
