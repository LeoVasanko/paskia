<script setup>
import AdminDialog from './AdminDialog.vue'

defineProps({
  dialog: { type: Object, required: true }
})

defineEmits(['submit', 'close'])
</script>

<template>
  <AdminDialog
    title="Add User To Role"
    :busy="dialog.busy"
    :error="dialog.error"
    @submit="$emit('submit')"
    @close="$emit('close')"
  >
    <p class="small muted">Role: {{ dialog.data.role.display_name }}</p>
    <label>Display Name
      <input v-model="dialog.data.name" placeholder="User display name" required />
    </label>
  </AdminDialog>
</template>
