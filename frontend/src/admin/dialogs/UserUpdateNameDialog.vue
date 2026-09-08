<script setup>
import AdminDialog from './AdminDialog.vue'
import NameEditForm from '@/components/NameEditForm.vue'

defineProps({
  dialog: { type: Object, required: true }
})

defineEmits(['submit', 'close'])
</script>

<template>
  <AdminDialog
    title="Edit User Name"
    :busy="dialog.busy"
    bare
    @submit="$emit('submit')"
    @close="$emit('close')"
  >
    <NameEditForm
      label="Display Name"
      v-model="dialog.data.name"
      :busy="dialog.busy"
      :error="dialog.error"
      @cancel="$emit('close')"
    />
  </AdminDialog>
</template>
