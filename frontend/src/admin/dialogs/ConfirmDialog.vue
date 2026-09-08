<script setup>
import AdminDialog from './AdminDialog.vue'

defineProps({
  dialog: { type: Object, required: true }
})

defineEmits(['submit', 'close'])
</script>

<template>
  <AdminDialog
    title="Confirm"
    submit-label="OK"
    :busy="dialog.busy"
    :error="dialog.error"
    @submit="$emit('submit')"
    @close="$emit('close')"
  >
    <p>{{ dialog.data.message }}</p>
  </AdminDialog>
</template>
