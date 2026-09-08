<script setup>
import { computed } from 'vue'
import AdminDialog from './AdminDialog.vue'

const props = defineProps({
  dialog: { type: Object, required: true },
  permissionIdPattern: { type: String, required: true }
})

defineEmits(['submit', 'close'])

const title = computed(() =>
  props.dialog.type === 'perm-create' ? 'Create Permission' : 'Edit Permission'
)
</script>

<template>
  <AdminDialog
    :title="title"
    :busy="dialog.busy"
    :error="dialog.error"
    @submit="$emit('submit')"
    @close="$emit('close')"
  >
    <label>Display Name
      <input v-model="dialog.data.display_name" required />
    </label>
    <label>Permission Scope
      <input v-model="dialog.data.scope" required :pattern="permissionIdPattern" title="Allowed: A-Za-z0-9:._~-" data-form-type="other" />
    </label>
    <p class="small muted">E.g. yourapp:reports. Changing the scope name may break deployed applications.</p>
    <label>Domain Scope
      <input v-model="dialog.data.domain" data-form-type="other" />
    </label>
    <p class="small muted">A domain restricts this permission to that host (any configured domain's rp-id or a subdomain of it). An OIDC client UUID sends it as a <em>groups</em> claim to that client.</p>
  </AdminDialog>
</template>
