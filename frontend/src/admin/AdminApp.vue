<script setup>
import { ref, onMounted } from 'vue'

const info = ref(null)
const loading = ref(true)
const error = ref(null)

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await fetch('/auth/user-info', { method: 'POST' })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    info.value = data
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="container">
    <h1>Passkey Admin</h1>
    <p class="subtitle">Manage organizations, roles, and permissions</p>

    <div v-if="loading">Loading…</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else>
      <div v-if="!info?.authenticated">
        <p>You must be authenticated.</p>
      </div>
      <div v-else-if="!(info?.is_global_admin || info?.is_org_admin)">
        <p>Insufficient permissions.</p>
      </div>
      <div v-else>
        <div class="card">
          <h2>User</h2>
          <div>{{ info.user.user_name }} ({{ info.user.user_uuid }})</div>
          <div>Role: {{ info.role?.display_name }}</div>
        </div>

        <div class="card">
          <h2>Organization</h2>
          <div>{{ info.org?.display_name }} ({{ info.org?.uuid }})</div>
          <div>Role permissions: {{ info.role?.permissions?.join(', ') }}</div>
          <div>Org grantable: {{ info.org?.permissions?.join(', ') }}</div>
        </div>

        <div class="card">
          <h2>Permissions</h2>
          <div>Effective: {{ info.permissions?.join(', ') }}</div>
          <div>Global admin: {{ info.is_global_admin ? 'yes' : 'no' }}</div>
          <div>Org admin: {{ info.is_org_admin ? 'yes' : 'no' }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.container { max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
.subtitle { color: #888 }
.card { margin: 1rem 0; padding: 1rem; border: 1px solid #eee; border-radius: 8px; }
.error { color: #a00 }
</style>
