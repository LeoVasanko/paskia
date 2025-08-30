<script setup>
import { ref, onMounted } from 'vue'

const info = ref(null)
const loading = ref(true)
const error = ref(null)
const orgs = ref([])
const permissions = ref([])

async function loadOrgs() {
  const res = await fetch('/auth/admin/orgs')
  const data = await res.json()
  if (data.detail) throw new Error(data.detail)
  orgs.value = data
}

async function loadPermissions() {
  const res = await fetch('/auth/admin/permissions')
  const data = await res.json()
  if (data.detail) throw new Error(data.detail)
  permissions.value = data
}

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await fetch('/auth/user-info', { method: 'POST' })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    info.value = data
    if (data.authenticated && (data.is_global_admin || data.is_org_admin)) {
      await Promise.all([loadOrgs(), loadPermissions()])
    }
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

// Org actions
async function createOrg() {
  const name = prompt('New organization display name:')
  if (!name) return
  const res = await fetch('/auth/admin/orgs', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ display_name: name, permissions: [] })
  })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

async function updateOrg(org) {
  const name = prompt('Organization display name:', org.display_name)
  if (!name) return
  const res = await fetch(`/auth/admin/orgs/${org.uuid}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ display_name: name, permissions: org.permissions })
  })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

async function deleteOrg(org) {
  if (!confirm(`Delete organization ${org.display_name}?`)) return
  const res = await fetch(`/auth/admin/orgs/${org.uuid}`, { method: 'DELETE' })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

async function addOrgPermission(org) {
  const id = prompt('Permission ID to add:', permissions.value[0]?.id || '')
  if (!id) return
  const res = await fetch(`/auth/admin/orgs/${org.uuid}/permissions/${encodeURIComponent(id)}`, { method: 'POST' })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

async function removeOrgPermission(org, permId) {
  const res = await fetch(`/auth/admin/orgs/${org.uuid}/permissions/${encodeURIComponent(permId)}`, { method: 'DELETE' })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

// Role actions
async function createRole(org) {
  const name = prompt('New role display name:')
  if (!name) return
  const csv = prompt('Permission IDs (comma-separated):', '') || ''
  const perms = csv.split(',').map(s => s.trim()).filter(Boolean)
  const res = await fetch(`/auth/admin/orgs/${org.uuid}/roles`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ display_name: name, permissions: perms })
  })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

async function updateRole(role) {
  const name = prompt('Role display name:', role.display_name)
  if (!name) return
  const csv = prompt('Permission IDs (comma-separated):', role.permissions.join(', ')) || ''
  const perms = csv.split(',').map(s => s.trim()).filter(Boolean)
  const res = await fetch(`/auth/admin/roles/${role.uuid}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ display_name: name, permissions: perms })
  })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

async function deleteRole(role) {
  if (!confirm(`Delete role ${role.display_name}?`)) return
  const res = await fetch(`/auth/admin/roles/${role.uuid}`, { method: 'DELETE' })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

// Permission actions
async function createPermission() {
  const id = prompt('Permission ID (e.g., auth/example):')
  if (!id) return
  const name = prompt('Permission display name:')
  if (!name) return
  const res = await fetch('/auth/admin/permissions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id, display_name: name })
  })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadPermissions()
}

async function updatePermission(p) {
  const name = prompt('Permission display name:', p.display_name)
  if (!name) return
  const res = await fetch(`/auth/admin/permissions/${encodeURIComponent(p.id)}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ display_name: name })
  })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadPermissions()
}

async function deletePermission(p) {
  if (!confirm(`Delete permission ${p.id}?`)) return
  const res = await fetch(`/auth/admin/permissions/${encodeURIComponent(p.id)}`, { method: 'DELETE' })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadPermissions()
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
          <h2>Organization</h2>
          <div>{{ info.org?.display_name }}</div>
          <div>Role permissions: {{ info.role?.permissions?.join(', ') }}</div>
          <div>Org grantable: {{ info.org?.permissions?.join(', ') }}</div>
        </div>

        <div class="card">
          <h2>Permissions</h2>
          <div>Effective: {{ info.permissions?.join(', ') }}</div>
          <div>Global admin: {{ info.is_global_admin ? 'yes' : 'no' }}</div>
          <div>Org admin: {{ info.is_org_admin ? 'yes' : 'no' }}</div>
        </div>

        <div v-if="info.is_global_admin || info.is_org_admin" class="card">
          <h2>Organizations</h2>
          <div class="actions">
            <button @click="createOrg" v-if="info.is_global_admin">+ Create Org</button>
          </div>
      <div v-for="o in orgs" :key="o.uuid" class="org">
            <div class="org-header">
        <strong>{{ o.display_name }}</strong>
            </div>
            <div class="org-actions">
              <button @click="updateOrg(o)">Edit</button>
              <button @click="deleteOrg(o)" v-if="info.is_global_admin">Delete</button>
            </div>
            <div>
              <div class="muted">Grantable permissions:</div>
              <div class="pill-list">
                <span v-for="p in o.permissions" :key="p" class="pill" :title="p">
                  {{ permissions.find(x => x.id === p)?.display_name || p }}
                  <button class="pill-x" @click="removeOrgPermission(o, p)" :title="'Remove ' + p">×</button>
                </span>
              </div>
              <button @click="addOrgPermission(o)" title="Add permission by ID">+ Add permission</button>
            </div>
            <div class="roles">
              <div class="muted">Roles:</div>
              <div v-for="r in o.roles" :key="r.uuid" class="role-item">
                <div>
                  <strong>{{ r.display_name }}</strong>
                </div>
                  <strong :title="r.uuid">{{ r.display_name }}</strong>
                <div class="role-actions">
                  <button @click="updateRole(r)">Edit</button>
                  <button @click="deleteRole(r)">Delete</button>
                </div>
              </div>
              <button @click="createRole(o)">+ Create role</button>
            </div>
            <div class="users" v-if="o.users?.length">
              <div class="muted">Users:</div>
              <table class="users-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Last Seen</th>
                    <th>Visits</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="u in o.users" :key="u.uuid" :title="u.uuid">
                    <td>{{ u.display_name }}</td>
                    <td>{{ u.role }}</td>
                    <td>{{ u.last_seen ? new Date(u.last_seen).toLocaleString() : '—' }}</td>
                    <td>{{ u.visits }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div v-if="info.is_global_admin || info.is_org_admin" class="card">
          <h2>All Permissions</h2>
          <div class="actions">
            <button @click="createPermission">+ Create Permission</button>
          </div>
          <div v-for="p in permissions" :key="p.id" class="perm" :title="p.id">
            <div>
              {{ p.display_name }}
            </div>
            <div class="perm-actions">
              <button @click="updatePermission(p)">Edit</button>
              <button @click="deletePermission(p)">Delete</button>
            </div>
          </div>
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
.actions { margin-bottom: .5rem }
.org { border-top: 1px dashed #eee; padding: .5rem 0 }
.org-header { display: flex; gap: .5rem; align-items: baseline }
.user-item { display: flex; gap: .5rem; margin: .15rem 0 }
.users-table { width: 100%; border-collapse: collapse; margin-top: .25rem; }
.users-table th, .users-table td { padding: .25rem .4rem; text-align: left; border-bottom: 1px solid #eee; font-weight: normal; }
.users-table th { font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; color: #555; }
.users-table tbody tr:hover { background: #fafafa; }
.org-actions, .role-actions, .perm-actions { display: flex; gap: .5rem; margin: .25rem 0 }
.muted { color: #666 }
.small { font-size: .9em }
.pill-list { display: flex; flex-wrap: wrap; gap: .25rem }
.pill { background: #f3f3f3; border: 1px solid #e2e2e2; border-radius: 999px; padding: .1rem .5rem; display: inline-flex; align-items: center; gap: .25rem }
.pill-x { background: transparent; border: none; color: #900; cursor: pointer }
button { padding: .25rem .5rem; border-radius: 6px; border: 1px solid #ddd; background: #fff; cursor: pointer }
button:hover { background: #f7f7f7 }
</style>
