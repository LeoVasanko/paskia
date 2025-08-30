<script setup>
import { ref, onMounted, computed, watch } from 'vue'
import CredentialList from '@/components/CredentialList.vue'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'
import StatusMessage from '@/components/StatusMessage.vue'
import { useAuthStore } from '@/stores/auth'

const info = ref(null)
const loading = ref(true)
const error = ref(null)
const orgs = ref([])
const permissions = ref([])
const currentOrgId = ref(null) // UUID of selected org for detail view
const currentUserId = ref(null) // UUID for user detail view
const userDetail = ref(null) // cached user detail object
const userLink = ref(null) // latest generated registration link
const userLinkExpires = ref(null)
const authStore = useAuthStore()

function parseHash() {
  const h = window.location.hash || ''
  currentOrgId.value = null
  currentUserId.value = null
  if (h.startsWith('#org/')) {
    currentOrgId.value = h.slice(5)
  } else if (h.startsWith('#user/')) {
    currentUserId.value = h.slice(6)
  }
}

async function loadOrgs() {
  const res = await fetch('/auth/admin/orgs')
  const data = await res.json()
  if (data.detail) throw new Error(data.detail)
  // Restructure to attach users to roles instead of flat user list at org level
  orgs.value = data.map(o => {
    const roles = o.roles.map(r => ({ ...r, users: [] }))
    const roleMap = Object.fromEntries(roles.map(r => [r.display_name, r]))
    for (const u of o.users || []) {
      if (roleMap[u.role]) roleMap[u.role].users.push(u)
    }
    return { ...o, roles }
  })
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
    // After loading orgs decide view if not global admin
    if (!data.is_global_admin && data.is_org_admin && orgs.value.length === 1) {
      if (!window.location.hash || window.location.hash === '#overview') {
        currentOrgId.value = orgs.value[0].uuid
        window.location.hash = `#org/${currentOrgId.value}`
      } else {
        parseHash()
      }
    } else parseHash()
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

async function createUserInRole(org, role) {
  const displayName = prompt(`New member display name for role "${role.display_name}":`)
  if (!displayName) return
  const res = await fetch(`/auth/admin/orgs/${org.uuid}/users`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ display_name: displayName, role: role.display_name })
  })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

async function moveUserToRole(org, user, targetRoleDisplayName) {
  if (user.role === targetRoleDisplayName) return
  const res = await fetch(`/auth/admin/orgs/${org.uuid}/users/${user.uuid}/role`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ role: targetRoleDisplayName })
  })
  const data = await res.json()
  if (data.detail) return alert(data.detail)
  await loadOrgs()
}

function onUserDragStart(e, user, org_uuid) {
  e.dataTransfer.effectAllowed = 'move'
  e.dataTransfer.setData('text/plain', JSON.stringify({ user_uuid: user.uuid, org_uuid }))
}

function onRoleDragOver(e) {
  e.preventDefault()
  e.dataTransfer.dropEffect = 'move'
}

function onRoleDrop(e, org, role) {
  e.preventDefault()
  try {
    const data = JSON.parse(e.dataTransfer.getData('text/plain'))
    if (data.org_uuid !== org.uuid) return // only within same org
    const user = org.roles.flatMap(r => r.users).find(u => u.uuid === data.user_uuid)
    if (user) moveUserToRole(org, user, role.display_name)
  } catch (_) { /* ignore */ }
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
  const res = await fetch(`/auth/admin/orgs/${org.uuid}/roles`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ display_name: name, permissions: [] })
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

onMounted(() => {
  window.addEventListener('hashchange', parseHash)
  load()
})

const selectedOrg = computed(() => orgs.value.find(o => o.uuid === currentOrgId.value) || null)

function openOrg(o) {
  window.location.hash = `#org/${o.uuid}`
}

function goOverview() {
  window.location.hash = '#overview'
}

function openUser(u) {
  window.location.hash = `#user/${u.uuid}`
}

const selectedUser = computed(() => {
  if (!currentUserId.value) return null
  for (const o of orgs.value) {
    for (const r of o.roles) {
      const u = r.users.find(x => x.uuid === currentUserId.value)
      if (u) return { ...u, org_uuid: o.uuid, role_display_name: r.display_name }
    }
  }
  return null
})

watch(selectedUser, async (u) => {
  if (!u) { userDetail.value = null; return }
  try {
    const res = await fetch(`/auth/admin/users/${u.uuid}`)
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    userDetail.value = data
  } catch (e) {
    userDetail.value = { error: e.message }
  }
})

const showRegModal = ref(false)
function generateUserRegistrationLink(u) {
  showRegModal.value = true
}

function onLinkCopied() {
  authStore.showMessage('Link copied to clipboard!')
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
    .catch(()=>{})
}

function permissionDisplayName(id) {
  return permissions.value.find(p => p.id === id)?.display_name || id
}

async function toggleRolePermission(role, permId, checked) {
  // Build next permission list
  const has = role.permissions.includes(permId)
  if (checked && has) return
  if (!checked && !has) return
  const next = checked ? [...role.permissions, permId] : role.permissions.filter(p => p !== permId)
  // Optimistic update
  const prev = [...role.permissions]
  role.permissions = next
  try {
    const res = await fetch(`/auth/admin/roles/${role.uuid}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ display_name: role.display_name, permissions: next })
    })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
  } catch (e) {
    alert(e.message || 'Failed to update role permission')
    role.permissions = prev // revert
  }
}
</script>

<template>
  <div class="container">
    <h1 v-if="!selectedUser">
      <template v-if="!selectedOrg">Passkey Admin</template>
      <template v-else>Organization Admin</template>
      <a href="/auth/" class="back-link" title="Back to User App">User</a>
      <a v-if="selectedOrg && info?.is_global_admin" @click.prevent="goOverview" href="#overview" class="nav-link" title="Back to overview">Overview</a>
    </h1>
    <p class="subtitle" v-if="!selectedUser">Manage organizations, roles, and permissions</p>

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

  <!-- Removed user-specific info (current org, effective permissions, admin flags) -->

        <!-- Overview Page -->
  <div v-if="!selectedUser && !selectedOrg && (info.is_global_admin || info.is_org_admin)" class="card">
          <h2>Organizations</h2>
          <div class="actions">
            <button @click="createOrg" v-if="info.is_global_admin">+ Create Org</button>
          </div>
          <table class="org-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Roles</th>
                 <th>Members</th>
                <th v-if="info.is_global_admin">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="o in orgs" :key="o.uuid">
                <td><a href="#org/{{o.uuid}}" @click.prevent="openOrg(o)">{{ o.display_name }}</a></td>
                <td>{{ o.roles.length }}</td>
                <td>{{ o.roles.reduce((acc,r)=>acc + r.users.length,0) }}</td>
                <td v-if="info.is_global_admin">
                  <button @click="updateOrg(o)" class="icon-btn" aria-label="Rename organization" title="Rename organization">✏️</button>
                  <button @click="deleteOrg(o)" class="icon-btn delete-icon" aria-label="Delete organization" title="Delete organization">❌</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- User Detail Page -->
        <div v-if="selectedUser" class="card user-detail">
          <h2 class="user-title"><span>{{ userDetail?.display_name || selectedUser.display_name }}</span></h2>
          <div v-if="userDetail && !userDetail.error" class="user-meta">
            <p class="small">Organization: {{ userDetail.org.display_name }}</p>
            <p class="small">Role: {{ userDetail.role }}</p>
            <p class="small">Visits: {{ userDetail.visits }}</p>
            <p class="small">Created: {{ userDetail.created_at ? new Date(userDetail.created_at).toLocaleString() : '—' }}</p>
            <p class="small">Last Seen: {{ userDetail.last_seen ? new Date(userDetail.last_seen).toLocaleString() : '—' }}</p>
            <h3 class="cred-title">Registered Passkeys</h3>
            <CredentialList :credentials="userDetail.credentials" :aaguid-info="userDetail.aaguid_info" />
          </div>
          <div v-else-if="userDetail?.error" class="error small">{{ userDetail.error }}</div>
          <div class="actions">
            <button @click="generateUserRegistrationLink(selectedUser)">Generate Registration Token</button>
            <button @click="goOverview" v-if="info.is_global_admin" class="icon-btn" title="Overview">🏠</button>
            <button @click="openOrg(selectedOrg)" v-if="selectedOrg" class="icon-btn" title="Back to Org">↩️</button>
          </div>
          <p class="matrix-hint muted">Use the token dialog to register a new credential for the member.</p>
          <RegistrationLinkModal
            v-if="showRegModal"
            :endpoint="`/auth/admin/users/${selectedUser.uuid}/create-link`"
            :auto-copy="false"
            @close="showRegModal = false"
            @copied="onLinkCopied"
          />
        </div>

        <!-- Organization Detail Page -->
        <div v-else-if="selectedOrg" class="card">
          <h2 class="org-title" :title="selectedOrg.uuid">
            <span class="org-name">{{ selectedOrg.display_name }}</span>
            <button @click="updateOrg(selectedOrg)" class="icon-btn" aria-label="Rename organization" title="Rename organization">✏️</button>
          </h2>
          <div class="org-actions">
            <button @click="deleteOrg(selectedOrg)" v-if="info.is_global_admin" class="icon-btn delete-icon" aria-label="Delete organization" title="Delete organization">❌</button>
            <button @click="createRole(selectedOrg)">+ Role</button>
            <button @click="goOverview" v-if="info.is_global_admin">Back</button>
          </div>

          <div class="matrix-wrapper">
            <h3>Permissions Matrix</h3>
            <div class="matrix-scroll">
              <div
                class="perm-matrix-grid"
                :style="{ gridTemplateColumns: 'minmax(180px, 1fr) ' + selectedOrg.roles.map(()=> '2.2rem').join(' ') }"
              >
                <!-- Headers -->
                <div class="grid-head perm-head">Permission</div>
                <div
                  v-for="r in selectedOrg.roles"
                  :key="'head-' + r.uuid"
                  class="grid-head role-head"
                  :title="r.display_name"
                >
                  <span>{{ r.display_name }}</span>
                </div>

                <!-- Data Rows -->
                <template v-for="pid in selectedOrg.permissions" :key="pid">
                  <div class="perm-name" :title="pid">{{ permissionDisplayName(pid) }}</div>
                  <div
                    v-for="r in selectedOrg.roles"
                    :key="r.uuid + '-' + pid"
                    class="matrix-cell"
                  >
                    <input
                      type="checkbox"
                      :checked="r.permissions.includes(pid)"
                      @change="e => toggleRolePermission(r, pid, e.target.checked)"
                    />
                  </div>
                </template>
              </div>
            </div>
            <p class="matrix-hint muted">Toggle which permissions each role grants.</p>
          </div>
          <div class="roles-grid">
            <div
              v-for="r in selectedOrg.roles"
              :key="r.uuid"
              class="role-column"
              @dragover="onRoleDragOver"
              @drop="e => onRoleDrop(e, selectedOrg, r)"
            >
              <div class="role-header">
                <strong class="role-name" :title="r.uuid">
                  <span>{{ r.display_name }}</span>
                  <button @click="updateRole(r)" class="icon-btn" aria-label="Rename role" title="Rename role">✏️</button>
                </strong>
                <div class="role-actions">
                  <button @click="createUserInRole(selectedOrg, r)" class="plus-btn" aria-label="Add user" title="Add user">➕</button>
                </div>
              </div>
              <template v-if="r.users.length > 0">
        <ul class="user-list">
                  <li
                    v-for="u in r.users"
                    :key="u.uuid"
                    class="user-chip"
                    draggable="true"
                    @dragstart="e => onUserDragStart(e, u, selectedOrg.uuid)"
          @click="openUser(u)"
                    :title="u.uuid"
                  >
                    <span class="name">{{ u.display_name }}</span>
                    <span class="meta">{{ u.last_seen ? new Date(u.last_seen).toLocaleDateString() : '—' }}</span>
                  </li>
                </ul>
              </template>
              <div v-else class="empty-role">
                <p class="empty-text muted">No members</p>
                <button @click="deleteRole(r)" class="icon-btn delete-icon" aria-label="Delete empty role" title="Delete role">❌</button>
              </div>
            </div>
          </div>
        </div>

  <div v-if="!selectedUser && !selectedOrg && (info.is_global_admin || info.is_org_admin)" class="card">
          <h2>All Permissions</h2>
          <div class="actions">
            <button @click="createPermission">+ Create Permission</button>
          </div>
          <div v-for="p in permissions" :key="p.id" class="perm" :title="p.id">
            <div class="perm-name-line">
              <span>{{ p.display_name }}</span>
              <button @click="updatePermission(p)" class="icon-btn" aria-label="Rename permission" title="Rename permission">✏️</button>
            </div>
            <div class="perm-actions">
              <button @click="deletePermission(p)" class="icon-btn delete-icon" aria-label="Delete permission" title="Delete permission">❌</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <StatusMessage />
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
.roles-grid { display: flex; gap: 1rem; align-items: stretch; overflow-x: auto; padding: .5rem 0 }
.role-column { background: #fafafa; border: 1px solid #eee; border-radius: 8px; padding: .5rem; min-width: 200px; flex: 0 0 240px; display: flex; flex-direction: column; }
.role-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: .25rem }
.user-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: .25rem; flex: 1 1 auto; }
.user-chip { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: .25rem .4rem; display: flex; justify-content: space-between; gap: .5rem; cursor: grab; }
.user-chip:active { cursor: grabbing }
.user-chip .name { font-weight: 500 }
.user-chip .meta { font-size: .65rem; color: #666 }
.role-column.drag-over { outline: 2px dashed #66a; }
.org-table { width: 100%; border-collapse: collapse; }
.org-table th, .org-table td { padding: .4rem .5rem; border-bottom: 1px solid #eee; text-align: left; }
.org-table th { font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; color: #555; }
.org-table a { text-decoration: none; color: #0366d6; }
.org-table a:hover { text-decoration: underline; }
.nav-link { font-size: .6em; margin-left: .5rem; background: #eee; padding: .25em .6em; border-radius: 999px; border: 1px solid #ccc; text-decoration: none; }
.nav-link:hover { background: #ddd; }
.back-link { font-size: .5em; margin-left: .75rem; text-decoration: none; background: #eee; padding: .25em .6em; border-radius: 999px; border: 1px solid #ccc; vertical-align: middle; line-height: 1.2; }
.back-link:hover { background: #ddd; }
.matrix-wrapper { margin: 1rem 0; text-align: left; }
.matrix-scroll { overflow-x: auto; text-align: left; }
.perm-matrix-grid { display: inline-grid; gap: 0; align-items: stretch; margin-right: 4rem; }
.perm-matrix-grid > * { background: #fff; border: none; padding: .35rem .4rem; font-size: .75rem; }
.perm-matrix-grid .grid-head { background: transparent; border: none; font-size: .65rem; letter-spacing: .05em; font-weight: 600; text-transform: uppercase; display: flex; justify-content: center; align-items: flex-end; padding-bottom: .25rem; }
.perm-matrix-grid .perm-head { justify-content: flex-start; align-items: flex-end; }
.perm-matrix-grid .role-head span { writing-mode: vertical-rl; transform: rotate(180deg); font-size: .6rem; line-height: 1; }
.perm-matrix-grid .perm-name { font-weight: 500; white-space: nowrap; text-align: left; }
.perm-matrix-grid .matrix-cell { display: flex; justify-content: center; align-items: center; }
.perm-matrix-grid .matrix-cell input { cursor: pointer; }
.matrix-hint { font-size: .7rem; margin-top: .25rem; }
/* Inline organization title with icon */
.org-title { display: flex; align-items: center; gap: .4rem; }
.org-title .org-name { flex: 0 1 auto; }
/* Plus button for adding users */
.plus-btn { background: none; border: none; font-size: 1.15rem; line-height: 1; padding: 0 .1rem; cursor: pointer; opacity: .6; }
.plus-btn:hover, .plus-btn:focus { opacity: 1; outline: none; }
.plus-btn:focus-visible { outline: 2px solid #555; outline-offset: 2px; }
.empty-role { display: flex; flex-direction: column; gap: .4rem; align-items: flex-start; padding: .35rem .25rem; flex: 1 1 auto; width: 100%; }
.empty-role .empty-text { font-size: .7rem; margin: 0; }
.delete-icon { color: #c00; }
.delete-icon:hover, .delete-icon:focus { color: #ff0000; }
.user-detail .user-link-box { margin-top: .75rem; font-size: .7rem; background: #fff; border: 1px dashed #ccc; padding: .5rem; border-radius: 6px; cursor: pointer; word-break: break-all; }
.user-detail .user-link-box:hover { background: #f9f9f9; }
.user-detail .user-link-box .expires { font-size: .6rem; margin-top: .25rem; color: #555; }
/* Minimal icon button for rename/edit actions */
.icon-btn { background: none; border: none; padding: 0 .15rem; margin-left: .15rem; cursor: pointer; font-size: .8rem; line-height: 1; opacity: .55; vertical-align: middle; }
.icon-btn:hover, .icon-btn:focus { opacity: .95; outline: none; }
.icon-btn:focus-visible { outline: 2px solid #555; outline-offset: 2px; }
.icon-btn:active { transform: translateY(1px); }
.org-title { display: flex; align-items: baseline; gap: .25rem; }
.role-name { display: inline-flex; align-items: center; gap: .15rem; font-weight: 600; }
.perm-name-line { display: flex; align-items: center; gap: .15rem; }
.user-meta { margin-top: .25rem; }
.cred-title { margin-top: .75rem; font-size: .85rem; }
.cred-list { list-style: none; padding: 0; margin: .25rem 0 .5rem; display: flex; flex-direction: column; gap: .35rem; }
.cred-item { background: #fff; border: 1px solid #eee; border-radius: 6px; padding: .35rem .5rem; font-size: .65rem; }
.cred-line { display: flex; flex-direction: column; gap: .15rem; }
.cred-line .dates { color: #555; font-size: .6rem; }
</style>
