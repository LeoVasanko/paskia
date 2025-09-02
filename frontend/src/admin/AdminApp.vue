<script setup>
import { ref, onMounted, onBeforeUnmount, computed, watch } from 'vue'
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
const addingOrgForPermission = ref(null)
const PERMISSION_ID_PATTERN = '^[A-Za-z0-9:._~-]+$'
const showCreatePermission = ref(false)
const newPermId = ref('')
const newPermName = ref('')
const editingPermId = ref(null)
const renameIdValue = ref('')
const dialog = ref({ type: null, data: null, busy: false, error: '' })
const safeIdRegex = /[^A-Za-z0-9:._~-]/g

function sanitizeNewId() { if (newPermId.value) newPermId.value = newPermId.value.replace(safeIdRegex, '') }
function sanitizeRenameId() { if (renameIdValue.value) renameIdValue.value = renameIdValue.value.replace(safeIdRegex, '') }

function handleGlobalClick(e) {
  if (!addingOrgForPermission.value) return
  const menu = e.target.closest('.org-add-menu')
  const trigger = e.target.closest('.add-org-btn')
  if (!menu && !trigger) {
    addingOrgForPermission.value = null
  }
}

onMounted(() => {
  document.addEventListener('click', handleGlobalClick)
})
onBeforeUnmount(() => {
  document.removeEventListener('click', handleGlobalClick)
})

// Build a summary: for each permission id -> { orgs: Set(org_display_name), userCount }
const permissionSummary = computed(() => {
  const summary = {}
  for (const o of orgs.value) {
    const orgBase = { uuid: o.uuid, display_name: o.display_name }
    // Org-level permissions (direct)
    for (const pid of o.permissions || []) {
      if (!summary[pid]) summary[pid] = { orgs: [], orgSet: new Set(), userCount: 0 }
      if (!summary[pid].orgSet.has(o.uuid)) {
        summary[pid].orgs.push(orgBase)
        summary[pid].orgSet.add(o.uuid)
      }
    }
    // Role-based permissions (inheritance)
    for (const r of o.roles) {
      for (const pid of r.permissions) {
        if (!summary[pid]) summary[pid] = { orgs: [], orgSet: new Set(), userCount: 0 }
        if (!summary[pid].orgSet.has(o.uuid)) {
          summary[pid].orgs.push(orgBase)
          summary[pid].orgSet.add(o.uuid)
        }
        summary[pid].userCount += r.users.length
      }
    }
  }
  const display = {}
  for (const [pid, v] of Object.entries(summary)) {
    display[pid] = { orgs: v.orgs.sort((a,b)=>a.display_name.localeCompare(b.display_name)), userCount: v.userCount }
  }
  return display
})

function availableOrgsForPermission(pid) {
  return orgs.value.filter(o => !o.permissions.includes(pid))
}

function renamePermissionDisplay(p) { openDialog('perm-display', { permission: p }) }

function startRenamePermissionId(p) { editingPermId.value = p.id; renameIdValue.value = p.id }
function cancelRenameId() { editingPermId.value = null; renameIdValue.value = '' }
async function submitRenamePermissionId(p) {
  const newId = renameIdValue.value.trim()
  if (!newId || newId === p.id) { cancelRenameId(); return }
  try {
    const body = { old_id: p.id, new_id: newId, display_name: p.display_name }
    const res = await fetch('/auth/admin/permission/rename', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    let data; try { data = await res.json() } catch(_) { data = {} }
    if (!res.ok || data.detail) throw new Error(data.detail || data.error || `Failed (${res.status})`)
    await refreshPermissionsContext(); cancelRenameId()
  } catch (e) { authStore.showMessage(e?.message || 'Rename failed') }
}

async function refreshPermissionsContext() {
  // Reload both lists so All Permissions table shows new associations promptly.
  await Promise.all([loadPermissions(), loadOrgs()])
}

async function attachPermissionToOrg(pid, orgUuid) {
  if (!orgUuid) return
  try {
    const params = new URLSearchParams({ permission_id: pid })
    const res = await fetch(`/auth/admin/orgs/${orgUuid}/permission?${params.toString()}`, { method: 'POST' })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } catch (e) {
  authStore.showMessage(e.message || 'Failed to add permission to org')
  }
}

async function detachPermissionFromOrg(pid, orgUuid) {
  openDialog('confirm', { message: 'Remove permission from this org?', action: async () => {
    try {
      const params = new URLSearchParams({ permission_id: pid })
      const res = await fetch(`/auth/admin/orgs/${orgUuid}/permission?${params.toString()}`, { method: 'DELETE' })
      const data = await res.json()
      if (data.detail) throw new Error(data.detail)
      await loadOrgs()
    } catch (e) {
      authStore.showMessage(e.message || 'Failed to remove permission from org')
    }
  } })
}

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
function createOrg() { openDialog('org-create', {}) }

function updateOrg(org) { openDialog('org-update', { org }) }

function deleteOrg(org) {
  if (!info.value?.is_global_admin) { authStore.showMessage('Global admin only'); return }
  openDialog('confirm', { message: `Delete organization ${org.display_name}?`, action: async () => {
    const res = await fetch(`/auth/admin/orgs/${org.uuid}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } })
}

function createUserInRole(org, role) { openDialog('user-create', { org, role }) }

async function moveUserToRole(org, user, targetRoleDisplayName) {
  if (user.role === targetRoleDisplayName) return
  const res = await fetch(`/auth/admin/orgs/${org.uuid}/users/${user.uuid}/role`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ role: targetRoleDisplayName })
  })
  const data = await res.json()
  if (data.detail) { authStore.showMessage(data.detail); return }
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

// (legacy function retained but unused in UI)
async function addOrgPermission() { /* obsolete */ }

async function removeOrgPermission() { /* obsolete */ }

// Role actions
function createRole(org) { openDialog('role-create', { org }) }

function updateRole(role) { openDialog('role-update', { role }) }

function deleteRole(role) {
  openDialog('confirm', { message: `Delete role ${role.display_name}?`, action: async () => {
    const res = await fetch(`/auth/admin/roles/${role.uuid}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } })
}

// Permission actions
async function submitCreatePermission() {
  const id = newPermId.value.trim()
  const name = newPermName.value.trim()
  if (!id || !name) return
  const res = await fetch('/auth/admin/permissions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id, display_name: name }) })
  const data = await res.json(); if (data.detail) { authStore.showMessage(data.detail); return }
  await loadPermissions(); newPermId.value=''; newPermName.value=''; showCreatePermission.value=false
}
function cancelCreatePermission() { newPermId.value=''; newPermName.value=''; showCreatePermission.value=false }

function updatePermission(p) { openDialog('perm-display', { permission: p }) }

function deletePermission(p) {
  openDialog('confirm', { message: `Delete permission ${p.id}?`, action: async () => {
    const params = new URLSearchParams({ permission_id: p.id })
    const res = await fetch(`/auth/admin/permission?${params.toString()}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await loadPermissions()
  } })
}

onMounted(async () => {
  window.addEventListener('hashchange', parseHash)
  await authStore.loadSettings()
  if (authStore.settings?.rp_name) {
    document.title = authStore.settings.rp_name + ' Admin'
  }
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
    authStore.showMessage(e.message || 'Failed to update role permission')
    role.permissions = prev // revert
  }
}

function openDialog(type, data) { dialog.value = { type, data, busy: false, error: '' } }
function closeDialog() { dialog.value = { type: null, data: null, busy: false, error: '' } }

// Admin user rename
const editingUserName = ref(false)
const editUserNameValue = ref('')
const editUserNameValid = computed(()=> true) // backend validates
function beginEditUserName() {
  if (!selectedUser.value) return
  editingUserName.value = true
  editUserNameValue.value = ''
}
function cancelEditUserName() { editingUserName.value = false }
async function submitEditUserName() {
  if (!editingUserName.value) return
  try {
    const res = await fetch(`/auth/admin/users/${selectedUser.value.uuid}/display-name`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: editUserNameValue.value }) })
    const data = await res.json(); if (!res.ok || data.detail) throw new Error(data.detail || 'Rename failed')
    editingUserName.value = false
    await loadOrgs()
    const r = await fetch(`/auth/admin/users/${selectedUser.value.uuid}`)
    const jd = await r.json(); if (!r.ok || jd.detail) throw new Error(jd.detail || 'Reload failed')
    userDetail.value = jd
    authStore.showMessage('User renamed', 'success', 1500)
  } catch (e) {
    authStore.showMessage(e.message || 'Rename failed')
  }
}

async function submitDialog() {
  if (!dialog.value.type || dialog.value.busy) return
  dialog.value.busy = true; dialog.value.error = ''
  try {
    const t = dialog.value.type
    if (t === 'org-create') {
      const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch('/auth/admin/orgs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: [] }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await Promise.all([loadOrgs(), loadPermissions()])
    } else if (t === 'org-update') {
      const { org } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/admin/orgs/${org.uuid}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: org.permissions }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'role-create') {
      const { org } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/admin/orgs/${org.uuid}/roles`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: [] }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'role-update') {
      const { role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const permsCsv = dialog.value.data.perms || ''
      const perms = permsCsv.split(',').map(s=>s.trim()).filter(Boolean)
      const res = await fetch(`/auth/admin/roles/${role.uuid}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: perms }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'user-create') {
      const { org, role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/admin/orgs/${org.uuid}/users`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, role: role.display_name }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'perm-display') {
      const { permission } = dialog.value.data; const display = dialog.value.data.display_name?.trim(); if (!display) throw new Error('Display name required')
      const params = new URLSearchParams({ permission_id: permission.id, display_name: display })
      const res = await fetch(`/auth/admin/permission?${params.toString()}`, { method: 'PUT' })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadPermissions()
    } else if (t === 'confirm') {
      const action = dialog.value.data.action; if (action) await action()
    }
    closeDialog()
  } catch (e) {
    dialog.value.error = e.message || 'Error'
  } finally { dialog.value.busy = false }
}
</script>

<template>
  <div class="container">
    <h1 v-if="!selectedUser">
      <template v-if="!selectedOrg">{{ (authStore.settings?.rp_name || 'Passkey') + ' Admin' }}</template>
      <template v-else>Organization Admin</template>
      <a href="/auth/" class="back-link" title="Back to User App">User</a>
      <a v-if="selectedOrg && info?.is_global_admin" @click.prevent="goOverview" href="#overview" class="nav-link" title="Back to overview">Overview</a>
    </h1>
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
          <h2 class="user-title">
            <span v-if="!editingUserName">{{ userDetail?.display_name || selectedUser.display_name }} <button class="icon-btn" @click="beginEditUserName" title="Rename user">✏️</button></span>
            <span v-else>
              <input v-model="editUserNameValue" :placeholder="userDetail?.display_name || selectedUser.display_name" maxlength="64" @keyup.enter="submitEditUserName" />
              <button class="icon-btn" @click="submitEditUserName">💾</button>
              <button class="icon-btn" @click="cancelEditUserName">✖</button>
            </span>
          </h2>
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
          <div class="org-actions"></div>

          <div class="matrix-wrapper">
            <div class="matrix-scroll">
              <div
                class="perm-matrix-grid"
                :style="{ gridTemplateColumns: 'minmax(180px, 1fr) ' + selectedOrg.roles.map(()=> '2.2rem').join(' ') + ' 2.2rem' }"
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
                <div class="grid-head role-head add-role-head" title="Add role" @click="createRole(selectedOrg)" role="button">➕</div>

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
                  <div class="matrix-cell add-role-cell" />
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
                  <button @click="updateRole(r)" class="icon-btn" aria-label="Edit role" title="Edit role">✏️</button>
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
            <button v-if="!showCreatePermission" @click="showCreatePermission = true">+ Create Permission</button>
            <form v-else class="inline-form" @submit.prevent="submitCreatePermission">
              <input v-model="newPermId" @input="sanitizeNewId" required :pattern="PERMISSION_ID_PATTERN" placeholder="permission id" title="Allowed: A-Za-z0-9:._~-" />
              <input v-model="newPermName" required placeholder="display name" />
              <button type="submit">Save</button>
              <button type="button" @click="cancelCreatePermission">Cancel</button>
            </form>
          </div>
          <div class="permission-grid">
            <div class="perm-grid-head">Permission</div>
            <div class="perm-grid-head">Orgs</div>
            <div class="perm-grid-head center">Members</div>
            <div class="perm-grid-head center">Actions</div>
            <template v-for="p in [...permissions].sort((a,b)=> a.id.localeCompare(b.id))" :key="p.id">
              <div class="perm-cell perm-name" :title="p.id">
                <div class="perm-title-line">{{ p.display_name }}</div>
                <div class="perm-id-line muted">{{ p.id }}</div>
              </div>
              <div class="perm-cell perm-orgs" :title="permissionSummary[p.id]?.orgs?.map(o=>o.display_name).join(', ') || ''">
                <template v-if="permissionSummary[p.id]">
                  <span class="org-pill" v-for="o in permissionSummary[p.id].orgs" :key="o.uuid">
                    {{ o.display_name }}
                    <button class="pill-x" @click.stop="detachPermissionFromOrg(p.id, o.uuid)" aria-label="Remove">×</button>
                  </span>
                </template>
                <span class="org-add-wrapper">
                  <button
                    v-if="availableOrgsForPermission(p.id).length && addingOrgForPermission !== p.id"
                    class="add-org-btn"
                    @click.stop="addingOrgForPermission = p.id"
                    aria-label="Add organization"
                    title="Add organization"
                  >➕</button>
                  <div
                    v-if="addingOrgForPermission === p.id"
                    class="org-add-menu"
                    tabindex="0"
                    @keydown.escape.stop.prevent="addingOrgForPermission = null"
                  >
                    <div class="org-add-list">
                      <button
                        v-for="o in availableOrgsForPermission(p.id)"
                        :key="o.uuid"
                        class="org-add-item"
                        @click.stop="attachPermissionToOrg(p.id, o.uuid); addingOrgForPermission = null"
                      >{{ o.display_name }}</button>
                    </div>
                    <div class="org-add-footer">
                      <button class="org-add-cancel" @click.stop="addingOrgForPermission = null" aria-label="Cancel">Cancel</button>
                    </div>
                  </div>
                </span>
              </div>
              <div class="perm-cell perm-users center">{{ permissionSummary[p.id]?.userCount || 0 }}</div>
              <div class="perm-cell perm-actions center">
                <div class="perm-actions-inner" :class="{ editing: editingPermId === p.id }">
                  <div class="actions-view">
                    <button @click="renamePermissionDisplay(p)" class="icon-btn" aria-label="Change display name" title="Change display name">✏️</button>
                    <button @click="startRenamePermissionId(p)" class="icon-btn" aria-label="Change id" title="Change id">🆔</button>
                    <button @click="deletePermission(p)" class="icon-btn delete-icon" aria-label="Delete permission" title="Delete permission">❌</button>
                  </div>
                  <form class="inline-id-form overlay" @submit.prevent="submitRenamePermissionId(p)">
                    <input v-model="renameIdValue" @input="sanitizeRenameId" required :pattern="PERMISSION_ID_PATTERN" class="id-input" title="Allowed: A-Za-z0-9:._~-" />
                    <button type="submit" class="icon-btn" aria-label="Save">✔</button>
                    <button type="button" class="icon-btn" @click="cancelRenameId" aria-label="Cancel">✖</button>
                  </form>
                </div>
              </div>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
  <StatusMessage />
  <div v-if="dialog.type" class="modal-overlay" @keydown.esc.prevent.stop="closeDialog" tabindex="-1">
    <div class="modal" role="dialog" aria-modal="true">
      <h3 class="modal-title">
        <template v-if="dialog.type==='org-create'">Create Organization</template>
        <template v-else-if="dialog.type==='org-update'">Rename Organization</template>
        <template v-else-if="dialog.type==='role-create'">Create Role</template>
        <template v-else-if="dialog.type==='role-update'">Edit Role</template>
        <template v-else-if="dialog.type==='user-create'">Add User To Role</template>
        <template v-else-if="dialog.type==='perm-display'">Edit Permission Display</template>
        <template v-else-if="dialog.type==='confirm'">Confirm</template>
      </h3>
      <form @submit.prevent="submitDialog" class="modal-form">
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
        <template v-else-if="dialog.type==='perm-display'">
          <p class="small muted">ID: {{ dialog.data.permission.id }}</p>
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
          <button type="button" @click="closeDialog" :disabled="dialog.busy">Cancel</button>
        </div>
      </form>
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
/* Avoid global button 100% width from frontend main styles */
button, .perm-actions button, .org-actions button, .role-actions button { width: auto; }
.roles-grid { display: flex; flex-wrap: wrap; gap: 1rem; align-items: stretch; padding: .5rem 0; }
.role-column { background: #fafafa; border: 1px solid #eee; border-radius: 8px; padding: .5rem; min-width: 200px; flex: 1 1 240px; display: flex; flex-direction: column; max-width: 300px; }
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
/* Add role column styles */
.add-role-head { cursor: pointer; color: #2a6; font-size: 1rem; display:flex; justify-content:center; align-items:flex-end; }
.add-role-head:hover { color:#1c4; }
/* Removed add-role placeholder styles */
/* Inline organization title with icon */
.org-title { display: flex; align-items: center; gap: .4rem; }
.org-title .org-name { flex: 0 1 auto; }
/* Plus button for adding users */
.plus-btn { background: none; border: none; font-size: 1.15rem; line-height: 1; padding: 0 .1rem; cursor: pointer; opacity: .6; }
.plus-btn:hover, .plus-btn:focus { opacity: 1; outline: none; }
.plus-btn:focus-visible { outline: 2px solid #555; outline-offset: 2px; }
.empty-role { display: flex; flex-direction: column; gap: .4rem; align-items: flex-start; padding: .35rem .25rem; /* removed flex grow & width for natural size */ }
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
/* Permission grid */
.permission-grid { display: grid; grid-template-columns: minmax(220px,2fr) minmax(160px,3fr) 70px 90px; gap: 2px; margin-top: .5rem; }
.permission-grid .perm-grid-head { font-size: .6rem; text-transform: uppercase; letter-spacing: .05em; font-weight: 600; padding: .35rem .4rem; background: #f3f3f3; border: 1px solid #e1e1e1; }
.permission-grid .perm-cell { background: #fff; border: 1px solid #eee; padding: .35rem .4rem; font-size: .7rem; display: flex; align-items: center; gap: .4rem; }
.permission-grid .perm-name { flex-direction: row; flex-wrap: wrap; }
.permission-grid .perm-name { flex-direction: column; align-items: flex-start; gap:2px; }
.permission-grid .perm-title-line { font-weight:600; line-height:1.1; }
.permission-grid .perm-id-line { font-size:.55rem; line-height:1.1; word-break:break-all; }
.permission-grid .center { justify-content: center; }
.permission-grid .perm-actions { gap: .25rem; }
.permission-grid .perm-actions .icon-btn { font-size: .9rem; }
/* Inline edit overlay to avoid layout shift */
.perm-actions-inner { position: relative; display:flex; width:100%; justify-content:center; }
.perm-actions-inner .inline-id-form.overlay { position:absolute; inset:0; display:none; align-items:center; justify-content:center; gap:.25rem; background:rgba(255,255,255,.9); backdrop-filter:blur(2px); padding:0 .15rem; }
.perm-actions-inner.editing .inline-id-form.overlay { display:inline-flex; }
.perm-actions-inner.editing .actions-view { visibility:hidden; }
/* Inline forms */
.inline-form, .inline-id-form { display:inline-flex; gap:.25rem; align-items:center; }
.inline-form input, .inline-id-form input { padding:.25rem .4rem; font-size:.6rem; border:1px solid #ccc; border-radius:4px; }
.inline-form button, .inline-id-form button { font-size:.6rem; padding:.3rem .5rem; }
.inline-id-form .id-input { width:120px; }
/* Modal */
.modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,.4); display:flex; justify-content:center; align-items:flex-start; padding-top:8vh; z-index:200; }
.modal { background:#fff; border-radius:10px; padding:1rem 1.1rem; width: min(420px, 90%); box-shadow:0 10px 30px rgba(0,0,0,.25); animation:pop .18s ease; }
@keyframes pop { from { transform:translateY(10px); opacity:0 } to { transform:translateY(0); opacity:1 } }
.modal-title { margin:0 0 .65rem; font-size:1rem; }
.modal-form { display:flex; flex-direction:column; gap:.65rem; }
.modal-form label { display:flex; flex-direction:column; font-size:.65rem; gap:.25rem; font-weight:600; }
.modal-form input, .modal-form textarea { border:1px solid #ccc; border-radius:6px; padding:.45rem .55rem; font-size:.7rem; font-weight:400; font-family:inherit; }
.modal-form textarea { resize:vertical; }
.modal-actions { display:flex; gap:.5rem; justify-content:flex-end; margin-top:.25rem; }
.modal-actions button { font-size:.65rem; }
/* Org pill editing */
.perm-orgs { flex-wrap: wrap; gap: .25rem; }
.perm-orgs .org-pill { background:#eef4ff; border:1px solid #d0dcf0; padding:2px 6px; border-radius:999px; font-size:.55rem; display:inline-flex; align-items:center; gap:4px; }
.perm-orgs .org-pill .pill-x { background:none; border:none; cursor:pointer; font-size:.7rem; line-height:1; padding:0; margin:0; color:#555; }
.perm-orgs .org-pill .pill-x:hover { color:#c00; }
.add-org-btn { background:none; border:none; cursor:pointer; font-size:.7rem; padding:0 2px; line-height:1; opacity:.55; display:inline; }
.add-org-btn:hover, .add-org-btn:focus { opacity:1; }
.add-org-btn:focus-visible { outline:2px solid #555; outline-offset:2px; }
.org-add-wrapper { position:relative; display:inline-block; }
.org-add-menu { position:absolute; top:100%; left:0; z-index:20; margin-top:4px; min-width:160px; background:#fff; border:1px solid #e2e6ea; border-radius:6px; padding:.3rem .35rem; box-shadow:0 4px 10px rgba(0,0,0,.08); display:flex; flex-direction:column; gap:.25rem; font-size:.6rem; }
.org-add-menu:before { content:""; position:absolute; top:-5px; left:10px; width:8px; height:8px; background:#fff; border-left:1px solid #e2e6ea; border-top:1px solid #e2e6ea; transform:rotate(45deg); }
.org-add-list { display:flex; flex-direction:column; gap:0; max-height:180px; overflow-y:auto; scrollbar-width:thin; }
.org-add-item { background:transparent; border:none; padding:.25rem .4rem; font-size:.6rem; border-radius:4px; cursor:pointer; line-height:1.1; text-align:left; width:100%; color:#222; }
.org-add-item:hover, .org-add-item:focus { background:#f2f5f9; }
.org-add-item:active { background:#e6ebf0; }
.org-add-footer { margin-top:.25rem; display:flex; justify-content:flex-end; }
.org-add-cancel { background:transparent; border:none; font-size:.55rem; padding:.15rem .35rem; cursor:pointer; color:#666; border-radius:4px; }
.org-add-cancel:hover, .org-add-cancel:focus { background:#f2f5f9; color:#222; }
.org-add-cancel:active { background:#e6ebf0; }
</style>
